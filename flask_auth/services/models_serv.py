from datetime import datetime
from http import HTTPStatus as HTTP
from typing import Any

from flask import Response, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    verify_jwt_in_request
)
from sqlalchemy import and_

from db.db import db_session
from db.redis import jwt_redis_blocklist
from models.db_models import Auth, Role, User
from services.utils import token_expire_time, user_agent_hash


class UserServ(User):

    @classmethod
    def get_obj_by_name(cls, name: str, email: bool = False) -> 'User':
        '''Gives the object by name. Optionally by email.'''
        if email:
            return db_session.query(User).filter(User.email == name).one_or_none()
        return db_session.query(User).filter(User.name == name).one_or_none()

    @classmethod
    def create_user(cls, name: str, email: str, password: str, password2: str) -> tuple[Response, HTTP]:
        '''Create User.'''
        if password == password2 and len(password) >= 8:
            try:
                user = User(name=name,
                            email=email,
                            password=password)
                db_session.add(user)
                db_session.commit()
                return jsonify('User created. Login is email.'), HTTP.CREATED
            except Exception as e:
                db_session.rollback()
                return jsonify(msg="Wrong email or password or name",
                               err=e.args), HTTP.BAD_REQUEST
        else:
            return jsonify('password != password2 or length < 8'), HTTP.BAD_REQUEST

    @classmethod
    def update_user(cls, name: str, email: str, pass_old: str, password: str, password2: str) -> tuple[Response, HTTP]:
        '''Change User'''
        try:
            user = cls.get_obj_by_name(name)
            user.email = email if email else user.email
            pass_old_hash = user.password_hash(pass_old, user.email)
            if user.password == pass_old_hash and password and password2:
                if password == password2 and len(password) >= 8:
                    user.password = user.password_hash(password, user.email)
                    db_session.add(user)
                    db_session.commit()
                    return jsonify('User update.'), HTTP.ACCEPTED
                else:
                    return jsonify('password != password2 or length < 8'), HTTP.BAD_REQUEST
            raise Exception
        except Exception as e:
            db_session.rollback()
            return jsonify(msg="Wrong email or password or name",
                           err=e.args), HTTP.BAD_REQUEST

    @classmethod
    def user_crud(cls) -> tuple[Response, HTTP]:
        name = request.json.get('name', None)
        email = request.json.get('email', None)
        pass_old = request.json.get('pass_old', None)
        password = request.json.get('password', None)
        password2 = request.json.get('password2', None)
        if request.method == 'POST':
            response = cls.create_user(name, email, password, password2)
        elif request.method == 'PUT':
            verify_jwt_in_request()
            user = get_current_user()
            json = request.get_json()
            if user.name != json['name']:
                return jsonify('Token not for this user.'), HTTP.UNAUTHORIZED
            response = cls.update_user(name, email, pass_old, password, password2)
        else:
            response = jsonify(), HTTP.METHOD_NOT_ALLOWED
        return response

    @classmethod
    def get_user_roles(cls, username: str) -> tuple[Response, HTTP]:
        '''Gives the user role sheet.'''
        user = cls.get_obj_by_name(username)
        if user is None:
            return jsonify('No user'), HTTP.NOT_FOUND
        list_roles = [item.role for item in user.role]
        if not list_roles:
            return jsonify('No roles'), HTTP.NOT_FOUND
        return jsonify({'roles': list_roles}), HTTP.OK

    @classmethod
    def add_or_del_role_user(cls, json: dict, add: bool = False) -> tuple[Response, HTTP]:
        '''The method adds or removes the user's role.
        Adds all keys to the blocklist, if deleted. The output is a ready Response.'''
        try:
            role = RoleServ.get_obj_by_role(json['role'])
            user = cls.get_obj_by_name(json['user'])
            if add:
                user.role.append(role)
                db_session.commit()
                return jsonify('Role added for user. Refresh user access token.'), HTTP.CREATED
            else:
                user.role.remove(role)
                user_agents = db_session.query(Auth.user_agent).filter(Auth.user_id == str(user.id)).distinct().all()
                for user_agent in user_agents:
                    AuthServ.add_old_tokens_in_block(user, user_agent_hash(user_agent[0]))
                    last_auth = AuthServ.last_auth(user.id, user_agent_hash(user_agent[0]))
                    last_auth.access_token = None
                    last_auth.refresh_token = None
                db_session.commit()
                return jsonify('Remove a role from a user. All keys have been revoked'), HTTP.NO_CONTENT
        except Exception as e:
            db_session.rollback()
            return jsonify(msg="Wrong role.id and user.id or see in err",
                           err=e.args), HTTP.BAD_REQUEST


class AuthServ(Auth):

    @classmethod
    def registry_auth(cls, user: User,
                      user_agent: str | None = None,
                      u_a_hash: int | None = None,
                      access_token: str | None = None,
                      refresh_token: str | None = None):
        '''The method creates a new entry in Auth.'''
        auth = cls(user_id=str(user.id),
                   user_agent=user_agent,
                   u_a_hash=u_a_hash,
                   access_token=access_token,
                   refresh_token=refresh_token)
        db_session.add(auth)
        db_session.commit()

    @classmethod
    def history_auth(cls, user_id: str, page: int, size: int) -> list[list[str]]:
        ''' The method generates a list of authorizations
        of the current user via /login.
        You could have formed it via repr, but this way:)'''
        user_list = [[datetime.isoformat(item.data_time), item.user_agent] for item in db_session.query(cls).filter(cls.user_id == user_id).order_by(cls.data_time.desc())[page * size:page * size + size]]
        return user_list

    @classmethod
    def last_auth(cls, user_id: str, u_a_hash: int) -> 'Auth':
        '''The method returns the last authorization by user id and user_agent.'''
        if last_auth := db_session.query(cls).filter(and_(cls.user_id == str(user_id), cls.u_a_hash == u_a_hash)).order_by(cls.data_time.desc()).first():
            return last_auth
        return None

    @classmethod
    def tokens_from_db(cls, user_id: str, u_a_hash: int) -> tuple[Any, Any, Any]:
        '''The method returns the ACCESS/REFRESH token pair
        and the time of their last update, from the last Auth.'''
        if token := db_session.query(cls.access_token, cls.refresh_token, cls.tokens_time).filter(and_(cls.user_id == str(user_id), cls.u_a_hash == u_a_hash)).order_by(cls.data_time.desc()).first():
            return token[0], token[1], token[2]
        return None, None, None

    @classmethod
    def add_old_tokens_in_block(cls, user: User, u_a_hash: int) -> None:
        '''The method adds a pair of tokens to the Redis blocklist.'''
        access_token, refresh_token, tokens_time = cls.tokens_from_db(user.id, u_a_hash)
        if access_token:
            expire_time = token_expire_time(True, tokens_time)
            if expire_time:
                jwt_redis_blocklist.set(access_token, "", ex=expire_time)
        if refresh_token:
            expire_time = token_expire_time(False, tokens_time)
            if expire_time:
                jwt_redis_blocklist.set(refresh_token, "", ex=expire_time)

    @classmethod
    def login_refresh_service(cls, user: User, login: bool = False) -> tuple[str, str]:
        '''Method for login/refresh endpoints.
        During login: creates a new token pair, adds an entry to Auth,
        adds old keys (for user_agent) to the blocklist.
        On refresh: the same, but changes the last entry in the Auth,
        to the new keys.
        The whole movement takes into account the user_agent from whom the request is made.'''
        user_agent = request.headers.get('User-Agent', 'empty')
        u_a_hash = user_agent_hash(user_agent)
        access_token = create_access_token(identity=user)
        refresh_token = create_refresh_token(identity=user)
        decode_access_token = decode_token(access_token)
        decode_refresh_token = decode_token(refresh_token)
        cls.add_old_tokens_in_block(user, u_a_hash)
        if login:
            cls.registry_auth(user=user, user_agent=user_agent,
                              u_a_hash=u_a_hash,
                              access_token=decode_access_token['jti'],
                              refresh_token=decode_refresh_token['jti'])
        else:
            last_auth = cls.last_auth(user.id, u_a_hash)
            last_auth.access_token = decode_access_token['jti']
            last_auth.refresh_token = decode_refresh_token['jti']
            db_session.commit()
        return access_token, refresh_token

    @classmethod
    def logout_service(cls, user: User) -> None:
        '''Changes the last entry in the Auth log, replacing the keys with None.
        Adds to the blocklist.'''
        user_agent = request.headers.get('User-Agent', 'empty')
        u_a_hash = user_agent_hash(user_agent)
        cls.add_old_tokens_in_block(user, u_a_hash)
        last_auth = cls.last_auth(user.id, u_a_hash)
        last_auth.access_token = None
        last_auth.refresh_token = None
        db_session.commit()

    @classmethod
    def logout_all_service(cls, user: User) -> None:
        '''Recalls all keys, all user_agents, replacing all keys with None.
        Adds keys for all user_agents to the blocklist'''
        u_a_hashes = db_session.query(cls.u_a_hash).filter(cls.user_id == str(user.id)).distinct().all()
        for u_a_hash in u_a_hashes:
            cls.add_old_tokens_in_block(user, u_a_hash[0])
            last_auth = cls.last_auth(user.id, u_a_hash[0])
            last_auth.access_token = None
            last_auth.refresh_token = None
        db_session.commit()


class RoleServ(Role):

    @classmethod
    def get_obj_by_role(cls, role: str) -> 'Role':
        return db_session.query(Role).filter(Role.role == role).one_or_none()

    @classmethod
    def get_list_roles(cls) -> tuple[Response, HTTP]:
        result = [item.role for item in db_session.query(Role).all()]
        if not result:
            return jsonify(msg="Roles are missing"), HTTP.BAD_REQUEST
        return jsonify({'roles': result}), HTTP.OK

    @classmethod
    def create_role(cls) -> tuple[Response, HTTP]:
        json = request.get_json()
        role = Role(role=json['role'])
        try:
            db_session.add(role)
            db_session.commit()
        except Exception as e:
            db_session.rollback()
            return jsonify(msg="Wrong role", err=e.args), HTTP.BAD_REQUEST
        return jsonify('Role created.'), HTTP.CREATED

    @classmethod
    def update_role(cls) -> tuple[Response, HTTP]:
        json = request.get_json()
        try:
            role_obj = cls.get_obj_by_role(json['old_role'])
            role_obj.role = json['new_role']
            db_session.add(role_obj)
            db_session.commit()
            return jsonify('Role update.'), HTTP.CREATED
        except Exception as e:
            db_session.rollback()
            return jsonify(msg="Wrong role", err=e.args), HTTP.BAD_REQUEST

    @classmethod
    def delete_role(cls) -> tuple[Response, HTTP]:
        json = request.get_json()
        try:
            role = cls.get_obj_by_role(json['role'])
            db_session.delete(role)
            db_session.commit()
            return jsonify('Role delete.'), HTTP.NO_CONTENT
        except Exception as e:
            db_session.rollback()
            return jsonify(msg="Wrong role", err=e.args), HTTP.BAD_REQUEST

    @classmethod
    def role_crud(cls) -> tuple[Response, HTTP]:
        if request.method == 'POST':
            response = cls.create_role()
        elif request.method == 'DELETE':
            response = cls.delete_role()
        elif request.method == 'PUT':
            response = cls.update_role()
        elif request.method == 'GET':
            response = cls.get_list_roles()
        return response
