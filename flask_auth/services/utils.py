import logging
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps
from http import HTTPStatus as HTTP
from zlib import crc32

from flask import jsonify, request
from flask_jwt_extended import get_jwt

from core.config import ACCESS_EXPIRES, REFRESH_EXPIRES, TESTS, THROTTLING
from db.redis import jwt_redis_blocklist


def role_required(*req_roles: str):
    '''Decorator for JWT requests only. Supplements jwt_required,
    checks availability by role.
    If role is superuser then all handles are available.'''
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            claims = get_jwt()
            for req_role in req_roles:
                if req_role in claims['roles'] or 'superuser' in claims['roles']:
                    return fn(*args, **kwargs)
            else:
                return jsonify(msg='The role does not grant access! Or refresh you access token!'), HTTP.FORBIDDEN
        return decorator
    return wrapper


def token_expire_time(access: bool, token_time: datetime) -> timedelta | None:
    '''Calculates the remaining token time, if minus returns None,
    then there is no need to revoke it, the token is no longer valid.'''
    if access:
        expire = ACCESS_EXPIRES - (datetime.utcnow() - token_time)
    elif not access:
        expire = REFRESH_EXPIRES - (datetime.utcnow() - token_time)
    if expire < timedelta():
        return None
    return expire


def user_agent_hash(user_agent: str) -> int:
    '''The function hashes user_agent to reduce size,
    use crc32 for speed.'''
    return crc32(user_agent.encode('utf-8'))


def check_user_agent():
    '''The decoder checks the current user_agent against the received token.
    If they do not match, then 403.
    You can use everywhere - where the token is, but I put it on both logout's, and refresh.
    If you use everywhere, it is more correct to use this mechanics:
    https://flask-jwt-extended.readthedocs.io/en/stable/api/#module-flask_jwt_extended '''
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            jwt = get_jwt()
            if user_agent_hash(request.headers.get('User-Agent', '')) == jwt['ua']:
                return fn(*args, **kwargs)
            else:
                return jsonify(msg='The keys were received by another user_agent'), HTTP.FORBIDDEN
        return decorator
    return wrapper


def throttling_user_agent(*req_roles: str):
    '''Decorator does not affect admin and superuser and those specified in param.
    It 'suffocates' the rest by putting them into Redis.
    Completes jwt_required where needed, but also lets in without authorization.'''
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            try:
                if TESTS:
                    return fn(*args, **kwargs)
                jwt = get_jwt()
                if 'superuser' in jwt['roles'] or 'admin' in jwt['roles']:
                    return fn(*args, **kwargs)
                elif req_roles:
                    for role in req_roles:
                        if role in jwt['roles']:
                            return fn(*args, **kwargs)
                raise Exception
            except Exception:
                hash_u_a = user_agent_hash(request.headers.get('User-Agent', 'empty'))
                ip = request.remote_addr
                if jwt_redis_blocklist.get(str(hash_u_a) + ip) is None:
                    jwt_redis_blocklist.set(str(hash_u_a) + ip, "", THROTTLING)
                    return fn(*args, **kwargs)
                else:
                    return jsonify(msg='Try again later'), HTTP.FORBIDDEN
        return decorator
    return wrapper


def generate_password(length):
    letters_and_digits = string.ascii_letters + string.digits
    crypt_rand_string = ''.join(secrets.choice(
        letters_and_digits) for i in range(length))
    return crypt_rand_string
