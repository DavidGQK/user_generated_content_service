from flask import Blueprint, request
from flask_jwt_extended import jwt_required

from flask_auth.services.models_serv import RoleServ, UserServ
from flask_auth.services.utils import role_required

role = Blueprint('role', __name__)


@role.route('/role_crud', methods=['GET', 'POST', 'DELETE', 'PUT'])
@jwt_required()
@role_required('admin')
def role_crud():
    """
    ---
    post:
      summary: Create role (need access token)
      description: Creates a role. Authentication is required.
      security:
        - jwt_key: []
      requestBody:
        content:
          application/json:
            schema: RoleSchema
      responses:
        201:
          description: Role created
        403:
          description: FORBIDDEN
        422:
         description: UNPROCESSABLE ENTITY
      tags:
        - Role
    put:
      summary: Change role (need access token)
      description: Update the role. Authentication is required.
      security:
        - jwt_key: []
      requestBody:
        content:
          'application/json':
            schema: PutRoleSchema
      responses:
        202:
          description: Role update
        403:
          description: FORBIDDEN
        422:
         description: UNPROCESSABLE ENTITY
      tags:
        - Role
    delete:
      summary: Delete role (need access token)
      description: Deletes the role. Authentication is required.
      security:
        - jwt_key: []
      requestBody:
        content:
          'application/json':
            schema: RoleSchema
      responses:
        204:
          description: Role delete
        403:
          description: FORBIDDEN
        422:
         description: UNPROCESSABLE ENTITY
      tags:
        - Role
    get:
      summary: List roles (need access token)
      description: Gives the list of all roles. Authentication is required.
      security:
        - jwt_key: []
      responses:
        204:
          description: List roles
          content:
            application/json:
              schema: ListRolesSchema
        403:
          description: FORBIDDEN
        422:
          description: UNPROCESSABLE ENTITY
      tags:
        - Role
    """
    response = RoleServ.role_crud()
    return response


@role.route('/user/roles', methods=['POST'])
@jwt_required()
@role_required('admin')
def add_role_for_user():
    """
    ---
    post:
     summary: Add role for user (need access token)
     description: Adds a role to the user. Authentication is required.
     security:
       - jwt_key: []
     requestBody:
       content:
         application/json:
           schema: UserRoleSchema
     responses:
       201:
         description: Added role for user
       400:
         description: BAD REQUEST.
       422:
         description: UNPROCESSABLE ENTITY
     tags:
       - Role
    """
    json = request.get_json()
    response = UserServ.add_or_del_role_user(json, True)
    return response


@role.route('/user/roles', methods=['DELETE'])
@jwt_required()
@role_required('admin')
def delete_role_from_user():
    """
    ---
    delete:
        summary: Delete role from user (need access token)
        description: Deletes the role (revokes all keys). Authentication is required.
        security:
          - jwt_key: []
        requestBody:
            content:
                application/json:
                  schema: UserRoleSchema
        responses:
          200:
            description: Role delete from user.
          400:
            description: BAD REQUEST.
          422:
            description: UNPROCESSABLE ENTITY
        tags:
          - Role
    """
    json = request.get_json()
    response = UserServ.add_or_del_role_user(json)
    return response


@role.route('/user/roles/<string:user>', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_user_roles(user: str):
    """
    ---
    get:
        summary: Get user roles (need access token)
        description: Deletes the user's role. Authentication is required.
        security:
          - jwt_key: []
        parameters:
        - name: user
          in: path
          description: user
          schema:
            type: string
        responses:
          200:
            description: Role delete.
            content:
                application/json:
                    schema: ListRolesSchema
          404:
            description: No Role // No User
          422:
            description: UNPROCESSABLE ENTITY
        tags:
          - Role
    """
    response = UserServ.get_user_roles(user)
    return response
