from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin

SWAGGER_URL = '/auth/docs/v1'
API_URL = '/auth/swagger/v1'
VERSION = '1.0.0'
CONFIG = {
    'layout': 'BaseLayout'
}


class APISpecSwagger(APISpec):
    def create_tags(self, tags: list[dict]):
        """Creating tags."""
        self.tag(*tags)

    def load_docstrings(self, app):
        """ Download the API description.

        :param app: an instance of the Flask application, from where we take the description of the functions
        """
        for fn_name in app.view_functions:
            if fn_name != 'static':
                self.path(view=app.view_functions[fn_name])


apispec = APISpecSwagger(
    title='Flask Auth documentation',
    version=VERSION,
    openapi_version='3.0.3',
    plugins=[FlaskPlugin(), MarshmallowPlugin()],
)

# security
jwt_scheme = {
    'type': 'http', "scheme": 'bearer', 'bearerFormat': 'JWT',
    'description': 'Enter the token "abcde12345".',
}
apispec.components.security_scheme("jwt_key", jwt_scheme)

# parameter
user_agent_parameter = {'name': 'User-Agent', 'schema': {'type': 'string'}}
apispec.components.parameter('user_agent', 'header', user_agent_parameter)
