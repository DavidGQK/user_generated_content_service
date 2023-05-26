from flask import Blueprint, json

from core.config import app
from docs.v1.config import API_URL, apispec

swagger = Blueprint("swagger", __name__)


@app.route(API_URL)
def create_swagger_spec():
    apispec.create_tags([{'name': 'Auth', 'description': 'Auth'}])
    apispec.create_tags([{'name': 'Role', 'description': 'Role'}])
    apispec.load_docstrings(app)
    return json.dumps(apispec.to_dict())
