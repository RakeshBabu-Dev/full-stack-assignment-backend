from flask import Blueprint
from flask_restx import Api
from controllers.users import ns as user_controller

blueprint = Blueprint("api", __name__)

api = Api(blueprint, title="My API", version="1.0", description="HomePage")

print("IN_API_PAGE")  # Debug print to ensure namespaces are added
api.add_namespace(user_controller, path="/users")
