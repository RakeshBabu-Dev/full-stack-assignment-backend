from flask_restx import Namespace, Resource, fields,Api
from flask import request
from models.user_model import Users as UserModel
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from utils.auth import check_role  # Import the helper function for role-based access control
from schemas.user_schema import UserSchema
from bson import ObjectId
from api import Blueprint

blueprint = Blueprint("Users", __name__)
api = Api(blueprint)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Define the namespace for users
ns = Namespace("users", description="User operations")

# Define user models for Swagger UI documentation
user_register_model = ns.model('Register', {
    'email': fields.String(required=True, description="User's email"),
    'password': fields.String(required=True, description="User's password"),
})

user_login_model = ns.model('Login', {
    'email': fields.String(required=True, description="User's email"),
    'password': fields.String(required=True, description="User's password"),
})

response_model = ns.model('Response', {
    'message': fields.String(description="Response message"),
    'access_token': fields.String(description="JWT Access Token", required=False),
    'refresh_token': fields.String(description="JWT Refresh Token", required=False),
})
reset_password_model = ns.model('ResetPassword', {
    'currentPassword': fields.String(required=True, description="Current password of the user"),
    'newPassword': fields.String(required=True, description="New password to be set"),
    'id' : fields.String(required = True ) 
})


# Routes

# User Registration Route - POST Method (Create user)
@ns.route('/register')
class Register(Resource):
    @ns.expect(user_register_model)
    @ns.response(201, "User registered successfully", response_model)
    @ns.response(400, "Invalid input")
    def post(self):
        """Register a new user"""
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return {'message': 'Email and Password are required'}, 400

        # Check if user already exists
        if UserModel.objects(email=email).first():
            return {'message': 'User already exists'}, 400

        # Hash the password and save user
        hashed_password = generate_password_hash(password)
        user = UserModel(email=email, password=hashed_password)
        user.save()

        return {'message': 'User registered successfully'}, 201


# User Login Route - POST Method (Authenticate and return JWT)
@ns.route('/login')
class Login(Resource):
    @ns.expect(user_login_model)
    @limiter.limit("3 per minute", key_func=lambda: request.json.get('email'))  # Limit per user
    @ns.response(429, "Too many login attempts, please try again later.")
    @ns.response(200, "Login successful", response_model)
    @ns.response(401, "Invalid email or password")
    @ns.response(400, "Invalid input")
    def post(self):
        """Login user and return JWT"""
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return {'message': 'Email and Password are required'}, 400

        # Authenticate user
        user = UserModel.objects(email=email, status = 1).first()
        if not user or not check_password_hash(user.password, password):
            if not user:
                return {'message': 'No User Found, Please Contact your admin if you not Registered'}, 401
            if not check_password_hash(user.password, password):
                return {'message': 'Invalid email or password'}, 401
        # Create JWT tokens (access token)
        access_token = create_access_token(identity=email)
        refresh_token = create_refresh_token(identity=email)

        return {
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'current_user': UserSchema(many = False).dump(user),
        }, 200


# User Profile Route - GET Method (Retrieve logged-in user's profile)
@ns.route('/profile')
class UserProfile(Resource):
    @jwt_required()  # Protect this endpoint with JWT
    def get(self):
        """Get logged-in user info"""
        current_user = get_jwt_identity()
        user = UserModel.objects(email=current_user).first()
        if not user:
            return {'message': 'User not found'}, 404

        return {'email': user.email, 'name': user.name, 'status': user.status}, 200


# User Status Update Route - PATCH Method (Update user status)
@ns.route("/")
class UserConfig(Resource):
    def patch(self):
        status_data = api.payload
        print(status_data, "STATUS")

        user_id = status_data.get('id')
        new_status = status_data.get('status')
        if not user_id or new_status is None:
            return {'message': 'Invalid input'}, 400

        user_model = UserModel.objects(_id=ObjectId(user_id)).first()
        if not user_model:
            return {'message': 'User not found'}, 404

        UserModel.objects(_id=ObjectId(user_id)).update(set__status= 0 if new_status == 1 else 1 )

        return {'message': 'User status updated successfully'}, 200


# Token Refresh Route - POST Method (Refresh JWT token)
@ns.route('/refresh')
class TokenRefresh(Resource):
    @jwt_required(refresh=True)  # Requires the refresh token
    def post(self):
        """Refresh the access token"""
        identity = get_jwt_identity()
        new_access_token = create_access_token(identity=identity)
        return {'access_token': new_access_token}, 200


# Admin-only Route
@ns.route('/admin-only')
class AdminOnly(Resource):
    @jwt_required()
    @check_role(1)  # Only Admins can access this route
    def get(self):
        return {"message": "Welcome, Admin!"}


# Employee-only Route
@ns.route('/employee-dashboard')
class EmployeeDashboard(Resource):
    @jwt_required()
    @check_role(2)  # Only Employees can access this route
    def get(self):
        return {"message": "Welcome, Employee!"}


# Public Route (accessible by everyone)
@ns.route('/public-dashboard')
class PublicDashboard(Resource):
    @jwt_required(optional=True)  # Public can access without login
    def get(self):
        return {"message": "Welcome, Public!"}

@ns.route("/grid-data")
class UserListResource(Resource):
    def get(self):
        user_model = UserModel.objects.all()
        if not user_model:  # Check if the user_model is empty
            return {'message': 'No users found'}, 404
        user_data = UserSchema(many=True).dump(user_model)
        return {'message': user_data}
    
@ns.route('/reset-password')
class ResetPassword(Resource):
    @jwt_required()  # Protect this route with JWT
    @ns.expect(reset_password_model)
    @ns.response(200, "Password reset successfully")
    @ns.response(400, "Invalid input")
    @ns.response(401, "Current password is incorrect")
    def post(self):
        credential = api.payload
        print(credential,"CURRENT")
        user = UserModel.objects(_id = ObjectId(credential.get('id'))).first()
        if not user:
            return {'message': 'User not found'}, 404

        current_password = credential.get('currentPassword')
        new_password = credential.get('newPassword')

        if not current_password or not new_password:
            return {'message': 'Current password and new password are required'}, 400

        if not check_password_hash(user.password, current_password):
            return {'message': 'Current password is incorrect'}, 401

        UserModel.objects(_id = ObjectId(credential.get('id'))).update(set__password=generate_password_hash(new_password))

        return {'message': 'Password reset successfully'}, 200
    