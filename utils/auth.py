# utils/auth.py
from flask_jwt_extended import get_jwt_identity
from models.user_model import Users as UserModel

def check_role(required_role):
    """Helper function to check if user has the required role."""
    def decorator(fn):
        def wrapper(*args, **kwargs):
            current_user_email = get_jwt_identity()
            user = UserModel.objects(email=current_user_email).first()
            if not user:
                return {"message": "User not found"}, 404

            if user.user_type != required_role:
                return {"message": "Unauthorized access"}, 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator
