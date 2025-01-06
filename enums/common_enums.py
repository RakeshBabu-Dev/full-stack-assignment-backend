# user_type_enum.py
from enum import Enum

class UserType(Enum):
    PUBLIC = 3    # Public User
    EMPLOYEE = 2  # Employee User
    ADMIN = 1     # Admin User
