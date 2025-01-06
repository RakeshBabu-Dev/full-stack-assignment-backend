from mongoengine import Document, StringField, IntField, ObjectIdField
from bson import ObjectId
from enums.common_enums import UserType
class Users(Document):
    _id = ObjectIdField(default = ObjectId)
    name = StringField()
    email = StringField()
    status = IntField(default = 1)  # 1 for active, 0 for inactive
    user_type = IntField(default = UserType.EMPLOYEE.value)  # 1 for admin, 2 for employee, 3 for public
    password = StringField()



