from marshmallow import Schema, fields,post_dump
from bson import ObjectId

class UserSchema(Schema):
    id = fields.String(attribute='_id')  # Maps Mongo's '_id' to 'id'
    name = fields.String(required=True)
    email = fields.String(required=True)
    status = fields.Integer(required=True)
    user_type = fields.Integer(required=True)
    # password = fields.String(required=True)

    