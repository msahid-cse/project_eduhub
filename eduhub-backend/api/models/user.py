from mongoengine import Document, StringField

class User(Document):
    username = StringField(required=True, unique=True)
    email = StringField(required=True, unique=True)
    password = StringField(required=True)  # Store hashed password
    role = StringField(choices=["admin", "user"], default="user")
