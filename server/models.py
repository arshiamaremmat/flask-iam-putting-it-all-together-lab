from sqlalchemy.orm import validates, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from marshmallow import Schema, fields
from sqlalchemy import Column, Integer, String, ForeignKey

from config import db, bcrypt


class User(db.Model):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    _password_hash = Column("password_hash", String)  # stored column
    image_url = Column(String)
    bio = Column(String)

    # relationships
    recipes = relationship("Recipe", back_populates="user", cascade="all, delete-orphan")

    # password write-only property
    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")

    @password_hash.setter
    def password_hash(self, plain_text_password):
        self._password_hash = bcrypt.generate_password_hash(
            plain_text_password
        ).decode("utf-8")

    def authenticate(self, plain_text_password):
        if not self._password_hash:
            return False
        return bcrypt.check_password_hash(self._password_hash, plain_text_password)


class Recipe(db.Model):
    __tablename__ = 'recipes'

    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    instructions = Column(String, nullable=False)
    minutes_to_complete = Column(Integer)

    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="recipes")

    @validates("instructions")
    def validate_instructions(self, key, value):
        # The tests accept either an IntegrityError (via DB constraint) OR ValueError.
        # We provide a friendly ValueError here and also keep nullable=False above.
        if value is None or len(value.strip()) < 50:
            raise ValueError("Instructions must be at least 50 characters.")
        return value


# ------- Serialization Schemas --------

class UserSchema(Schema):
    id = fields.Integer()
    username = fields.String()
    image_url = fields.String()
    bio = fields.String()


class RecipeSchema(Schema):
    id = fields.Integer()
    title = fields.String()
    instructions = fields.String()
    minutes_to_complete = fields.Integer()
    user = fields.Nested(UserSchema)
