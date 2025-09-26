#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe, UserSchema, RecipeSchema

user_schema = UserSchema()
recipe_schema = RecipeSchema()
recipes_schema = RecipeSchema(many=True)

# ----------------- Helpers -----------------

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return db.session.get(User, uid)

def unauthorized():
    return {"error": "Unauthorized"}, 401

def unprocessable(errors):
    # Normalize error payload as an array of strings for the client UI
    # (frontend expects `err.errors`)
    if isinstance(errors, str):
        errors = [errors]
    return {"errors": errors}, 422


# ----------------- Resources -----------------

class Signup(Resource):
    def post(self):
        data = request.get_json() or {}
        username = data.get("username")
        password = data.get("password")
        image_url = data.get("image_url")
        bio = data.get("bio")

        if not username or not password:
            return unprocessable(["Username and password are required."])

        try:
            user = User(username=username, image_url=image_url, bio=bio)
            user.password_hash = password  # bcrypt setter
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return unprocessable(["Username must be unique."])
        except ValueError as e:
            db.session.rollback()
            return unprocessable([str(e)])

        session["user_id"] = user.id
        return user_schema.dump(user), 201


class CheckSession(Resource):
    def get(self):
        user = current_user()
        if not user:
            return unauthorized()
        return user_schema.dump(user), 200


class Login(Resource):
    def post(self):
        data = request.get_json() or {}
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return unauthorized()

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session["user_id"] = user.id
            return user_schema.dump(user), 200

        return unauthorized()


class Logout(Resource):
    def delete(self):
        if not session.get("user_id"):
            return unauthorized()
        session.pop("user_id", None)
        return "", 204


class RecipeIndex(Resource):
    def get(self):
        # auth required
        if not current_user():
            return unauthorized()

        recipes = Recipe.query.all()
        return recipes_schema.dump(recipes), 200

    def post(self):
        # auth required
        user = current_user()
        if not user:
            return unauthorized()

        data = request.get_json() or {}
        title = data.get("title")
        instructions = data.get("instructions")
        minutes = data.get("minutes_to_complete")

        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes,
                user=user,
            )
            db.session.add(recipe)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return unprocessable(["Title and instructions are required."])
        except ValueError as e:
            db.session.rollback()
            return unprocessable([str(e)])

        return recipe_schema.dump(recipe), 201


api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(RecipeIndex, "/recipes", endpoint="recipes")


if __name__ == '__main__':
    app.run(port=5555, debug=True)
