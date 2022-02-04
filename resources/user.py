from flask_restful import Resource, reqparse
from werkzeug.security import safe_str_cmp
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from models.user import UserModel
from blocklist import BLOCKLIST

_user_parser = reqparse.RequestParser()
_user_parser.add_argument(
    'username',
    type=str,
    required=True,
    help="This field cannot be blank."
)
_user_parser.add_argument(
    'password',
    type=str,
    required=True,
    help="This field cannot be blank."
)

class UserRegister(Resource):
    def post(self):
        data = _user_parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {"message": "A user with that username already exists"}, 400

        user = UserModel(**data)
        user.save_to_db()

        return {"message": "User created successfully."}, 201


class User(Resource):
    @classmethod
    def get(cls, user_id):
        user= UserModel.find_by_id(user_id)
        if not user:
            return {"message": "User not found TT"}, 404
        return user.json()

    @classmethod
    def delete(cls, user_id):
        user= UserModel.find_by_id(user_id)
        if not user:
            return {"message": "User not found TT"}, 404
        user.delete_from_db()
        return {"message": "User deleted!"}


class UserLogin(Resource):
    @classmethod
    def post(self):
        #get data from _user_parser
        data= _user_parser.parse_args()

        #find user in db
        user= UserModel.find_by_username(data["username"])

        #check passwd
        #create access token
        #create refresh token
        #what 'authenticate()' in JWT used to do
        if user and safe_str_cmp(user.password, data["password"]):
            acces_token= create_access_token(identity=user.id, fresh=True)
            refresh_token= create_refresh_token(user.id)
            return {
                "access_token": acces_token,
                "refresh_token": refresh_token
            }
        return {"message": "Invalid Credentials"}, 401



class UserLogout(Resource):
    @jwt_required()
    def post(self):
        jti= get_jwt()['jti']
        print(f"jti: {jti}")
        BLOCKLIST.add(jti)
        return {"message": "Successfully logged out!"}


class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user= get_jwt_identity()
        new_token= create_access_token(identity=current_user, fresh=False)
        return {'access_token': new_token}