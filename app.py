import os

from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager

from resources.user import UserRegister, User, UserLogin, UserLogout, TokenRefresh
from resources.item import Item, ItemList
from resources.store import Store, StoreList
from blocklist import BLOCKLIST

app = Flask(__name__)
db_url= os.environ.get("DATABASE_URL", "sqlite:///data.db")
if db_url != "sqlite:///data.db":
  if db_url[:10] != "postgresql": #in case it is passed a 'postgres:<conn>' string
    db_url= f"postgresql{db_url[8:]}"
app.config['SQLALCHEMY_DATABASE_URI']= db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.secret_key = 'secretoprimordial'
api = Api(app)


@app.before_first_request
def create_tables():
    db.create_all()


jwt = JWTManager(app)

@jwt.additional_claims_loader
def add_claims_to_jwt(identity):
  if identity == 1: #instead of hard-coding, read from a config file or db
    return {"is_admin": True}
  return {"is_admin": False}

@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
  return jwt_payload['jti'] in BLOCKLIST

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'message': 'The token has expired.',
        'error': 'token_expired'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
  return jsonify({
    'message': 'Signature verfication failed.',
    'error': 'invalid_token'
  }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
  return jsonify({
    'message': 'Request does not contain an access token.',
    'error': 'authorization_required'
  }), 401

@jwt.needs_fresh_token_loader
def token_not_fresh_callback(jwt_header, jwt_payload):
  return jsonify({
    'message': 'The token is not fresh.',
    'error': 'fresh_token_required'
  }), 401

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
  return jsonify({
    'message': 'The token has been revoked.',
    'error': 'token_revoked'
  }), 401

api.add_resource(Store, '/store/<string:name>')
api.add_resource(StoreList, '/stores')
api.add_resource(Item, '/item/<string:name>')
api.add_resource(ItemList, '/items')
api.add_resource(UserRegister, '/register')
api.add_resource(User, "/user/<int:user_id>")
api.add_resource(UserLogin, "/login")
api.add_resource(UserLogout, "/logout")
api.add_resource(TokenRefresh, '/refresh')

if __name__ == '__main__':
    from db import db
    db.init_app(app)
    app.run(port=5000, debug=True)