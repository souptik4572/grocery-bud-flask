from flask_restful import Resource, reqparse, abort, fields, marshal_with
import jwt
import bcrypt
from decouple import config

from models import Session, engine, Base
from models.user import User

session = Session()

SECRET_KEY = config('ACCESS_SECRET_TOKEN')
BCRYPT_SALT = int(config('BCRYPT_SALT'))

user_register_args = reqparse.RequestParser()
user_register_args.add_argument(
    "name", type=str, help="name is missing", required=True)
user_register_args.add_argument(
    "email", type=str, help="email is missing", required=True)
user_register_args.add_argument(
    "password", type=str, help="password is missing", required=True)

user_login_args = reqparse.RequestParser()
user_login_args.add_argument(
    "email", type=str, help="email is missing", required=True)
user_login_args.add_argument(
    "password", type=str, help="password is missing", required=True)

user_resource_fields = {
    "name": fields.String,
    "email": fields.String,
    "password": fields.String
}


class ParticularUser(Resource):
    def post(self, param):
        if param == "login":
            args = user_login_args.parse_args()
            result = session.query(User).filter(
                User.email == args['email']).first()
            if not result:
                abort(404, error="User with email id does not exist")
            is_password_matching = bcrypt.checkpw(
                args['password'].encode('utf-8'), result.password.encode('utf-8'))
            if is_password_matching:
                encoded_token = jwt.encode(
                    {"email": result.email, "id": result.id}, SECRET_KEY, algorithm='HS256')
                return {'name': result.name, 'token': encoded_token}
            abort(404, error="Passwords does not match")
        else:
            abort(404, error="Route does not exist")

    @marshal_with(user_resource_fields)
    def put(self, param):
        if param == "register":
            args = user_register_args.parse_args()
            result = session.query(User).filter(
                User.email == args['email']).first()
            if result:
                abort(404, error="User already exists")
            hashed_password = str(bcrypt.hashpw(args['password'].encode(
                'utf-8'), bcrypt.gensalt(BCRYPT_SALT))).replace("b'", "").replace("'", "")
            new_user = User(args['name'], args['email'], hashed_password)
            session.add(new_user)
            session.commit()
            return new_user, 201
        else:
            abort(404, error="Route does not exist")
