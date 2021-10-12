from flask import Flask
from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with
from flask_sqlalchemy import SQLAlchemy
import jwt
import bcrypt
from decouple import config

from models.item import Item
from models.user import User
from base import Session, engine, Base

Base.metadata.create_all(engine)
session = Session()

SECRET_KEY = config('ACCESS_SECRET_TOKEN')
BCRYPT_SALT = int(config('BCRYPT_SALT'))

app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///items.db'
database = SQLAlchemy(app)

item_get_delete_args = reqparse.RequestParser()
item_get_delete_args.add_argument(
    "Authorization", type=str, help="jwt is missing", location='headers', required=True)

item_put_args = reqparse.RequestParser()
item_put_args.add_argument(
    "name", type=str, help="name of the item is missing", required=True)
item_put_args.add_argument(
    "Authorization", type=str, help="jwt is missing", location='headers', required=True)

item_patch_args = reqparse.RequestParser()
item_patch_args.add_argument("name", type=str, required=True)
item_patch_args.add_argument(
    "Authorization", type=str, help="jwt is missing", location='headers', required=True)

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


class MyDateFormat(fields.Raw):
    def format(self, value):
        return value.strftime('%Y-%m-%d')


item_resource_fields = {
    "id": fields.String,
    "name": fields.String,
    "created_on": MyDateFormat
}

user_resource_fields = {
    "name": fields.String,
    "email": fields.String,
    "password": fields.String
}


def get_logged_in_user(token):
    try:
        user = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if not user['id']:
            abort(404, error="Token is invalid")
        return user['id']
    except:
        abort(404, error="Token is invalid")


class AllItems(Resource):
    @marshal_with(item_resource_fields)
    def get(self):
        args = item_get_delete_args.parse_args()
        logged_in_email = get_logged_in_user(
            args['Authorization'].split(' ')[1])
        result = session.query(Item).filter(
            Item.user_id == logged_in_email).all()
        if not result:
            abort(404, error="Items does not exist")
        return result

    @marshal_with(item_resource_fields)
    def put(self):
        args = item_put_args.parse_args()
        logged_in_email = get_logged_in_user(
            args['Authorization'].split(' ')[1])
        current_user = session.query(User).filter(
            User.id == logged_in_email).first()
        new_item = Item(args['name'], current_user)
        session.add(new_item)
        session.commit()
        return new_item, 201


class ParticularItem(Resource):
    @marshal_with(item_resource_fields)
    def get(self, item_id):
        args = item_get_delete_args.parse_args()
        logged_in_email = get_logged_in_user(
            args['Authorization'].split(' ')[1])
        result = session.query(Item).filter(Item.id == item_id).first()
        if not result:
            abort(404, error="Item does not exist")
        return result, 200

    @marshal_with(item_resource_fields)
    def patch(self, item_id):
        args = item_patch_args.parse_args()
        logged_in_email = get_logged_in_user(
            args['Authorization'].split(' ')[1])
        result = session.query(Item).filter(Item.id == item_id).first()
        if not result:
            abort(404, error="Item does not exist")
        if args["name"]:
            result.name = args["name"]
        session.commit()
        return result, 201

    @marshal_with(item_resource_fields)
    def delete(self, item_id):
        args = item_get_delete_args.parse_args()
        logged_in_email = get_logged_in_user(
            args['Authorization'].split(' ')[1])
        result = session.query(Item).filter(Item.id == item_id).first()
        if not result:
            abort(404, error="Item does not exist, cannot perform deletion")
        # session.query(Item).filter(Item.id == item_id).delete(synchronize_session=False)
        session.delete(result)
        session.commit()
        return result, 201


class ParticularUser(Resource):
    def post(self, param):
        if param == "login":
            args = user_login_args.parse_args()
            result = session.query(User).filter(
                User.email == args['email']).first()
            if not result:
                abort(404, error="User with email id does not exist")
            is_password_matching = bcrypt.checkpw(args['password'].encode('utf-8'), result.password.encode('utf-8'))
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
            hashed_password = str(bcrypt.hashpw(args['password'].encode('utf-8'), bcrypt.gensalt(BCRYPT_SALT))).replace("b'", "").replace("'", "")
            new_user = User(args['name'], args['email'], hashed_password)
            session.add(new_user)
            session.commit()
            return new_user, 201
        else:
            abort(404, error="Route does not exist")


api.add_resource(ParticularItem, "/item/<string:item_id>")
api.add_resource(AllItems, "/item")
api.add_resource(ParticularUser, "/auth/<string:param>")

if __name__ == "__main__":
    app.run(debug=True)
