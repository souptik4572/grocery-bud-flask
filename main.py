from flask import Flask
from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
import jwt
import bcrypt
import jwt
from uuid import uuid1
from decouple import config

SECRET_KEY = config('ACCESS_SECRET_TOKEN')
BCRYPT_SALT = int(config('BCRYPT_SALT'))

app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///items.db'
database = SQLAlchemy(app)


class ItemModel(database.Model):
    id = database.Column(database.String, primary_key=True)
    name = database.Column(database.String(50), nullable=False)
    owner_email = database.Column(database.String, database.ForeignKey(
        'user_model.email'), nullable=False)

    def __repr__(self) -> str:
        return f"Item(id = {self.id}, name = {self.name})"


class UserModel(database.Model):
    name = database.Column(database.String(150), nullable=False)
    email = database.Column(database.String(200), primary_key=True)
    password = database.Column(database.String(200), nullable=False)
    items = database.relationship('ItemModel', backref='item_model')

    def __repr__(self) -> str:
        return f"User(name = {self.name}, email = {self.email}, password = {self.password})"

# database.create_all()


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

item_resource_fields = {
    "id": fields.String,
    "name": fields.String,
    "owner_email": fields.String
}

user_resource_fields = {
    "name": fields.String,
    "email": fields.String,
    "password": fields.String
}


def get_logged_in_user(token):
    try:
        user = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if not user['email']:
            abort(404, error="Token is invalid")
        return user['email']
    except:
        abort(404, error="Token is invalid")


class AllItems(Resource):
    @marshal_with(item_resource_fields)
    def get(self):
        args = item_get_delete_args.parse_args()
        logged_in_email = get_logged_in_user(
            args['Authorization'].split(' ')[1])
        result = ItemModel.query.filter_by(
            owner_email=logged_in_email).all()
        if not result:
            abort(404, error="Items does not exist")
        return result

    @marshal_with(item_resource_fields)
    def put(self):
        args = item_put_args.parse_args()
        logged_in_email = get_logged_in_user(
            args['Authorization'].split(' ')[1])
        new_item = ItemModel(
            id=str(uuid1()), name=args['name'], owner_email=logged_in_email)
        database.session.add(new_item)
        database.session.commit()
        return new_item, 201


class ParticularItem(Resource):
    @marshal_with(item_resource_fields)
    def get(self, item_id):
        args = item_get_delete_args.parse_args()
        logged_in_email = get_logged_in_user(
            args['Authorization'].split(' ')[1])
        result = ItemModel.query.filter_by(id=item_id).first()
        if not result:
            abort(404, error="Item does not exist")
        return result, 200

    @marshal_with(item_resource_fields)
    def patch(self, item_id):
        args = item_patch_args.parse_args()
        logged_in_email = get_logged_in_user(
            args['Authorization'].split(' ')[1])
        result = ItemModel.query.filter_by(id=item_id).first()
        if not result:
            abort(404, error="Item does not exist")
        if args["name"]:
            result.name = args["name"]
        database.session.commit()
        return result, 201

    @marshal_with(item_resource_fields)
    def delete(self, item_id):
        args = item_get_delete_args.parse_args()
        logged_in_email = get_logged_in_user(
            args['Authorization'].split(' ')[1])
        result = ItemModel.query.filter_by(id=item_id).first()
        if not result:
            abort(404, error="Item does not exist, cannot perform deletion")
        ItemModel.query.filter_by(id=item_id).delete()
        database.session.commit()
        return result, 201


class ParticularUser(Resource):
    def post(self, param):
        if param == "login":
            args = user_login_args.parse_args()
            result = UserModel.query.filter_by(email=args['email']).first()
            if not result:
                abort(404, error="User with email id does not exist")
            is_password_matching = bcrypt.checkpw(
                args['password'].encode('utf-8'), result.password)
            if is_password_matching:
                encoded_token = jwt.encode(
                    {"email": result.email}, SECRET_KEY, algorithm='HS256')
                return {'token': encoded_token}
            abort(404, error="Passwords does not match")
        else:
            abort(404, error="Route does not exist")

    @marshal_with(user_resource_fields)
    def put(self, param):
        if param == "register":
            args = user_register_args.parse_args()
            result = UserModel.query.filter_by(email=args['email']).first()
            if result:
                abort(404, error="User already exists")
            hashed_password = bcrypt.hashpw(
                args['password'].encode('utf-8'), bcrypt.gensalt(BCRYPT_SALT))
            new_user = UserModel(
                email=args['email'], name=args['name'], password=hashed_password)
            database.session.add(new_user)
            database.session.commit()
            return new_user, 201
        else:
            abort(404, error="Route does not exist")


api.add_resource(ParticularItem, "/item/<string:item_id>")
api.add_resource(AllItems, "/item")
api.add_resource(ParticularUser, "/auth/<string:param>")

if __name__ == "__main__":
    app.run(debug=True)
