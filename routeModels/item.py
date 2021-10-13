from flask_restful import Resource, reqparse, abort, fields, marshal_with
import jwt
from decouple import config

from models import Session, engine, Base
from models.item import Item
from models.user import User

session = Session()

SECRET_KEY = config('ACCESS_SECRET_TOKEN')
BCRYPT_SALT = int(config('BCRYPT_SALT'))

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


class MyDateFormat(fields.Raw):
    def format(self, value):
        return value.strftime('%Y-%m-%d')


item_resource_fields = {
    "id": fields.String,
    "name": fields.String,
    "created_on": MyDateFormat
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
