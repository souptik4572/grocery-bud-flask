from flask import Flask
from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///items.db'
database = SQLAlchemy(app)


class ItemModel(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    name = database.Column(database.String(50), nullable=False)

    def __repr__(self) -> str:
        return f"Item(id = {self.id}, name = {self.name})"

# database.create_all()


item_put_args = reqparse.RequestParser()
item_put_args.add_argument(
    "name", type=str, help="name of the item is missing", required=True)

item_patch_args = reqparse.RequestParser()
item_patch_args.add_argument("name", type=str)

item_resource_fields = {
    "id": fields.String,
    "name": fields.String
}


class AllItems(Resource):
    @marshal_with(item_resource_fields)
    def get(self):
        result = ItemModel.query.all()
        if not result:
            abort(404, error="Items does not exist")
        return result


class ParticularItem(Resource):
    @marshal_with(item_resource_fields)
    def get(self, item_id):
        result = ItemModel.query.filter_by(id=item_id).first()
        if not result:
            abort(404, error="Item does not exist")
        return result, 200

    @marshal_with(item_resource_fields)
    def put(self, item_id):
        result = ItemModel.query.filter_by(id=item_id).first()
        if result:
            abort(404, error="Item already exists, cannot be overwritten")
        args = item_put_args.parse_args()
        new_item = ItemModel(id=item_id, name=args['name'])
        database.session.add(new_item)
        database.session.commit()
        return new_item, 201

    @marshal_with(item_resource_fields)
    def patch(self, item_id):
        result = ItemModel.query.filter_by(id=item_id).first()
        if not result:
            abort(404, error="Item does not exist")
        args = item_patch_args.parse_args()
        if args["name"]:
            result.name = args["name"]
        database.session.commit()
        return result, 201

    @marshal_with(item_resource_fields)
    def delete(self, item_id):
        result = ItemModel.query.filter_by(id=item_id).first()
        if not result:
            abort(404, error="Item does not exist, cannot perform deletion")
        ItemModel.query.filter_by(id=item_id).delete()
        database.session.commit()
        return result, 201


api.add_resource(ParticularItem, "/item/<int:item_id>")
api.add_resource(AllItems, "/item")

if __name__ == "__main__":
    app.run(debug=True)
