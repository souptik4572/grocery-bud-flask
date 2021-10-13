from flask import Flask
from flask_restful import Api
from decouple import config

from models import Base, engine

from routeModels.user import ParticularUser
from routeModels.item import ParticularItem, AllItems

SECRET_KEY = config('ACCESS_SECRET_TOKEN')
BCRYPT_SALT = int(config('BCRYPT_SALT'))

app = Flask(__name__)
api = Api(app)

Base.metadata.create_all(engine)

api.add_resource(ParticularItem, "/item/<string:item_id>")
api.add_resource(AllItems, "/item")
api.add_resource(ParticularUser, "/auth/<string:param>")

if __name__ == "__main__":
    app.run(debug=True)
