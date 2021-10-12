from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from decouple import config

DATABASE_URL = config('DATABASE_URL')
ENV = config('ENV')

local_database_url = 'sqlite:///items.db' # for local development
if ENV == 'prod':
    local_database_url = DATABASE_URL

engine = create_engine(local_database_url)
Session = sessionmaker(bind=engine)

Base = declarative_base()