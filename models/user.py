from sqlalchemy import Column, Integer, String
from base import Base

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    password = Column(String, nullable=False)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password
