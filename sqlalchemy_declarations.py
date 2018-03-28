import os
import sys
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

Base = declarative_base()
secret_key = 'power you can trust'

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(32),index=True)
    password_hash = Column(String(64))
    full_name = Column(String(128))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user = session.query(User).get(data['id'])
        return user

class Clockin(Base):
    __tablename__ = 'clockins'
    jobid = Column(Integer, primary_key=True)
    job_name = Column(String(250))
    intime = Column(String(250),nullable=False)
    incoords = Column(String(250))
    outtime = Column(String(250),nullable=False)
    outcoords = Column(String(250))
    employee_id = Column(Integer, ForeignKey('users.id'))
    employee = relationship(User)

engine = create_engine('sqlite:///sqlite.db')
DBSession = sessionmaker(bind = engine)
session = DBSession()
Base.metadata.create_all(engine)
