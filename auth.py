import os
from flask import Flask, abort, request,jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

app.config['SECRET_KEY'] = 'power you can trust'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

print("imported")
