#!login/bin/python3
import os
from flask import Flask,jsonify, abort, make_response, request,g, url_for,render_template
from flask_httpauth import HTTPBasicAuth
from flask_restful import Api, Resource, reqparse, fields, marshal
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy_declarations import User, Clockin

# init
app = Flask(__name__)
app.config['SECRET_KEY'] = 'power you can trust'
api = Api(app)
engine = create_engine('sqlite:///sqlite.db')

# extentions

DBSession = sessionmaker(bind = engine)
session = DBSession()
auth = HTTPBasicAuth()



@auth.verify_password
def verify_password(username_or_token, password):
    user = User.verify_auth_token(username_or_token)
    if not user:
        user = session.query(User).filter(User.username == username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/clockin/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    full_name = request.json.get('fullname')
    if username is None or password is None or full_name is None:
        abort(400)
    if session.query(User).filter(User.username == username).first() is not None:
        abort(400)
    user = User(username=username, full_name=full_name)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return (jsonify({'username':user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})

@app.route('/clockin/api/users/<int:id>')
def get_user(id):
    user = session.query(User).get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username, 'fullname' : user.full_name})

@app.route('/clockin/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})

@app.route('/clockin/api/resources')
@auth.login_required
def get_resource():
    return jsonify({'data':'%s' % g.user.username})

job_fields = {
    'jobname' : fields.String,
    'username': fields.String,
    'incoords' : fields.String,
    'intime' : fields.String,
    'outcoords' : fields.String,
    'outtime' : fields.String,
    'uri' : fields.Url('job')
}

class JobListAPI(Resource):
    decorators = [auth.login_required]
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('jobname', type = str, required = True,
            help= 'No job name provided', location = 'json')
        self.reqparse.add_argument('intime', type = str, required = True,
            help= 'No start time provided', location = 'json')
        self.reqparse.add_argument('incoords', type = str, default = "", location = 'json')
        self.reqparse.add_argument('outtime', type = str, required = True,
            help= 'No end time provided', location = 'json')
        self.reqparse.add_argument('outcoords', type = str, default = "", location ='json')
        super(JobListAPI, self).__init__()

    def get(self):
        return {'jobs' : [marshal(job, job_fields) for job in jobs]}

    def post(self):
        args = self.reqparse.parse_args()
        current_user = session.query(User).filter_by(username = g.user.username).first()
        job = Clockin(job_name = args['jobname'],
                      incoords = args['incoords'],
                      intime = args['intime'],
                      outcoords = args['outcoords'],
                      outtime = args['outtime'],
                      employee = current_user
                      )
        session.add(job)
        session.commit()
        return {'job':"success"} ,201

class JobAPI(Resource):
    decorators = [auth.login_required]
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('jobname', type = str, location='json')
        self.reqparse.add_argument('outtime', type = str, required = True, location='json')
        self.reqparse.add_argument('outcoords', type = str, default = "", location ='json')
        self.reqparse.add_argument('intime', type = str, required = True, location='json')
        self.reqparse.add_argument('incoords', type = str, default = "", location ='json')
        super(JobAPI, self).__init__()

    def get(self, id):
        job = [job for job in jobs if job['id'] == id]
        if len(job) == 0:
            abort(404)
        return ['job', marshal(job[0], job_fields)]

    def put(self,id):
        job = [job for job in jobs if job['id'] == id]
        if len(job) == 0:
            abort(404)
        job = job[0]
        args = self.reqparse.parse_args()
        for k, v in args.items():
            if v is not None:
                job[k] = v
        return {'job' : marshal(job,job_fields)}

    def delete(self,id):
        pass

api.add_resource(JobListAPI, '/clockin/api/jobs', endpoint = 'jobs')
api.add_resource(JobAPI, '/clockin/api/jobs/<int:id>', endpoint = 'job')

jobs = [{'id':1}]

@app.route('/')
def index():
    return render_template('index.html')

@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error':'Unauthorized Access'}),401)

if __name__ =='__main__':
    app.run(debug=True)
