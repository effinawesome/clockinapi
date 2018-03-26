#!login/bin/python3
import os
from flask import Flask,jsonify, abort, make_response, request,g, url_for,render_template
from flask_httpauth import HTTPBasicAuth
from flask_restful import Api, Resource, reqparse, fields, marshal
from flask_sqlalchemy import SQLAlchemy
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

# init
app = Flask(__name__)
app.config['SECRET_KEY'] = 'power you can trust'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
api = Api(app)

# extentions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

class Job(db.Model):
    __tablename__ = 'jobs'
    jobid = db.Column(db.Integer, primary_key= True)
    username = db.Column(db.String(32), index = True)
    jobname = db.Column(db.String(128))
    intime = db.Column(db.String(128))
    incoords = db.Column(db.String(64))
    outtime = db.Column(db.String(128))
    outcoords = db.Column(db.String(64))

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32),index=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user = User.query.get(data['id'])
        return user

@auth.verify_password
def verify_password(username_or_token, password):
    user = User.verify_auth_token(username_or_token)
    if not user:
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/clockin/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)
    if User.query.filter_by(username=username).first() is not None:
        abort(400)
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username':user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})

@app.route('/clockin/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})

@app.route('/clockin/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})

@app.route('/clockin/api/resources')
@auth.login_required
def get_resource():
    return jsonify({'data':'Hello, %s!' % g.user.username})

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
        super(JobListAPI, self).__init__()

    def get(self):
        return {'jobs' : [marshal(job, job_fields) for job in jobs]}

    def post(self):
        args = self.reqparse.parse_args()
        job = {
            'id': jobs[-1]['id'] + 1,
            'jobname' : args['jobname'],
            'incoords':args['incoords'],
            'intime':args['intime']
        }
        jobs.append(job)
        return {'job':marshal(job,job_fields)} ,201

class JobAPI(Resource):
    decorators = [auth.login_required]
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('jobname', type = str, location='json')
        self.reqparse.add_argument('incoords', type = str, location='json')
        self.reqparse.add_argument('outtime', type = str, required = True, location='json')
        self.reqparse.add_argument('outcoords', type = str, default = "", location ='json')
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
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True)
