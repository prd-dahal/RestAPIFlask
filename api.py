#Username: pradeep
#Password: hello
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import os 
import jwt
import datetime
from functools import wraps




file_path = os.path.abspath(os.getcwd())+"\database.db"
print(file_path)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'asecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+file_path

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(50), unique = True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class BlockedTokens(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    blocks = db.Column(db.String(500))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
            
        if not token:
            return jsonify({'message':'Token is missing!'}),401
        
        #check for the logout
        blockedTokens = BlockedTokens.query.all()
        for blockedToken in blockedTokens:
                if blockedToken.blocks == token:
                    return jsonify({'message':'You are logged out!'})
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            header_data = jwt.get_unverified_header(token)
            current_user = User.query.filter_by(public_id = data['public_id']).first()
        except:
            return jsonify({'message':'Token is invalid'}),401
        return f(current_user,token, *args, **kwargs)
    return decorated

#this route gives the user information for admin. x-access-token must be provided in headers to get information 
@app.route('/user', methods=['GET'])
@token_required  
def get_all_users(current_user,token):
    users = User.query.all()
    if not current_user.admin:
        return jsonify({'message':'you are not authorized to see all data go to user/me to get your info'})
    output = []
    for user in users:
        user_data = {}
        user_data["public_id"] = user.public_id 
        user_data["name"] = user.name
        # user_data["password"] = user.password
        user_data["admin"] = user.admin
        output.append(user_data)
    return jsonify({'users':output})

#route to get personal info of any user. Must provide 'x-access-token' of given particular user
@app.route('/user/me', methods =['GET'])
@token_required
def get_one_user(current_user, token):
    cur_usr = {}
    cur_usr["public_id"] = current_user.public_id
    cur_usr["name"] = current_user.name
    cur_usr["admin"] = current_user.admin
    return jsonify({'current_user':cur_usr})

#put route not implemented 
@app.route('/user/<user_id>', methods =['PUT'])
def promote_user(user_id):
    
    return ''

#route to create user must provide {'username':'usr', 'password':'psw'} in json format in body of request
@app.route('/user', methods=['POST'])
def create_user():
    new_user_data = request.get_json()
    
    hash_password = generate_password_hash(new_user_data['password'], method = 'sha256')
    new_user = User(public_id= str(uuid.uuid4()), name = new_user_data['name'], password = hash_password, admin = False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message':'New User Created'})

#delete a user based on the public id. Only admin can delete users
@app.route('/user/<public_id>', methods = ['DELETE'])
@token_required 
def delete_user(current_user, token, public_id):
    
    if not current_user.admin:
        return jsonify({'message':'Not authorized to delete'})
    
    user = User.query.filter_by(public_id = public_id).first()
    if not user:
        return jsonify({'message':'No User Found!'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message':'The user has been deleted!'})

#secured route which can be accessed by any authorized user
@app.route('/securedRoute', methods = ['GET'])
@token_required
def secured_route(current_user, token):
    print(current_user)
    return jsonify({'message':'Hello '+ str(current_user.name) +' Welcome to this secured endpoint.'})

#this routes takes in username and password verify it in database and returns token 
@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm = "Login required!'})
    
    user = User.query.filter_by(name = auth.username).first()
    if not user:
        return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm = "Login required!'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id':user.public_id, 'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes = 600)}, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({'token':token})
    return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm = "Login required!'})

##logs out from the system by blacklisting the token
@app.route('/logout')
@token_required
def logout(current_user, token):
    blockedTokens = BlockedTokens(blocks = token )
    db.session.add(blockedTokens)
    db.session.commit()
    return jsonify({'message':'logout successfully'})

if __name__ == '__main__':
    app.run(debug = True)