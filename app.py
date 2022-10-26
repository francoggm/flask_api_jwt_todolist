from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    todo = db.relationship('Todo', backref="user")

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({"message": "Token is missing"}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({"message": "Invalid Token!"}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({"message": "Cannot perfom that function!"})

    users = User.query.all()
    output = [{"public_id": user.public_id, "name": user.name, "password": user.password, "admin": user.admin} for user in users]
    return jsonify(output)

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_users(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': "No user found"})
    return jsonify({"user": {"public_id": user.public_id, "name": user.name, "password": user.password, "admin": user.admin}})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({"message": "Cannot perfom that function!"})

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New User Created'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message": "Cannot perfom that function!"})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': "No user found"})
    user.admin = True
    db.session.commit()
    return jsonify({"message": "User has been promoted to admin"})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message": "Cannot perfom that function!"})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': "No user found"})
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User has been deleted"})

@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    
    if check_password_hash(user.password, auth.password):
        exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        token = jwt.encode({"public_id": user.public_id, "exp": exp}, app.config['SECRET_KEY'])
        return jsonify({"token": token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

@app.route('/todo')
@token_required
def get_all_todos(current_user):
    todos = Todo.query.filter_by(user_id=current_user.id).all()
    output = [{"id": todo.id, "text": todo.text, "complete": todo.complete} for todo in todos]
    return jsonify({"todos": output})

@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    todo = Todo.query.filter_by(user_id=current_user.id, id=int(todo_id)).first()
    if not todo:
        return jsonify({"message": "No todo found!"})
    return jsonify({"id": todo.id, "text": todo.text, "complete": todo.complete})

@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()
    new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({"message": "Todo created"})

@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(user_id=current_user.id, id=int(todo_id)).first()
    if not todo:
        return jsonify({"message": "No todo found!"})
    todo.complete = True
    db.session.commit()
    return jsonify({"message": "Todo item has been completed"})

@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(user_id=current_user.id, id=int(todo_id)).first()
    if not todo:
        return jsonify({"message": "No todo found!"})
    db.session.delete(todo)
    db.session.commit()
    return jsonify({"message": "Todo item has been deleted"})


if __name__ == '__main__':
    app.run(debug=True)