from flask import Flask, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

app =Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bugs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

app.secret_key = "suckoutthebugs"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
         }
    

class Bug(db.Model):
    id = db.Column(db.Integer, unique=True, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False )

    def to_dict(self):
        return {
           'id': self.id,
           'title': self.title,
           'description': self.description,
           'status': self.status,
           'user_id': self.user_id
        }
    
def login_required(f):
    @wraps(f)
    def run(*args, **kwargs):
        if not 'user_id' in session:
            return jsonify({'error': 'You need to be logged in'}), 401
        return f(*args, **kwargs)
    return run

    
@app.route('/signup', methods=['POST'])
def signup():
    if not request.is_json:
        return jsonify({'error': 'Request must be in JSON'}), 400
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Must Contain username and Password'}), 400
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'Username is Taken'}), 409
    hashed = generate_password_hash(password)

    new_user = User(username=username, password=hashed)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Account created Successfully'}), 200

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({'error': 'Request must be in JSON'}), 400
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Must contain Username and password'}), 400
    
    user = User.query.filter_by(username=username).first()
    
    if user is None or not check_password_hash(user.password, password):
        return jsonify({'error': 'Username not Found'}), 401
    session['user_id'] = user.id
    return jsonify({'message': 'You are logged in'}), 200

@app.route('/bugs', methods=['POST'])
@login_required
def bugs():
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    status = data.get('status')

    if not title or not description or not status:
        return jsonify({'error': 'Request must contain title, description and status'}), 400
    
    bugs = Bug(title=title, description=description, status=status, user_id=session['user_id'])
    db.session.add(bugs)
    db.session.commit()
    return jsonify({'message': 'Bug created succesfully'}), 201

@app.route('/bugs', methods=['GET'])
@login_required
def get_my_bugs():
    report = Bug.query.filter_by(user_id=session['user_id']).all()
    if not report :
        return jsonify({'error': 'User hasnt logged in any bugs'}), 404
    return jsonify([bug.to_dict() for bug in report]), 200

@app.route('/bugs/<int:bug_id>', methods=['PATCH'])
@login_required
def fix_report(bug_id):
    bug = Bug.query.get(bug_id)
    if bug is None:
        return jsonify({'error': 'No bugs found'}), 404
    if bug.user_id != session['user_id']:
        return jsonify({'error': 'Not authorized'}),  403
    data = request.get_json()
    if  'title' in data:
        bug.title = data['title']
    if 'description' in data:
        bug.description = data['description']
    if 'status' in data:
        bug.status = data['status']

    db.session.commit()
    return jsonify({'message': 'bugs updated'}), 200

@app.route('/bugs/<int:bug_id>', methods=['DELETE'])
@login_required
def delete_bugs(bug_id):
    bug = Bug.query.get(bug_id)
    if bug is None:
        return jsonify({'error': f'NO bug with ID {bug_id} Found'}), 404
    if not bug.user_id == session['user_id']:
        return jsonify({'error': 'Not authorized'}), 403
    db.session.delete(bug)
    db.session.commit()
    return jsonify({'message': 'Bug deleted Successdully'}), 200
                       
@app.route('/logout', methods=['POST'])
def logout():
   session.pop('user_id', None)
   return jsonify({'message': 'Logout succesful'}), 200

    


    



with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)

