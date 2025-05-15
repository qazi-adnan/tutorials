from flask import Flask, request, jsonify
from config import Config
from models import db, bcrypt, User
import jwt
import datetime
from functools import wraps


app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt.init_app(app)

# 🔄 Instead of @app.before_first_request, we use app.app_context
with app.app_context():
    db.create_all()



def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=Config.JWT_EXPIRATION_SECONDS)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 403
        try:
            if token.startswith('Bearer '):
                token = token.split(' ')[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({'message': 'Invalid or expired token'}), 403
        return f(current_user, *args, **kwargs)
    return decorated
    


# Registration endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid email or password'}), 401

    token = generate_token(user.id)
    return jsonify({'message': 'Login successful', 'token': token}), 200


@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user):
    return jsonify({
        'message': f'Hello {current_user.username}, you have access to this protected route!'
    })

    
@app.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email
    })



@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    user_list = []

    for user in users:
        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email
            # Note: Don't return passwords
        }
        user_list.append(user_data)

    return jsonify(user_list)




if __name__ == '__main__':
    app.run(debug=True)

