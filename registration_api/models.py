from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

# Initialize extensions (to be connected to app in app.py)
db = SQLAlchemy()
bcrypt = Bcrypt()

# User model (table)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique user ID
    username = db.Column(db.String(50), unique=True, nullable=False)  # Must be unique
    email = db.Column(db.String(120), unique=True, nullable=False)    # Must be unique
    password = db.Column(db.String(128), nullable=False)              # Hashed password
