class Config:
    # Flask secret key
    SECRET_KEY = '9d8f4c2a6f734b6dc9ea843028a29a8452b8bbfdbe3caaed31bc4cc5e1ad2374'

    # SQLite database file
    SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'

    # Disable modification tracking (performance boost)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

