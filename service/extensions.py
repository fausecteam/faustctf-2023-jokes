from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
likes = db.Table('likes',
                 db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                 db.Column('joke_id', db.Integer, db.ForeignKey('joke.id'), primary_key=True)
                 )
login_manager = LoginManager()
