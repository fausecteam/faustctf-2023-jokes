from flask_login import UserMixin

from extensions import db, likes


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    name = db.Column(db.String(1000), unique=True)
    password = db.Column(db.String(100))
    liked_posts = db.relationship('Joke', secondary=likes, backref='likers')


class Joke(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    draft = db.Column(db.Boolean, default=False)
    under_review = db.Column(db.Boolean, default=False)
    category = db.Column(db.String(256))
    content = db.Column(db.String(4096))  # TODO adjust
    likes = db.Column(db.Integer, default=0)
