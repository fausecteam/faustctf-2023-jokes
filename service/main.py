import os

from flask import Flask, render_template

import app
from app import app as app_blueprint
from auth import auth as auth_blueprint
from events import register_event
from extensions import db, login_manager
from models import User
from init import init_application


def init_eventhandler():
    register_event("submit", app.submit_joke, False)
    register_event("review", app.review, False),
    register_event("export", app.export, False)
    register_event("backup", app.backup)


def create_app(only_create_database=False):
    _application = Flask(__name__)
    _application.config["SECRET_KEY"] = os.urandom(24)
    _application.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///db.sqlite'
    _application.register_blueprint(auth_blueprint)
    _application.register_blueprint(app_blueprint)
    login_manager.login_view = 'auth.login'
    init_eventhandler()
    with _application.app_context():
        db.init_app(_application)
        db.drop_all()
        db.create_all()
        init_application()
        login_manager.init_app(_application)
    return _application


service = create_app()


@service.route('/')
def hello_world():  # put application's code here
    return render_template('index.html')


@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(int(user_id))
