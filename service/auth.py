import flask
import flask_login
from flask import Blueprint, render_template, url_for, redirect, request, flash, current_app
from flask_login import login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db
from models import User

auth = Blueprint('auth', __name__)


@auth.route('/login')
def login():
    return render_template('index.html')


@auth.route('/login', methods=['POST'])
def login_post():
    name = request.form.get("name")
    password = request.form.get("password")
    user = User.query.filter_by(name=name).first()
    if not user or not check_password_hash(user.password, password):
        flash("User or password wrong")
        return render_template('index.html'), 401
    login_user(user)
    return redirect(url_for('app.profile'))


@auth.route('/register')
def register():
    return render_template('register.html')


@auth.route('/register', methods=['POST'])
def register_post():
    name = request.form.get("name")
    password = request.form.get("password")
    user = User.query.filter_by(name=name).first()
    if user or name == "admin":
        flash("Name exists already.")
        return render_template('register.html'), 409
    new_user = User(name=name, password=generate_password_hash(password, method='scrypt'))
    current_app.logger.info("Added user %s", name)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('auth.login'))


@auth.route('/logout')
def logout():
    # TODO add button on website
    current_app.logger.info("User %s logged out", flask_login.current_user)
    logout_user()
    return redirect(url_for('auth.login'))
