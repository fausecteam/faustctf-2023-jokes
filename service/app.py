import json
import os
import threading


import flask_login
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from flask import render_template, Blueprint, request, flash, jsonify, Response, current_app
from flask_login import login_required, current_user
from sqlalchemy import func

import categories
from events import PublicEvent, eventhandler, AdminEvent
from extensions import db
from models import Joke, User

app = Blueprint('app', __name__)
like_update_lock = threading.Lock()
team_id = int(open("/etc/team-num", "r").read())

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    c = request.args.get("category")
    if not c or c not in categories.category_list:
        return render_template('profile.html',
                               categories=categories.category_list,
                               jokes=Joke.query.filter_by(draft=False, under_review=False),
                               options=categories.category_list)
    else:
        return render_template('profile.html',
                               categories=categories.category_list,
                               jokes=Joke.query.filter_by(category=c, draft=False, under_review=False),
                               options=categories.category_list)


@app.route('/profile', methods=["POST"])
@login_required
def profile_post():
    if "message" in request.form:
        if not verify(request.form.get("message"), bytes.fromhex(request.form.get("hash"))):
            return Response("Not cool", 401)
        message = json.loads(request.form["message"])
        if message["team"] != team_id:
            return Response("", 401)
        loc = {}
        exec(message["action"], None, loc)
        return loc["rv"]
    if event := request.form.get("event"):
        if request.form.get("privileges") == "admin":
            if flask_login.current_user != "admin":
                return render_template("unauthorized.html", joke=Joke.query.filter_by(draft=False, under_review=False).order_by(func.random()).first()), 401
            else:
                return eventhandler[AdminEvent(event)]()
        elif request.form.get("privileges") == "public":
            return eventhandler[PublicEvent(event)]()
    return profile()


def export():
    print("export")
    return query_jokes()


def backup():
    print("backup")
    return query_jokes(True, True)


def query_jokes(draft=False, under_review=False):
    if draft and under_review:
        jokes = Joke.query.all()
    else:
        jokes = Joke.query.filter_by(draft=draft, under_review=under_review)
    jokes_list = {}
    for j in jokes:
        if j.category in jokes_list:
            jokes_list[j.category].append(j.content)
        else:
            jokes_list[j.category] = [j.content]
    return jsonify(jokes_list)


def submit_joke():
    if not capacity():
        flash("No capacity for further reviews. Please try again later", "error")
        return profile()
    category_title = request.form.get("category")
    if category_title not in categories.category_list:
        flash("This category does not exist", "error")
        return profile()
    joke = request.form.get("content")
    db.session.add(Joke(
        draft=False,
        under_review=True,
        category=category_title,
        content=joke
    ))
    current_app.logger.info("Submitted category:\n%s\njoke:\n%s", joke, category_title)
    db.session.commit()
    flash("Joke submitted", "info")
    return profile()


def submit_draft(category_title, joke):
    db.session.add(Joke(draft=True, category=category_title, content=joke))
    db.session.commit()
    return profile()


def capacity():
    return Joke.query.filter_by(under_review=True).count() < 1000


def process_reviewed_jokes():
    jokes = Joke.query.filter_by(under_review=True)
    for j in jokes:
        if j.likes >= 2:
            j.under_review = False
        else:
            db.session.delete(j)
    db.session.commit()
    return Response("", 200)


@app.route('/review', methods=["POST", "GET"])
@login_required
def review():
    print("review")
    if c := request.form.get("filter"):
        return render_template("review.html",
                               review=Joke.query.filter_by(under_review=True, category=c),
                               options=categories.category_list)
    return render_template("review.html",
                           review=Joke.query.filter_by(under_review=True),
                           options=categories.category_list)


@app.route('/like-joke', methods=["POST"])
@login_required
def like_joke():
    joke_id = request.json.get("joke_id")
    user_id = current_user.id
    user = User.query.get(user_id)
    with like_update_lock:
        joke = Joke.query.get(joke_id)
        if joke:
            likes = joke.likes
            if user and joke_id in [j.id for j in user.liked_posts]:
                joke.likes = likes - 1
                user.liked_posts.remove(joke)
            else:
                joke.likes = likes + 1
                user.liked_posts.append(joke)
            db.session.commit()
            return jsonify({'newLikeCount': joke.likes})


def verify(message, signature):
    with open(os.path.join(os.path.dirname(__file__), "public.key"), "rb") as key_file:
        key = RSA.importKey(key_file.read())
    verifier = pkcs1_15.new(key)
    try:
        verifier.verify(SHA256.new(message.encode()), signature)
    except (ValueError, TypeError):
        return False
    return True
