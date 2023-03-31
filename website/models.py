from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    description = db.Column(db.String(500))
    profile_picture = db.Column(db.String(250))
    phone = db.Column(db.String(50))

    subdomains = db.relationship('Subdomains')

"""
class Subdomains(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(50000))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
"""

class Subdomains(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500))
    methods = db.Column(db.String(1000))
    tools = db.Column(db.String(1000))
    files = db.Column(db.String(1000))
    resultFiles = db.Column(db.String(1000))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    entryID = db.Column(db.String(50))

class Vulnerabilities(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500))
    methods = db.Column(db.String(1000))
    tools = db.Column(db.String(1000))
    files = db.Column(db.String(1000))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    entryID = db.Column(db.String(50))