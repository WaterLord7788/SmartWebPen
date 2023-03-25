from flask import Flask, flash, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from os.path import join, dirname, realpath
from os import path
import os


db = SQLAlchemy()
DB_NAME = "database.db"
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'doc'}
UPLOAD_FOLDER = join(dirname(realpath(__file__)), 'static/img/')

ADMIN = "kristian.paivinen@yahoo.com"
SIGNUP_ENABLED = True

MIN_NUMER_FILEGENERATOR = 100000
MAX_NUMBER_FILEGENERATION = 999999 # Useful to set higher in order to increase randomness

GENERATED_OUTPUT_DIRECTORY = 'generated/'
SUBDOMAIN_SCAN_OUTPUT_DIRECTORY = join(dirname(realpath(__file__)), GENERATED_OUTPUT_DIRECTORY, 'subdomains/')
PORT_SCAN_OUTPUT_DIRECTORY = join(dirname(realpath(__file__)), GENERATED_OUTPUT_DIRECTORY, 'ports/')
VULNERABILITY_SCAN_OUTPUT_DIRECTORY = join(dirname(realpath(__file__)), GENERATED_OUTPUT_DIRECTORY, 'vulnerabilities/')


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
 

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import User
    
    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))
    
    from .check import checkForFolders
    checkForFolders(GENERATED_OUTPUT_DIRECTORY, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, PORT_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY)

    return app


def create_database(app):
    if not path.exists('website/' + DB_NAME):
        db.create_all(app=app)
        print('Created Database!')
