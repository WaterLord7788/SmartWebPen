from flask import Flask, flash, request, redirect, url_for
from os.path import join, dirname, realpath
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from .systemFunctions import generateSafeSecret
from pathlib import Path
from os import path
import warnings
import logging
import click
import toml
import os



config = toml.load('./config.toml')
db = SQLAlchemy()


DB_NAME = config['db']['DB_NAME']
GENERATE_SECRET_KEY_ON_RESTART = config['security']['GENERATE_SECRET_KEY_ON_RESTART']
SECRET_KEY = config['security']['SECRET_KEY']
ADMIN = config['security']['ADMIN']
DEBUG_ENABLED = config['security']['DEBUG_ENABLED']
SIGNUP_ENABLED = config['security']['SIGNUP_ENABLED']

MIN_NUMBER_FILEGENERATOR = config['filegen']['MIN_NUMBER_FILEGENERATOR']
MAX_NUMBER_FILEGENERATION = config['filegen']['MAX_NUMBER_FILEGENERATION']
GENERATED_OUTPUT_DIRECTORY = config['filegen']['GENERATED_OUTPUT_DIRECTORY']

GENERAL_LOGGING_DISABLED = config['logging']['GENERAL_LOGGING_DISABLED']

SCREENSHOT_DELAY_SECONDS = config['functions']['SCREENSHOT_DELAY_SECONDS']
PING_COUNT_NUMBER        = config['functions']['PING_COUNT_NUMBER']
GOSPIDER_DEPTH_NUMBER    = config['functions']['GOSPIDER_DEPTH_NUMBER']
AMASS_TIMEOUT_MINUTES    = config['functions']['AMASS_TIMEOUT_MINUTES']
WAYMORE_TIMEOUT_MINUTES  = config['functions']['WAYMORE_TIMEOUT_MINUTES']


ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'doc'}
UPLOAD_FOLDER = join(dirname(realpath(__file__)), 'static/img/')
UPLOAD_FOLDER = join(dirname(realpath(__file__)), 'static/img/')
SUBDOMAIN_SCAN_OUTPUT_DIRECTORY     = join(dirname(realpath(__file__)), GENERATED_OUTPUT_DIRECTORY, 'subdomains/')
PORT_SCAN_OUTPUT_DIRECTORY          = join(dirname(realpath(__file__)), GENERATED_OUTPUT_DIRECTORY, 'ports/')
VULNERABILITY_SCAN_OUTPUT_DIRECTORY = join(dirname(realpath(__file__)), GENERATED_OUTPUT_DIRECTORY, 'vulnerabilities/')
GENERATED_OUTPUT_DIRECTORY          = join(dirname(realpath(__file__)), GENERATED_OUTPUT_DIRECTORY)



def create_app():
    print("[+] Flask application started - 127.0.0.1:5000!")
    app = Flask(__name__)
    
    if GENERATE_SECRET_KEY_ON_RESTART == True:
        app.config['SECRET_KEY'] = generateSafeSecret() # Generates safe UUID4 secret key, looks like: `3d6f45a5fc12445dbac2f59c3b6c7cb1`.
    else:
        app.config['SECRET_KEY'] = SECRET_KEY

    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}' # Connection string to our database.
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True            # A configuration to enable or disable tracking modifications of objects. You set it to False to disable tracking and use less memory.
    db.init_app(app) # Initialize the app. Obviously.

    log = logging.getLogger('werkzeug')
    log.disabled = GENERAL_LOGGING_DISABLED
    app.logger.disabled = GENERAL_LOGGING_DISABLED
    warnings.filterwarnings("ignore")
    
    def secho(text, file=None, nl=None, err=None, color=None, **styles):
        return
    def echo(text, file=None, nl=None, err=None, color=None, **styles):
        return

    click.echo = echo
    click.secho = secho


    from .views import views
    from .auth import auth
    from .api.debug.views import DEBUG_VIEWS
    from .api.ports.views import PORT_VIEWS
    from .api.subdomains.views import SUBDOMAIN_VIEWS
    from .api.upload.views import UPLOAD_VIEWS
    from .api.vulnerabilities.views import VULNERABILITY_VIEWS

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(DEBUG_VIEWS, url_prefix='/api/debug')
    app.register_blueprint(PORT_VIEWS, url_prefix='/api/ports')
    app.register_blueprint(SUBDOMAIN_VIEWS,url_prefix='/api/subdomains')
    app.register_blueprint(UPLOAD_VIEWS, url_prefix='/api/upload')
    app.register_blueprint(VULNERABILITY_VIEWS, url_prefix='/api/vulnerabilities')

    from .models import User
    
    with app.app_context():
        db.create_all()


    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app


def create_database(app):
    if not path.exists('website/' + DB_NAME):
        db.create_all(app=app)
        print('Created Database!')
