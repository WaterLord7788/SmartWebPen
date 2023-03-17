from flask import Flask, flash, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
from os.path import join, dirname, realpath
import os

db = SQLAlchemy()
DB_NAME = "database.db"
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'doc'}
UPLOAD_FOLDER = join(dirname(realpath(__file__)), 'static/img/')
ADMIN = "kristian.paivinen@yahoo.com"
SIGNUP_ENABLED = True
MIN_NUMER_FILEGENERATOR = 100000
MAX_NUMBER_FILEGENERATION = 999999 # Useful to set higher in order to increase randomness
SUBDOMAIN_SCAN_OUTPUT_DIRECTORY = join(dirname(realpath(__file__)), 'generated/subdomains/')
PORT_SCAN_OUTPUT_DIRECTORY = join(dirname(realpath(__file__)), 'generated/ports/')


if os.path.exists(SUBDOMAIN_SCAN_OUTPUT_DIRECTORY): 
    pass
else: 
    print('[-] No subdomain scan output folder found!')
    print('[*] Creating the necessary folder.')
    os.system('mkdir '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+'')
    print('[+] Folder created!')
if os.path.exists(PORT_SCAN_OUTPUT_DIRECTORY): 
    pass
else: 
    print('[Info] No port scan output folder found!')
    print('[Info] Creating the necessary folder.')
    os.system('mkdir '+PORT_SCAN_OUTPUT_DIRECTORY+'')
    print('[Info] Folder created!')

# Check required dependencies



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

    return app


def create_database(app):
    if not path.exists('website/' + DB_NAME):
        db.create_all(app=app)
        print('Created Database!')
