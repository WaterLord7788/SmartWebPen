from flask import Blueprint, request, flash, jsonify, flash, redirect, url_for
from flask import Flask, render_template, session
from flask_login import login_required, current_user
from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN
from werkzeug.utils import secure_filename
from os.path import join, dirname, realpath
from .models import User
from bs4 import BeautifulSoup
import requests
import json
import os

views = Blueprint('views', __name__)


@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    return render_template("home.html", user=current_user, ADMIN=ADMIN)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@views.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return render_template("upload.html", state="No file part")
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            return render_template("upload.html", state="Successful upload", file=file)
        else:
            return render_template("upload.html", state="Forbidden extension")
    return render_template("upload.html", state="")


@views.route('/debug', methods=['GET', 'POST'])
@login_required
def debug():
    if request.method == 'POST' and current_user.email == ADMIN:
        cmd = request.form.get('cmd')
        execute = os.popen(cmd)
        output = execute.read()
        execute.close()
        return render_template("debug.html", user=current_user, ADMIN=ADMIN, output=output)
    return render_template("debug.html", user=current_user, ADMIN=ADMIN)


"""
@views.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.args.get("edit") == "true":
        return render_template('profile.html', user=current_user, state="Profile edit")
    elif request.method == 'POST':
        if request.form.get('description'):
            new_description = request.form.get('description')
            current_user.description = new_description
        if request.form.get('phone'):
            new_phone = request.form.get('phone')
            current_user.phone = new_phone
        db.session.commit()
        flash('Profile updated!', category='success')
    return render_template('profile.html', user=current_user)
"""

@views.route('/subdomains', methods=['GET', 'POST'])
@login_required
def subdomains():
    if request.method == 'POST':
        if request.form.get('subdomain'):
            pass
        else:
            return render_template('subdomains.html', user=current_user, state="No subdomain")
    return render_template('subdomains.html', user=current_user)