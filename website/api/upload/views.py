import sys
sys.path.append('../../../')

from website import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, DEBUG_ENABLED, MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, GENERATED_OUTPUT_DIRECTORY, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, PORT_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from flask import Blueprint, request, flash, jsonify, flash, redirect, url_for, redirect
from flask_login import login_required, current_user
from flask import Flask, render_template, session
from os.path import join, dirname, realpath
from werkzeug.utils import secure_filename
from website.systemFunctions import *
from bs4 import BeautifulSoup
from threading import Thread
from pathlib2 import Path
from website.scan import *
import requests
import asyncio
import random
import json
import os


UPLOAD_VIEWS = Blueprint('upload_views', __name__)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@UPLOAD_VIEWS.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'GET':     return render_template("upload.html", state="", user=current_user)
    if 'file' not in request.files: return render_template("upload.html", state="No file part", user=current_user)

    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        return render_template("upload.html", state="Successful upload", file=file, user=current_user)
    else:
        return render_template("upload.html", state="Forbidden extension", user=current_user)


