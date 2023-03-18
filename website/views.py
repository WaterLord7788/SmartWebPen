from flask import Blueprint, request, flash, jsonify, flash, redirect, url_for
from flask import Flask, render_template, session
from flask_login import login_required, current_user
from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, MIN_NUMER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY
from werkzeug.utils import secure_filename
from os.path import join, dirname, realpath
from .models import User, Subdomains
from bs4 import BeautifulSoup
from .scan import *
import requests
import asyncio # For asynchronous completion of os.system() commands
import random
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


@views.route('/subdomains', methods=['GET', 'POST'])
@login_required
def subdomains():
    subdomains = Subdomains.query.all()
    if request.method == 'POST':
        if request.form.get('subdomain'):
            # Subdomain sanitization
            domain = request.form.get('subdomain')
            domain = domain.replace('/', '').replace('\\', '').replace('http', '').replace('https', '').replace(':', '').replace(' ', '')
            
            # Get the required options
            tools, methods, files = [], [], []
            if request.form.get('useAMASS'):          tools.append('amass')
            if request.form.get('useSubfinder'):      tools.append('subfinder')
            #if request.form.get('useGau'):            tools.append('gau')
            if request.form.get('useWaybackurls'):    tools.append('waybackurls')
            if request.form.get('useCrt.sh'):         tools.append('crt.sh')
            if request.form.get('useCustomWordlist'): methods.append('customWordlist'); files.append(request.form.get('customWordlist'))
            if request.form.get('useAliveCheck'):     methods.append('checkAliveSubdomains')
            if request.form.get('useScreenshotting'): methods.append('useScreenshotting')
            flash(str('<b>Enumeration started</b> for domain '+request.form.get('subdomain')+'!'), category='success')
            flash(str('The the following <b>tools</b> are going to be used: '+str(tools)+''), category='info')

            # Convert list to string
            tools = str(tools).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
            methods = str(methods).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
            files = str(files).replace('[', '').replace(']', '').replace(',', '').replace("'", '')

            # Create subdomains report entry in database.db
            new_subdomain = Subdomains(url=domain, methods=methods, tools=tools, files=files)
            db.session.add(new_subdomain)
            db.session.commit()

            # Start executing commands in scan.py file
            asyncio.run(intializeEnumeration(domain, tools, methods, files))
        else:
            return render_template('subdomains.html', user=current_user, state="No subdomain", subdomains=subdomains)
    return render_template('subdomains.html', user=current_user, subdomains=subdomains)


@views.route('/vulnerabilities', methods=['GET', 'POST'])
@login_required
def vulnerabilities():
    #subdomains = Subdomains.query.all()
    if request.method == 'POST':
        if request.form.get('subdomain'):
            pass
        else:
            #return render_template('subdomains.html', user=current_user, state="No subdomain", subdomains=subdomains)
            pass
    return render_template('vulnerabilities.html', user=current_user)#, vulnerabilities=vulnerabilities)


@views.route('/ports', methods=['GET', 'POST'])
@login_required
def ports():
    if request.method == 'POST':
        if request.form.get('domain'):
            pass
        else:
            return render_template('ports.html', user=current_user, state="No domain")
    return render_template('ports.html', user=current_user)


@views.route('/subdomains/<int:id>/', methods=['GET', 'POST'])
@login_required
def getSubdomainScanDetails(id):
    return str('ID: '+str(id)+'')

@views.route('/ports/<int:id>/', methods=['GET', 'POST'])
@login_required
def getPortScanDetails(id):
    return str('ID: '+str(id)+'')