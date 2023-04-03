from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, MIN_NUMER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, GENERATED_OUTPUT_DIRECTORY, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, PORT_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from flask import Blueprint, request, flash, jsonify, flash, redirect, url_for
from .check import checkForFolders      # Checking for necessary folders
from .installation import installTools  # Checking for necessary tools
import asyncio                          # For asynchronous completion of os.system() commands
from .models import User, Scan
from flask_login import login_required, current_user
from flask import Flask, render_template, session
from os.path import join, dirname, realpath
from werkzeug.utils import secure_filename
from bs4 import BeautifulSoup
from threading import Thread
from .scan import *
import requests
import random
import json
import os


views = Blueprint('views', __name__)


@views.before_app_first_request
def setup():
    checkForFolders(GENERATED_OUTPUT_DIRECTORY, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, PORT_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY)
    installTools()


@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        if request.form.get('subdomain'):
            # Subdomain sanitization
            domain = request.form.get('subdomain')
            domain = domain.replace('/', '').replace('\\', '').replace('http', '').replace('https', '').replace(':', '').replace(' ', '')
            # Get the required options
            tools, methods, files, vulnerabilities = [], [], [], []

            if request.form.get('useAMASS'):             tools.append('amass')
            if request.form.get('useSubfinder'):         tools.append('subfinder')
            if request.form.get('useGau'):               tools.append('gau')
            if request.form.get('useWaybackurls'):       tools.append('waybackurls')
            if request.form.get('useCrt.sh'):            tools.append('crt.sh')
            if request.form.get('useCustomWordlistForSubdomains'): 
                methods.append('customWordlistForSubdomains')
                files.append(request.form.get('customWordlistForSubdomains'))
            if request.form.get('useAliveCheck'):        methods.append('checkAliveSubdomains')
            if request.form.get('useScreenshotting'):    methods.append('useScreenshotting')
            if request.form.get('exposedPorts'):         methods.append('checkExposedPorts')
            if request.form.get('vulnerableParameters'): methods.append('checkVulnerableParameters')

            if request.form.get('doVulnerabilityScanning'):
                if request.form.get('CRLF'):                                vulnerabilities.append('CRLF')
                if request.form.get('XSS'):                                 vulnerabilities.append('XSS')
                if request.form.get('SQLi'):                                vulnerabilities.append('SQLi')
                if request.form.get('Nuclei'):                              vulnerabilities.append('Nuclei')
                if request.form.get('useCustomWordlistForVulnerabilities'): 
                    methods.append('customWordlistForVulnerabilities')
                    files.append(request.form.get('customWordlistForVulnerabilities'))
            
            # Convert list to string.
            tools = str(tools).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
            methods = str(methods).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
            files = str(files).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
            vulnerabilities = str(vulnerabilities).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
            entryID = str(random.randint(MIN_NUMER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION))

            # Create scanning report entry in database.db.
            new_scan = Scan(url=domain, methods=methods, tools=tools, files=files, vulnerabilities=vulnerabilities, entryID=entryID)
            db.session.add(new_scan)
            db.session.commit()

            # Start executing commands in scan.py file.
            executeSubdomainEnumeration(domain, tools, methods, files, entryID)

            # Start executing vulnerability scanning, if user decided to do so.
            if request.form.get('doVulnerabilityScanning'):
                executeVulnerabilityScanning(domain, vulnerabilities, files, entryID)
            
            flash(str('<b>Scanning started</b> for domain '+request.form.get('subdomain')+'!'), category='success')
            flash(str('The following <b>tools</b> are going to be used: '+str(tools)+''), category='info')
            #flash(str('Something went <b>wrong</b>! Try again..'), category='error')

        else:
            return render_template('home.html', user=current_user, state="No subdomain")
    return render_template('home.html', user=current_user)


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
    scans = Scan.query.all()
    return render_template('subdomains.html', user=current_user, scans=scans)


@views.route('/vulnerabilities', methods=['GET', 'POST'])
@login_required
def vulnerabilities():
    vulnerabilities = Vulnerabilities.query.all()
    if request.method == 'POST':
        if request.form.get('subdomain'):
            # Subdomain sanitization
            domain = request.form.get('subdomain')
            domain = domain.replace('/', '').replace('\\', '').replace('http', '').replace('https', '').replace(':', '').replace(' ', '')
            
            # Get the required options
            tools, methods, files = [], [], []
            if request.form.get('CRLF'):          tools.append('CRLF')
            if request.form.get('XSS'):      tools.append('XSS')
            if request.form.get('SQLi'):    tools.append('SQLi')
            if request.form.get('Nuclei'):         tools.append('Nuclei')
            if request.form.get('useCustomWordlist'): methods.append('customWordlist'); files.append(request.form.get('customWordlist'))
            flash(str('<b>Vulnerability scanning started</b> for domain '+request.form.get('subdomain')+'!'), category='success')
            flash(str('The following <b>vulnerabilities</b> are going to be tested for: '+str(tools)+''), category='info')

            # Convert list to string
            tools = str(tools).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
            methods = str(methods).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
            files = str(files).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
            entryID = str(random.randint(MIN_NUMER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION))

            # Create vulnerability scan report entry in database.db
            new_vulnerability = Vulnerabilities(url=domain, methods=methods, tools=tools, files=files, entryID=entryID)
            db.session.add(new_vulnerability)
            db.session.commit()

            # Start executing commands in scan.py file
            executeVulnerabilityScanning(domain, tools, methods, files, entryID)
        else:
            return render_template('vulnerabilities.html', user=current_user, state="No subdomain", vulnerabilities=vulnerabilities)
    return render_template('vulnerabilities.html', user=current_user, vulnerabilities=vulnerabilities)



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

@views.route('/vulnerabilities/<int:id>/', methods=['GET', 'POST'])
@login_required
def getVulnerabilityScanDetails(id):
    return str('ID: '+str(id)+'')