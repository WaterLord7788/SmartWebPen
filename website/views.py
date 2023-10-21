from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, DEBUG_ENABLED, MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, GENERATED_OUTPUT_DIRECTORY, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, PORT_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from flask import Blueprint, request, flash, jsonify, flash, redirect, url_for, redirect
from .check import checkForFolders      # Checking for necessary folders
from .models import User, Scan, Vulnerability, PortScan
from flask_login import login_required, current_user
from flask import Flask, render_template, session
from os.path import join, dirname, realpath
from werkzeug.utils import secure_filename
from .systemFunctions import *
from bs4 import BeautifulSoup
from threading import Thread
from pathlib2 import Path
from .scan import *
import requests
import asyncio
import random
import json
import os


views = Blueprint('views', __name__)


@views.before_app_first_request
def setup():
    print('[!] Setup checking.')
    checkForFolders(
        GENERATED_OUTPUT_DIRECTORY, 
        SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, 
        PORT_SCAN_OUTPUT_DIRECTORY, 
        VULNERABILITY_SCAN_OUTPUT_DIRECTORY)
    print('[+] Setup checking completed!')


@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'GET':           return render_template('home.html', user=current_user, ADMIN=ADMIN)
    if not request.form.get('subdomain'): return render_template('home.html', user=current_user, state="No subdomain", ADMIN=ADMIN)

    domain = request.form.get('subdomain')
    domain = sanitizeInput(domain)
    tools, methods, files, resultFiles, vulnerabilities = [], [], [], [], []

    if request.form.get('useAMASS'):             tools.append('amass')
    if request.form.get('useSubfinder'):         tools.append('subfinder')
    if request.form.get('useGau'):               tools.append('gau')
    if request.form.get('useWaybackurls'):       tools.append('waybackurls')
    if request.form.get('useCrt.sh'):            tools.append('crt.sh')
    if request.form.get('useWaymore'):           tools.append('waymore')
    if request.form.get('useGoSpider'):          tools.append('goSpider')
    if request.form.get('useXLinkFinder'):       tools.append('useXLinkFinder')
    if request.form.get('useCustomWordlistForSubdomains'): 
        methods.append('customWordlistForSubdomains')
        files.append(request.form.get('customWordlistForSubdomains'))
    if request.form.get('useAliveCheck'):        methods.append('checkAliveSubdomains')
    if request.form.get('searchTargetsByASN'):   methods.append('searchTargetsByASN')
    if request.form.get('useScreenshotting'):    methods.append('useScreenshotting')
    if request.form.get('exposedPorts'):         methods.append('checkExposedPorts')
    if request.form.get('vulnerableParameters'): methods.append('checkVulnerableParameters')
    if request.form.get('generateSubdomainWordlist'): methods.append('generateSubdomainWordlist')

    if request.form.get('doVulnerabilityScanning'):
        if request.form.get('CRLF'):                                vulnerabilities.append('CRLF')
        if request.form.get('XSS'):                                 vulnerabilities.append('XSS')
        if request.form.get('SQLi'):                                vulnerabilities.append('SQLi')
        if request.form.get('Nuclei'):                              vulnerabilities.append('Nuclei')
        if request.form.get('useRetireJS'):                         vulnerabilities.append('retireJS')
        if request.form.get('useMantra'):                           vulnerabilities.append('mantra')
        if request.form.get('useCustomWordlistForVulnerabilities'): 
            methods.append('customWordlistForVulnerabilities')
            files.append(request.form.get('customWordlistForVulnerabilities'))
    
    # Convert list to string.
    tools = convertListToString(tools)
    methods = convertListToString(methods)
    files = convertListToString(files)
    resultFiles = convertListToString(resultFiles)
    vulnerabilities = convertListToString(vulnerabilities)
    entryID = str(random.randint(MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION))

    # Create scanning report entry in database.db.
    NEW_SCAN = Scan(url=domain, methods=methods, tools=tools, resultFiles=resultFiles, vulnerabilities=vulnerabilities, entryID=entryID)
    db.session.add(NEW_SCAN)
    saveDB()

    # Start executing commands in scan.py file.
    executeSubdomainEnumeration(domain, tools, methods, files, entryID)

    # Start executing vulnerability scanning, if user decided to do so.
    if request.form.get('doVulnerabilityScanning'):
        NEW_SECURITY_SCAN = Vulnerability(url=domain, resultFiles=resultFiles, vulnerabilities=vulnerabilities, entryID=entryID)
        db.session.add(NEW_SECURITY_SCAN)
        saveDB()

        # Start executing commands in scan.py file.
        executeVulnerabilityScanning(domain, vulnerabilities, files, entryID)
    
    flash(str(f'<b>Scanning started</b> for domain {domain}!'), category='success')
    flash(str(f'The following <b>tools</b> are going to be used: {str(tools)}'), category='info')
    return render_template("base.html", user=current_user, ADMIN=ADMIN, debugEnabled=DEBUG_ENABLED)


@views.route('/ports', methods=['GET', 'POST'])
@login_required
def ports():
    if request.method == 'GET': 
        ports = PortScan.query.all()
        return render_template('ports.html', user=current_user, ports=ports)
        return render_template('ports.html', user=current_user)
    if not request.form.get('domain'): return render_template('ports.html', user=current_user, state="No domain")

    domain = request.form.get('domain')
    domain = sanitizeInput(domain)
    flags, resultFiles = [], []

    if request.form.get('use-sV_flag'): flags.append('-sV')
    if request.form.get('use-Pn_flag'): flags.append('-Pn')
    if request.form.get('use-A_flag'):  flags.append('-A')
    if request.form.get('use-sO_flag'): flags.append('-sO')
    if request.form.get('use-sC_flag'): flags.append('-sC')
    if request.form.get('use--privileged_flag'): flags.append('--privileged')

    if request.form.get('getHTMLReport'): HTMLReport = True
    else: HTMLReport = False

    # Convert list to string.
    flags = convertListToString(flags)
    resultFiles = convertListToString(resultFiles)
    entryID = str(random.randint(MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION))

    # Create scanning report entry in database.db.
    NEW_PORTSCAN = PortScan(url=domain, flags=flags, resultFiles=resultFiles, entryID=entryID)
    db.session.add(NEW_PORTSCAN)
    saveDB()

    # Start executing commands in scan.py file.
    executePortScanning(domain, flags, HTMLReport, entryID)

    flash(str(f'<b>Port scanning started</b> for domain {domain}!'), category='success')
    flash(str(f'The following <b>flags</b> are going to be used: {str(flags)}'), category='info')
    return render_template("base.html", user=current_user, ADMIN=ADMIN, debugEnabled=DEBUG_ENABLED)


@views.route('/subdomains', methods=['GET', 'POST'])
@login_required
def subdomains():
    scans = Scan.query.all()
    return render_template('subdomains.html', user=current_user, scans=scans)


@views.route('/vulnerabilities', methods=['GET', 'POST'])
@login_required
def vulnerabilities():
    vulnerabilities = Vulnerability.query.all()
    return render_template('vulnerabilities.html', user=current_user, vulnerabilities=vulnerabilities)


@views.route('/redirect', methods=['GET'])
def redirectToUrl():
    return render_template('redirect.html', user=current_user)


@views.route('/file', methods=['GET'])
@login_required
def getFile():
    # HTTP GET parameter 'file' would look like in URL: http://127.0.0.1/file?file=subdomains/army.mil-amass-402766.txt
    if not request.args.get('file'):
        flash('No <b>file</b> parameter supplied!', category='error')
        return render_template('file.html', user=current_user)

    file = request.args.get('file')
    filePath = file
    contents = Path(filePath).read_text().replace('\n', '<br>')
    return render_template('file.html', file=file, contents=contents, user=current_user)


@views.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    return render_template("upload.html", state="", user=current_user)