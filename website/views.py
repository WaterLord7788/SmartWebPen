from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, DEBUG_ENABLED, MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, GENERATED_OUTPUT_DIRECTORY, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, PORT_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from flask import Blueprint, request, flash, jsonify, flash, redirect, url_for, redirect
from .check import checkForFolders      # Checking for necessary folders
from .installation import installTools  # Checking for necessary tools
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
import asyncio # For asynchronous completion of system commands
import random
import json
import os


views = Blueprint('views', __name__)


@views.before_app_first_request
def setup():
    print('[!] Setup checking.')
    checkForFolders(GENERATED_OUTPUT_DIRECTORY, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, PORT_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY)
    installTools()
    print('[+] Setup checking completed!')


@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'GET':           return render_template('home.html', user=current_user, ADMIN=ADMIN)
    if not request.form.get('subdomain'): return render_template('home.html', user=current_user, state="No subdomain", ADMIN=ADMIN)

    # Subdomain sanitization.
    domain = request.form.get('subdomain')
    domain = sanitizeInput(domain)
    # Get the required options.
    tools, methods, files, resultFiles, vulnerabilities = [], [], [], [], []

    if request.form.get('useAMASS'):             tools.append('amass')
    if request.form.get('useSubfinder'):         tools.append('subfinder')
    if request.form.get('useGau'):               tools.append('gau')
    if request.form.get('useWaybackurls'):       tools.append('waybackurls')
    if request.form.get('useCrt.sh'):            tools.append('crt.sh')
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


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@views.route('/upload', methods=['GET', 'POST'])
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


@views.route('/debug', methods=['GET', 'POST'])
@login_required
def debug():
    if DEBUG_ENABLED == False:  return render_template("debug.html", user=current_user, ADMIN=ADMIN, DEBUG_ENABLED=DEBUG_ENABLED)
    if request.method == 'GET': return render_template("debug.html", user=current_user, ADMIN=ADMIN)

    cmd = request.form.get('cmd')
    output = executeCMD(cmd)
    return render_template("debug.html", user=current_user, ADMIN=ADMIN, output=output)
    

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


@views.route('/subdomains/<int:entryID>/', methods=['GET', 'POST'])
@login_required
def getSubdomainScanDetails(entryID):
    subdomainScan = Scan.query.filter_by(entryID=entryID).first()
    if not subdomainScan: 
        flash(str('No scan with id of <b>'+str(entryID)+'</b> found!'), category='error')
        return render_template('id.subdomains.html', user=current_user)
        
    resultFiles = subdomainScan.resultFiles
    if len(resultFiles) < 4:
        flash(str('No resulting files of scan with id of <b>'+str(entryID)+'</b> found!'), category='error')
        flash('You might need to wait for the scan to finish.', category='info')
        return render_template('id.subdomains.html', user=current_user)
    
    # Real work starts here.
    # Code below fetches all the resulting files from the scan,
    # and outputs the results into an HTML box in `id.subdomains.html` file.
    resultFiles = resultFiles.split(' ')
    resultFiles.pop(0)
    files = {}

    for resultFile in resultFiles:
        file = ''
        print(resultFile)
        if '/subdomains/' in resultFile:     # If file is in subdomains/ folder.
            with open(resultFile, 'r') as f:
                for line in f:
                    line = line.strip()
                    line = '<a/href="../../redirect?url='+line+'"/target="_blank">'+line+'</a>'
                    line += '<br>'
                    file += line
            files[resultFile] = file
        elif 'waybackurls+' in resultFile:  # If file has more than just subdomains.
            with open(resultFile, 'r') as f:
                for line in f:
                    line = line.strip()
                    line += '<br>'
                    file += line
            files[resultFile] = file

    return render_template('id.subdomains.html', files=files, user=current_user)


@views.route('/ports/<int:id>/', methods=['GET', 'POST'])
@login_required
def getPortScanDetails(id):
    return str('ID: '+str(id)+'')


@views.route('/vulnerabilities/<int:id>/', methods=['GET', 'POST'])
@login_required
def getVulnerabilityScanDetails(id):
    return str('ID: '+str(id)+'')


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


@views.route('/delete-scan', methods=['POST'])
@login_required
def deleteScan():
    scan = json.loads(request.data)
    scanId = scan['scanId']
    scan = Scan.query.get(scanId)
    resultFiles = scan.resultFiles.split(' ')
    for resultFile in resultFiles:
        if len(resultFile) != 0:
            # If there are no files, we just ignore the error, hence we use try...except clause.
            try: os.remove(resultFile)
            except: pass
            # `os.rmdir` deletes only empty folder, so we need to do this every time after we delete a file.
            try: os.rmdir(os.path.dirname(resultFile))
            except: pass
    if scan:
        db.session.delete(scan)
        db.session.commit()
        flash('Scan deleted!', category='success')
    return jsonify({})


@views.route('/delete-vulnerability', methods=['POST'])
@login_required
def deleteVulnerability():
    vulnerability = json.loads(request.data)
    vulnId = vulnerability['vulnId']
    vulnerability = Vulnerability.query.get(vulnId)
    resultFiles = vulnerability.resultFiles.split(' ')
    for resultFile in resultFiles:
        if len(resultFile) != 0:
            # If there are no files, we just ignore the error, hence we use try...except clause.
            try: s.remove(resultFile)
            except: pass
            # `os.rmdir` deletes only empty folder, so we need to do this every time after we delete a file.
            try: os.rmdir(os.path.dirname(resultFile))
            except: pass
    if vulnerability:
        db.session.delete(vulnerability)
        db.session.commit()
        flash('Vulnerability scan deleted!', category='success')
    return jsonify({})


@views.route('/delete-port', methods=['POST'])
@login_required
def deletePortScan():
    portscan = json.loads(request.data)
    portId = portscan['portId']
    portscan = PortScan.query.get(portId)
    resultFiles = portscan.resultFiles.split(' ')
    for resultFile in resultFiles:
        if len(resultFile) != 0:
            # If there are no files, we just ignore the error, hence we use try...except clause.
            try: s.remove(resultFile)
            except: pass
            # `os.rmdir` deletes only empty folder, so we need to do this every time after we delete a file.
            try: os.rmdir(os.path.dirname(resultFile))
            except: pass
    if portscan:
        db.session.delete(portscan)
        db.session.commit()
        flash('Port scan deleted!', category='success')
    return jsonify({})