from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, DEBUG_ENABLED, MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, GENERATED_OUTPUT_DIRECTORY, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, PORT_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from flask import Blueprint, request, flash, jsonify, flash, redirect, url_for, redirect
from .check import checkForFolders      # Checking for necessary folders
from .installation import installTools  # Checking for necessary tools
from .models import User, Scan, Vulnerability
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
    if request.method == 'GET':           return render_template('home.html', user=current_user)
    if not request.form.get('subdomain'): return render_template('home.html', user=current_user, state="No subdomain")

    # Subdomain sanitization
    domain = request.form.get('subdomain')
    domain = domain.replace('/', '').replace('\\', '').replace('http', '').replace('https', '').replace(':', '').replace(' ', '')
    # Get the required options
    tools, methods, files, resultFiles, vulnerabilities = [], [], [], [], []

    if request.form.get('useAMASS'):             tools.append('amass')
    if request.form.get('useSubfinder'):         tools.append('subfinder')
    if request.form.get('useGau'):               tools.append('gau')
    if request.form.get('useWaybackurls'):       tools.append('waybackurls')
    if request.form.get('useCrt.sh'):            tools.append('crt.sh')
    if request.form.get('useCustomWordlistForSubdomains'): 
        methods.append('customWordlistForSubdomains')
        files.append(request.form.get('customWordlistForSubdomains'))
    if request.form.get('searchTargetsByASN'):   methods.append('searchTargetsByASN')
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
    resultFiles = str(resultFiles).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
    vulnerabilities = str(vulnerabilities).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
    entryID = str(random.randint(MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION))

    # Create scanning report entry in database.db.
    NEW_SCAN = Scan(url=domain, methods=methods, tools=tools, resultFiles=resultFiles, vulnerabilities=vulnerabilities, entryID=entryID)
    db.session.add(NEW_SCAN)
    db.session.commit()

    # Start executing commands in scan.py file.
    executeSubdomainEnumeration(domain, tools, methods, files, entryID)

    # Start executing vulnerability scanning, if user decided to do so.
    if request.form.get('doVulnerabilityScanning'):
        NEW_SECURITY_SCAN = Vulnerability(url=domain, resultFiles=resultFiles, vulnerabilities=vulnerabilities, entryID=entryID)
        db.session.add(NEW_SECURITY_SCAN)
        db.session.commit()

        # Start executing commands in scan.py file.
        executeVulnerabilityScanning(domain, vulnerabilities, files, entryID)
    
    flash(str('<b>Scanning started</b> for domain '+request.form.get('subdomain')+'!'), category='success')
    flash(str('The following <b>tools</b> are going to be used: '+str(tools)+''), category='info')
    
    #flash(str('Something went <b>wrong</b>! Try again..'), category='error')


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
    if DEBUG_ENABLED == False:  return render_template("debug.html", user=current_user, ADMIN=ADMIN)
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
    if request.method == 'GET': return render_template('ports.html', user=current_user)

    if request.form.get('domain'):
        pass
    else:
        return render_template('ports.html', user=current_user, state="No domain")


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
    else:
        # Real work starts here.
        # Code below fetches all the resulting files from the scan,
        # and outputs the results into an HTML box in id.subdomains.html file.
        resultFiles = resultFiles.split(' ')
        resultFiles.pop(0)
        files = {}

        for resultFile in resultFiles:
            file = ''
            print(resultFile)
            if 'subdomains/' in resultFile:     # If file is in subdomains/ folder.
                with open(resultFile) as f:
                    for line in f:
                        line = line.strip()
                        line = '<a/href="../../redirect?url='+line+'"/target="_blank">'+line+'</a>'
                        line += '<br>'
                        file += line
                files[resultFile] = file
            elif 'waybackurls+' in resultFile:  # If file has more than just subdomains.
                with open(resultFile) as f:
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
    scan = json.loads(request.data) # This function expects a JSON from the INDEX.js file.
    scanId = scan['scanId']
    scan = Scan.query.get(scanId)
    resultFiles = scan.resultFiles.split(' ')
    for resultFile in resultFiles:
        if len(resultFile) != 0:
            # If there is no files, we just ignore the error, hence we use try...except clause.
            try:
                os.remove(resultFile)
            except:
                pass

            # `os.rmdir` deletes only empty folder, so we need to do this every time we delete a file.
            try:
                os.rmdir(os.path.dirname(resultFile))
            except:
                pass
    if scan:
        db.session.delete(scan)
        db.session.commit()
        flash('Scan deleted!', category='success')
    return jsonify({})