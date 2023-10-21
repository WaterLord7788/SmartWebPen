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


SUBDOMAIN_VIEWS = Blueprint('subdomain_views', __name__)


@SUBDOMAIN_VIEWS.route('/<int:entryID>/', methods=['GET', 'POST'])
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


@SUBDOMAIN_VIEWS.route('/delete-scan', methods=['POST'])
@login_required
def deleteScan():
    scan = json.loads(request.data)
    scanId = scan['scanId']
    scan = Scan.query.get(scanId)
    entryID = scan.entryID

    cmd = f'rm -r {SUBDOMAIN_SCAN_OUTPUT_DIRECTORY}{entryID}/* && rm {SUBDOMAIN_SCAN_OUTPUT_DIRECTORY}{entryID}/'
    executeCMD(cmd)

    if scan:
        db.session.delete(scan)
        db.session.commit()
        flash('Scan deleted!', category='success')
    return jsonify({})