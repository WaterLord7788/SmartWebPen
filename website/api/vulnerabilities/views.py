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


VULNERABILITY_VIEWS = Blueprint('vulnerability_views', __name__)


@VULNERABILITY_VIEWS.route('/<int:id>/', methods=['GET', 'POST'])
@login_required
def getVulnerabilityScanDetails(id):
    return str('ID: '+str(id)+'')


@VULNERABILITY_VIEWS.route('/delete-vulnerability', methods=['POST'])
@login_required
def deleteVulnerability():
    vulnerability = json.loads(request.data)
    vulnId = vulnerability['vulnId']
    vulnerability = Vulnerability.query.get(vulnId)
    entryID = vulnerability.entryID
    
    cmd = f'rm -r {VULNERABILITY_SCAN_OUTPUT_DIRECTORY}{entryID}/* && rm {VULNERABILITY_SCAN_OUTPUT_DIRECTORY}{entryID}/'
    executeCMD(cmd)

    if vulnerability:
        db.session.delete(vulnerability)
        db.session.commit()
        flash('Vulnerability scan deleted!', category='success')
    return jsonify({})