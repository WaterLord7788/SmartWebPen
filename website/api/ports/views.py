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


PORT_VIEWS = Blueprint('port_views', __name__)


@PORT_VIEWS.route('/<int:id>/', methods=['GET', 'POST'])
@login_required
def getPortScanDetails(id):
    return str('ID: '+str(id)+'')


@PORT_VIEWS.route('/delete-port', methods=['POST'])
@login_required
def deletePortScan():
    portscan = json.loads(request.data)
    portId = portscan['portId']
    portscan = PortScan.query.get(portId)
    entryID = portscan.entryID
    
    cmd = f'rm -r {PORT_SCAN_OUTPUT_DIRECTORY}{entryID}/* && rm -rf {PORT_SCAN_OUTPUT_DIRECTORY}{entryID}/'
    executeCMD(cmd)

    if portscan:
        db.session.delete(portscan)
        db.session.commit()
        flash('Port scan deleted!', category='success')
    return jsonify({})