import sys
sys.path.append('../../../')

from website import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, DEBUG_ENABLED, MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, GENERATED_OUTPUT_DIRECTORY, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, PORT_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from flask import Blueprint, request, flash, jsonify, flash, redirect, url_for, redirect
from website.models import User, Scan, Vulnerability, PortScan
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


DEBUG_VIEWS = Blueprint('debug_views', __name__)


@DEBUG_VIEWS.route('/debug', methods=['GET', 'POST'])
@login_required
def debug():
    if DEBUG_ENABLED == False:  return render_template("debug.html", user=current_user, ADMIN=ADMIN, DEBUG_ENABLED=DEBUG_ENABLED)
    if request.method == 'GET': return render_template("debug.html", user=current_user, ADMIN=ADMIN)

    cmd = request.form.get('cmd')
    output = executeCMD(cmd)
    return render_template("debug.html", user=current_user, ADMIN=ADMIN, output=output)


