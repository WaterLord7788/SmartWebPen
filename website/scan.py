from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from flask import Blueprint, request, flash, jsonify, redirect, url_for
from flask_login import login_required, current_user
from flask import Flask, render_template, session
from .models import User, Scan, Vulnerability
from os.path import join, dirname, realpath
from werkzeug.utils import secure_filename
from bs4 import BeautifulSoup
from .scanFunctions import *
import requests
import asyncio
import random
import json


def executeSubdomainEnumeration(domain, tools, methods, files, entryID=str(random.randint(MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION))):
    print(); print('[+] Starting subdomain enumeration against '+str(domain)+'!')
    print('[*] Using the following tools   : '+str(tools)+'')
    print('[*] Using the following methods : '+str(methods)+'')
    print('[*] Using the following files   : '+str(files)+'')
    
    resultFiles = []
    S_DIR = SUBDOMAIN_SCAN_OUTPUT_DIRECTORY
    S_DIR = S_DIR + entryID + '/'               # Example: /root/Desktop/SmartWebPen/website/generated/subdomains/<entryID>/
    V_DIR = VULNERABILITY_SCAN_OUTPUT_DIRECTORY
    V_DIR = V_DIR + entryID + '/'               # Example: /root/Desktop/SmartWebPen/website/generated/vulnerabilities/<entryID>/
    executeCMD('mkdir '+S_DIR+'')               # Create a folder, in case if it is missing.

    for tool in tools.split():
        print('[*] Executing                   : '+tool+'')

        if tool == 'amass':
            resultFiles.append(amass(domain, entryID, S_DIR))

        elif tool == 'subfinder':
            resultFiles.append(subfinder(domain, entryID, S_DIR))

        elif tool == 'gau':
            resultFiles.append(gau(domain, entryID, S_DIR))

        elif tool == 'waybackurls':
            resultFiles.append(waybackurls(domain, entryID, S_DIR, stage='onlySubdomains'))
            resultFiles.append(waybackurls(domain, entryID, S_DIR, stage='everything'))

        elif tool == 'crt.sh':
            resultFiles.append(crtsh(domain, entryID, S_DIR))

    willIncludeASN = False
    willCheckAliveSubdomains = False
    for method in methods.split():
        print('[*] Using method                : '+method+'')

        if method == 'checkAliveSubdomains':
            willCheckAliveSubdomains = True
            resultFiles.append(checkAliveSubdomains(domain, entryID, S_DIR, stage='minimalDetails'))
            resultFiles.append(checkAliveSubdomains(domain, entryID, S_DIR, stage='additionalDetails'))

        if method == 'searchTargetsByASN':
            willIncludeASN = True
            # Function searchTargetsByASN() returns many files like - ['/file1.txt', '/file2.txt']
            # so we need to add each file separately.
            outputFiles = searchTargetsByASN(domain, entryID, S_DIR, checkAliveSubdomains=willCheckAliveSubdomains)
            for file in outputFiles:
                resultFiles.append(file)

        elif method == 'useScreenshotting':
            resultFiles.append(useScreenshotting(domain, entryID, S_DIR, V_DIR, threads=5))

        elif method == 'checkExposedPorts':
            resultFiles.append(checkExposedPorts(domain, entryID, S_DIR, includeASN=willIncludeASN))

        elif method == 'checkVulnerableParameters':
            vulns = ['debug_logic', 'idor', 'img-traversal', 'interestingEXT', 'interestingparams', 'interestingsubs', 
                     'jsvar', 'lfi', 'rce', 'redirect', 'sqli', 'ssrf', 'ssti', 'xss']
            for vuln in vulns:
                resultFiles.append(checkVulnerableParameters(domain, entryID, S_DIR, sensitiveVulnerabilityType=vuln))

            resultFiles.append(interestingSubsAlive(domain, entryID, S_DIR))

    for file in files.split():
        print('[*] Using file                  : '+file+'')

    print('[+] Resulting files created     : '+str(resultFiles)+'')
    resultFiles = str(resultFiles).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
    Scan.query.filter_by(entryID=entryID).first().resultFiles = str(Scan.query.filter_by(entryID=entryID).first().resultFiles) + ' ' + str(resultFiles)
    db.session.commit()
    print('[+] Subdomain scanning completed! Check logs in '+S_DIR+'')


def executeVulnerabilityScanning(domain, vulnerabilities, files, entryID):
    print(); print('[*] Starting vulnerability scanning against '+str(domain)+'!')
    print('[*] Searching vulnerabilities   : '+str(vulnerabilities)+'')
    print('[*] Using the following files   : '+str(files)+'')

    resultFiles = []
    S_DIR = SUBDOMAIN_SCAN_OUTPUT_DIRECTORY     # To make code less confusing. Less text = more understandable.
    S_DIR = S_DIR + entryID + '/'               # Example: /root/Desktop/SmartWebPen/website/generated/subdomains/<entryID>/
    V_DIR = VULNERABILITY_SCAN_OUTPUT_DIRECTORY
    V_DIR = V_DIR + entryID + '/'               # Example: /root/Desktop/SmartWebPen/website/generated/vulnerabilities/<entryID>/
    executeCMD('mkdir '+V_DIR+'')               # Create a folder, in case it being missing.

    for vulnerability in vulnerabilities.split():
        print('[*] Executing scanning for      : '+str(vulnerability)+'')

        if vulnerability == 'CRLF':
            resultFiles.append(CRLF(domain, entryID, S_DIR, V_DIR))

        elif vulnerability == 'XSS':
            resultFiles.append(XSS(domain, entryID, S_DIR, V_DIR))

        elif vulnerability == 'Nuclei':
            resultFiles.append(nuclei(domain, entryID, S_DIR, V_DIR))

        elif vulnerability == 'SQLi':
            resultFiles.append(SQLi(domain,entryID, S_DIR, V_DIR))

        elif vulnerability == 'Github':
            resultFiles.append(github(domain, entryID, S_DIR, V_DIR))

    print('[+] Resulting files created     : '+str(resultFiles)+'')
    resultFiles = str(resultFiles).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
    Vulnerability.query.filter_by(entryID=entryID).first().resultFiles = str(Vulnerability.query.filter_by(entryID=entryID).first().resultFiles) + ' ' + str(resultFiles)
    db.session.commit()
    print('[+] Vulnerability scanning completed! Check logs in '+V_DIR+'')
