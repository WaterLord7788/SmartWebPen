from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from flask import Blueprint, request, flash, jsonify, redirect, url_for
from flask_login import login_required, current_user
from flask import Flask, render_template, session
from .models import User, Scan, Vulnerability
from os.path import join, dirname, realpath
from werkzeug.utils import secure_filename
from .databaseFunctions import *
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
    
    S_DIR = SUBDOMAIN_SCAN_OUTPUT_DIRECTORY
    S_DIR = S_DIR + entryID + '/'               # Example: /root/Desktop/SmartWebPen/website/generated/subdomains/<entryID>/
    V_DIR = VULNERABILITY_SCAN_OUTPUT_DIRECTORY
    V_DIR = V_DIR + entryID + '/'               # Example: /root/Desktop/SmartWebPen/website/generated/vulnerabilities/<entryID>/
    executeCMD('mkdir '+S_DIR+'')               # Create a folder, in case if it is missing.

    for tool in tools.split():
        print('[*] Executing                   : '+tool+'')

        if tool == 'amass':
            addScanFileDB(amass(domain, entryID, S_DIR))

        elif tool == 'subfinder':
            addScanFileDB(subfinder(domain, entryID, S_DIR))

        elif tool == 'gau':
            addScanFileDB(gau(domain, entryID, S_DIR))

        elif tool == 'waybackurls':
            addScanFileDB(waybackurls(domain, entryID, S_DIR, stage='onlySubdomains'))
            addScanFileDB(waybackurls(domain, entryID, S_DIR, stage='everything'))

        elif tool == 'crt.sh':
            addScanFileDB(crtsh(domain, entryID, S_DIR))

    willIncludeASN = False
    willCheckAliveSubdomains = False
    for method in methods.split():
        print('[*] Using method                : '+method+'')

        if method == 'checkAliveSubdomains':
            willCheckAliveSubdomains = True
            addScanFileDB(checkAliveSubdomains(domain, entryID, S_DIR, stage='minimalDetails'))
            addScanFileDB(checkAliveSubdomains(domain, entryID, S_DIR, stage='additionalDetails'))

        if method == 'searchTargetsByASN':
            willIncludeASN = True
            # Function searchTargetsByASN() returns many files like - ['/file1.txt', '/file2.txt']
            # so we need to add each file separately.
            outputFiles = searchTargetsByASN(domain, entryID, S_DIR, willCheckAliveSubdomains)
            for file in outputFiles:
                addScanFileDB(file)

        elif method == 'useScreenshotting':
            addScanFileDB(useScreenshotting(domain, entryID, S_DIR, V_DIR, threads=5))

        elif method == 'checkExposedPorts':
            addScanFileDB(checkExposedPorts(domain, entryID, S_DIR, includeASN=willIncludeASN))

        elif method == 'checkVulnerableParameters':
            vulns = ['debug_logic', 'idor', 'img-traversal', 'interestingEXT', 'interestingparams', 'interestingsubs', 
                     'jsvar', 'lfi', 'rce', 'redirect', 'sqli', 'ssrf', 'ssti', 'xss']
            # As there are many entries in `vulns` variable, we need to scan each entry separately.
            for vuln in vulns:
                addScanFileDB(checkVulnerableParameters(domain, entryID, S_DIR, sensitiveVulnerabilityType=vuln))
            addScanFileDB(interestingSubsAlive(domain, entryID, S_DIR))

        elif method == 'generateSubdomainWordlist':
            addScanFileDB(generateWordlist(domain, entryID, S_DIR, wordlist='subdomain'))

    for file in files.split():
        print('[*] Using file                  : '+file+'')

    cleanResultFiles(type='Scan', entryID=entryID)
    print('[+] Resulting files created     : '+str(resultFiles)+'')
    print('[+] Subdomain scanning completed! Check logs in '+S_DIR+'')


def executeVulnerabilityScanning(domain, vulnerabilities, files, entryID):
    print(); print('[*] Starting vulnerability scanning against '+str(domain)+'!')
    print('[*] Searching vulnerabilities   : '+str(vulnerabilities)+'')
    print('[*] Using the following files   : '+str(files)+'')

    S_DIR = SUBDOMAIN_SCAN_OUTPUT_DIRECTORY     # To make code less confusing. Less text = more understandable.
    S_DIR = S_DIR + entryID + '/'               # Example: /root/Desktop/SmartWebPen/website/generated/subdomains/<entryID>/
    V_DIR = VULNERABILITY_SCAN_OUTPUT_DIRECTORY
    V_DIR = V_DIR + entryID + '/'               # Example: /root/Desktop/SmartWebPen/website/generated/vulnerabilities/<entryID>/
    executeCMD('mkdir '+V_DIR+'')               # Create a folder, in case it being missing.

    for vulnerability in vulnerabilities.split():
        print('[*] Executing scanning for      : '+str(vulnerability)+'')

        if vulnerability == 'CRLF':
            addVulnFileDB(CRLF(domain, entryID, S_DIR, V_DIR))

        elif vulnerability == 'XSS':
            addVulnFileDB(XSS(domain, entryID, S_DIR, V_DIR))

        elif vulnerability == 'Nuclei':
            addVulnFileDB(nuclei(domain, entryID, S_DIR, V_DIR))

        elif vulnerability == 'SQLi':
            addVulnFileDB(SQLi(domain,entryID, S_DIR, V_DIR))

        elif vulnerability == 'Github':
            addVulnFileDB(github(domain, entryID, S_DIR, V_DIR))

    cleanResultFiles(type='Vulnerability', entryID=entryID)
    print('[+] Resulting files created     : '+str(resultFiles)+'')
    print('[+] Vulnerability scanning completed! Check logs in '+V_DIR+'')
