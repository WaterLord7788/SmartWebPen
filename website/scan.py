from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY, SCREENSHOT_DELAY_SECONDS
from . import SCREENSHOT_DELAY_SECONDS, PING_COUNT_NUMBER, GOSPIDER_DEPTH_NUMBER, AMASS_TIMEOUT_MINUTES, WAYMORE_TIMEOUT_MINUTES
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


willRunWaymore = False
willIncludeASN = False
willCheckAliveSubdomains = False


def executeSubdomainEnumeration(domain, tools, methods, files, entryID=str(random.randint(MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION))):
    print(); print(f'[+] Starting subdomain enumeration against {str(domain)}!')
    print(f'[*] Using the following tools   : {str(tools)}')
    print(f'[*] Using the following methods : {str(methods)}')
    print(f'[*] Using the following files   : {str(files)}')
    
    S_DIR = SUBDOMAIN_SCAN_OUTPUT_DIRECTORY
    S_DIR = S_DIR + entryID + '/'               # Example: /root/Desktop/SmartWebPen/website/generated/subdomains/<entryID>/
    V_DIR = VULNERABILITY_SCAN_OUTPUT_DIRECTORY
    V_DIR = V_DIR + entryID + '/'               # Example: /root/Desktop/SmartWebPen/website/generated/vulnerabilities/<entryID>/
    executeCMD(f'mkdir {S_DIR}')                # Create a folder, in case if it is missing.

    for tool in tools.split():
        print(f'[*] Executing                   : {tool}')

        if tool == 'amass':
            addScanFileDB(entryID, amass(domain, entryID, S_DIR, timeout=AMASS_TIMEOUT_MINUTES))

        elif tool == 'subfinder':
            addScanFileDB(entryID, subfinder(domain, entryID, S_DIR))

        elif tool == 'gau':
            addScanFileDB(entryID, gau(domain, entryID, S_DIR))

        elif tool == 'waybackurls':
            addScanFileDB(entryID, waybackurls(domain, entryID, S_DIR, stage='onlySubdomains'))
            addScanFileDB(entryID, waybackurls(domain, entryID, S_DIR, stage='everything'))

        elif tool == 'crt.sh':
            addScanFileDB(entryID, crtsh(domain, entryID, S_DIR))

        elif tool == 'waymore':
            willRunWaymore = True
            outputFiles = waymore(domain, entryID, S_DIR, timeout=WAYMORE_TIMEOUT_MINUTES)
            for file in outputFiles:
                addScanFileDB(entryID, file)
        
        elif tool == 'goSpider':
            addScanFileDB(entryID, gospider(domain, entryID, S_DIR, depth=GOSPIDER_DEPTH_NUMBER))

        elif tool == 'xLinkFinder':
            addScanFileDB(entryID, xLinkFinder(domain, entryID, S_DIR))

    for method in methods.split():
        print(f'[*] Using method                : {method}')

        if method == 'checkAliveSubdomains':
            willCheckAliveSubdomains = True
            addScanFileDB(entryID, checkAliveSubdomains(domain, entryID, S_DIR, moreDetails=False))
            addScanFileDB(entryID, checkAliveSubdomains(domain, entryID, S_DIR, moreDetails=True))

        if method == 'searchTargetsByASN':
            willIncludeASN = True
            outputFiles = searchTargetsByASN(domain, entryID, S_DIR)
            for file in outputFiles:
                addScanFileDB(entryID, file)

        elif method == 'useScreenshotting':
            outputFiles = useScreenshotting(domain, entryID, S_DIR, V_DIR, threads=5, delay=SCREENSHOT_DELAY_SECONDS)
            for file in outputFiles:
                addScanFileDB(entryID, file)

        elif method == 'checkExposedPorts':
            addScanFileDB(entryID, checkExposedPorts(domain, entryID, S_DIR, includeASN=willIncludeASN))

        elif method == 'checkVulnerableParameters':
            vulns = ['debug_logic', 'idor', 'img-traversal', 'interestingEXT', 'interestingparams', 'interestingsubs', 
                     'jsvar', 'lfi', 'rce', 'redirect', 'sqli', 'ssrf', 'ssti', 'xss']
            for vuln in vulns:
                addScanFileDB(entryID, checkVulnerableParameters(domain, entryID, S_DIR, sensitiveVulnerabilityType=vuln))
            addScanFileDB(entryID, interestingSubsAlive(domain, entryID, S_DIR))

        elif method == 'generateSubdomainWordlist':
            addScanFileDB(entryID, generateWordlist(domain, entryID, S_DIR, wordlist='subdomain'))

    for file in files.split():
        print(f'[*] Using file                  : {file}')

    cleanResultFilesDB(type='Scan', entryID=entryID)
    resultFiles = getResultFilesDB(type='Scan', entryID=entryID)
    print(f'[+] Resulting files created     : {str(resultFiles)}')
    print(f'[+] Subdomain scanning completed! Check logs in {S_DIR}')
    saveDB()


def executeVulnerabilityScanning(domain, vulnerabilities, files, entryID):
    print(); print(f'[*] Starting vulnerability scanning against {str(domain)}!')
    print(f'[*] Searching vulnerabilities   : {vulnerabilities}')
    print(f'[*] Using the following files   : {str(files)}')

    S_DIR = SUBDOMAIN_SCAN_OUTPUT_DIRECTORY     # To make code less confusing. Less text = more understandable.
    S_DIR = S_DIR + entryID + '/'               # Example: /root/Desktop/SmartWebPen/website/generated/subdomains/<entryID>/
    V_DIR = VULNERABILITY_SCAN_OUTPUT_DIRECTORY
    V_DIR = V_DIR + entryID + '/'               # Example: /root/Desktop/SmartWebPen/website/generated/vulnerabilities/<entryID>/
    executeCMD(f'mkdir {V_DIR}')                # Create a folder, in case it being missing.

    for vulnerability in vulnerabilities.split():
        print(f'[*] Executing scanning for      : {str(vulnerability)}')

        if vulnerability == 'CRLF':
            addVulnFileDB(entryID, CRLF(domain, entryID, S_DIR, V_DIR))

        elif vulnerability == 'XSS':
            addVulnFileDB(entryID, XSS(domain, entryID, S_DIR, V_DIR))

        elif vulnerability == 'Nuclei':
            addVulnFileDB(entryID, nuclei(domain, entryID, S_DIR, V_DIR))

        elif vulnerability == 'SQLi':
            addVulnFileDB(entryID, SQLi(domain,entryID, S_DIR, V_DIR))

        elif vulnerability == 'Github':
            addVulnFileDB(entryID, github(domain, entryID, S_DIR, V_DIR))

        elif vulnerability == 'retireJS':
            addVulnFileDB(entryID, retireJS(domain, entryID, S_DIR, V_DIR, willRunWaymore=willRunWaymore))

        elif vulnerability == 'mantra':
            addVulnFileDB(entryID, mantra(domain, entryID, S_DIR, V_DIR))

    cleanResultFilesDB(type='Vulnerability', entryID=entryID)
    resultFiles = getResultFilesDB(type='Vulnerability', entryID=entryID)
    print(f'[+] Resulting files created     : {str(resultFiles)}')
    print(f'[+] Vulnerability scanning completed! Check logs in {V_DIR}')
    saveDB()


def executePortScanning(domain, flags, HTMLReport, entryID):
    print(); print(f'[*] Starting port scanning against {str(domain)}!')
    print(f'[*] Using the following flags   : {str(flags)}')

    P_DIR = PORT_SCAN_OUTPUT_DIRECTORY     # To make code less confusing. Less text = more understandable.
    P_DIR = P_DIR + entryID + '/'          # Example: /root/Desktop/SmartWebPen/website/generated/ports/<entryID>/
    executeCMD(f'mkdir {P_DIR}')           # Create a folder, in case it being missing.

    outputFiles = nmap(domain, entryID, P_DIR, flags, HTMLReport=HTMLReport)
    for file in outputFiles:
        addPortScanFileDB(entryID, file)

    cleanResultFilesDB(type='PortScan', entryID=entryID)
    resultFiles = getResultFilesDB(type='PortScan', entryID=entryID)
    print(f'[+] Resulting files created     : {str(resultFiles)}')
    print(f'[+] Port scanning completed! Check logs in {P_DIR}')
    saveDB()