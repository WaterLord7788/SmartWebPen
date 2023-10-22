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
from .webFunctions import *
import threading
import random
import json


willRunWaymore = False
willIncludeASN = False
willCheckAliveSubdomains = False


def startScan(domain, tools, methods, files, entryID=str(random.randint(MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION)), vulnerabilities=[]):
    global willRunWaymore, willIncludeASN, willCheckAliveSubdomains

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
            amass(domain, entryID, S_DIR, timeout=AMASS_TIMEOUT_MINUTES)

        elif tool == 'subfinder':
            subfinder(domain, entryID, S_DIR)

        elif tool == 'gau':
            gau(domain, entryID, S_DIR)

        elif tool == 'waybackurls':
            waybackurls(domain, entryID, S_DIR, stage='onlySubdomains')
            waybackurls(domain, entryID, S_DIR, stage='everything')

        elif tool == 'crt.sh':
            crtsh(domain, entryID, S_DIR)

        elif tool == 'waymore':
            willRunWaymore = True
            waymore(domain, entryID, S_DIR, timeout=WAYMORE_TIMEOUT_MINUTES)
        
        elif tool == 'goSpider':
            gospider(domain, entryID, S_DIR, depth=GOSPIDER_DEPTH_NUMBER)

        elif tool == 'xLinkFinder':
            xLinkFinder(domain, entryID, S_DIR)

    for method in methods.split():
        print(f'[*] Using method                : {method}')

        if method == 'checkAliveSubdomains':
            willCheckAliveSubdomains = True
            checkAliveSubdomains(domain, entryID, S_DIR, moreDetails=False)
            checkAliveSubdomains(domain, entryID, S_DIR, moreDetails=True)

        if method == 'searchTargetsByASN':
            willIncludeASN = True
            searchTargetsByASN(domain, entryID, S_DIR)

        elif method == 'useScreenshotting':
            useScreenshotting(domain, entryID, S_DIR, V_DIR, threads=5, delay=SCREENSHOT_DELAY_SECONDS)

        elif method == 'checkExposedPorts':
            checkExposedPorts(domain, entryID, S_DIR, includeASN=willIncludeASN)

        elif method == 'checkVulnerableParameters':
            vulns = ['debug_logic', 'idor', 'img-traversal', 'interestingEXT', 'interestingparams', 'interestingsubs', 
                     'jsvar', 'lfi', 'rce', 'redirect', 'sqli', 'ssrf', 'ssti', 'xss']
            for vuln in vulns:
                checkVulnerableParameters(domain, entryID, S_DIR, sensitiveVulnerabilityType=vuln)
            interestingSubsAlive(domain, entryID, S_DIR)

        elif method == 'generateSubdomainWordlist':
            generateWordlist(domain, entryID, S_DIR, wordlist='subdomain')

    for file in files.split():
        print(f'[*] Using file                  : {file}')

    print(f'[+] Subdomain scanning completed! Check logs in {S_DIR}')

    if vulnerabilities:
        executeVulnerabilityScanning(domain, vulnerabilities, files, entryID)


def executeVulnerabilityScanning(domain, vulnerabilities, files, entryID):
    global willRunWaymore, willIncludeASN, willCheckAliveSubdomains

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
            CRLF(domain, entryID, S_DIR, V_DIR)

        elif vulnerability == 'XSS':
            XSS(domain, entryID, S_DIR, V_DIR)

        elif vulnerability == 'Nuclei':
            nuclei(domain, entryID, S_DIR, V_DIR)

        elif vulnerability == 'SQLi':
            SQLi(domain,entryID, S_DIR, V_DIR)

        elif vulnerability == 'Github':
            github(domain, entryID, S_DIR, V_DIR)

        elif vulnerability == 'retireJS':
            retireJS(domain, entryID, S_DIR, V_DIR, willRunWaymore=willRunWaymore)

        elif vulnerability == 'mantra':
            mantra(domain, entryID, S_DIR, V_DIR)

    print(f'[+] Vulnerability scanning completed! Check logs in {V_DIR}')


def executePortScanning(domain, flags, HTMLReport, entryID):
    print(); print(f'[*] Starting port scanning against {str(domain)}!')
    print(f'[*] Using the following flags   : {str(flags)}')

    P_DIR = PORT_SCAN_OUTPUT_DIRECTORY     # To make code less confusing. Less text = more understandable.
    P_DIR = P_DIR + entryID + '/'          # Example: /root/Desktop/SmartWebPen/website/generated/ports/<entryID>/
    executeCMD(f'mkdir {P_DIR}')           # Create a folder, in case it being missing.

    nmap(domain, entryID, P_DIR, flags, HTMLReport=HTMLReport)

    print(f'[+] Port scanning completed! Check logs in {P_DIR}')