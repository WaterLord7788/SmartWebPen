from flask import Blueprint, request, flash, jsonify, flash, redirect, url_for
from flask import Flask, render_template, session
from flask_login import login_required, current_user
from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, MIN_NUMER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from werkzeug.utils import secure_filename
from os.path import join, dirname, realpath
from .models import User, Scan
from bs4 import BeautifulSoup
import requests
import asyncio
import random
import json
import os


def executeSubdomainEnumeration(domain, tools, methods, files, entryID=str(random.randint(MIN_NUMER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION))):
    """
    cmd = str('ping 127.0.0.1')
    execute = os.popen(cmd)
    output = execute.read()
    execute.close()

    filename = 'ping-'+str(random.randint(MIN_NUMER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION))+'.txt'
    directory = SUBDOMAIN_SCAN_OUTPUT_DIRECTORY
    realOutputDirectory = directory+filename
    with open(realOutputDirectory, "w") as file:
        file.write(output)
    """
    print(); print('[+] Starting subdomain enumeration!')
    print('[*] Using the following tools   : '+str(tools)+'')
    print('[*] Using the following methods : '+str(methods)+'')
    print('[*] Using the following files   : '+str(files)+'')

    resultFiles = []

    for tool in tools.split():
        print('[*] Executing                   : '+tool+'')
        if tool == 'amass':
            cmd = str('amass enum -active -brute -d '+domain+' | tee '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-amass-'+entryID+'.txt')
            execute = os.popen(cmd)
            output = execute.read()
            execute.close()
            resultFiles.append(str(''+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-amass-'+entryID+'.txt'))
        elif tool == 'subfinder':
            cmd = str('subfinder -all -d '+domain+' -o '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-subfinder-'+entryID+'.txt -rl 10 -silent')
            execute = os.popen(cmd)
            output = execute.read()
            resultFiles.append(str(''+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-subfinder-'+entryID+'.txt'))
            execute.close()
        elif tool == 'gau':
            cmd = str('printf '+domain+' | gau --subs --blacklist png,jpg,css,js | unfurl domains | sort -u | tee '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-gau-'+entryID+'.txt')
            execute = os.popen(cmd)
            output = execute.read()
            resultFiles.append(str(''+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-gau-'+entryID+'.txt'))
            execute.close()
        elif tool == 'waybackurls':
            cmd = str('waybackurls '+domain+' | unfurl domains | sort -u | tee '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-waybackurls-'+entryID+'.txt')
            execute = os.popen(cmd)
            output = execute.read()
            resultFiles.append(str(''+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-waybackurls-'+entryID+'.txt'))
            execute.close()
        """ # Currently not working - One of To-Do's
        elif tool == 'crt.sh':
            cmd = str("curl 'https://crt.sh/?q="+domain+"&output=json' | jq -r '.[].common_name' | sed 's/\*//g' | sort -u | tee "+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+""+domain+"-crt.sh-"+entryID+".txt")
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()"""
    for method in methods.split():
        print('[*] Using method                : '+method+'')
        if method == 'checkAliveSubdomains':
            # Raw output.
            cmd = str('(cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-amass-'+entryID+'.txt && cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-subfinder-'+entryID+'.txt && cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-gau-'+entryID+'.txt && cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-waybackurls-'+entryID+'.txt && cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-crt.sh-'+entryID+'.txt) | httpx -no-color | sort -u | tee '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-alive-'+entryID+'.txt ')
            execute = os.popen(cmd)
            output = execute.read()
            resultFiles.append(str(''+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-alive-'+entryID+'.txt'))
            execute.close()
            # Output subdomains with additional data. For user to read through.
            cmd = str('(cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-*-'+entryID+'.txt ) | httpx -title -cl -sc -tech-detect -fr -server -no-color | sort -u | tee '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-alive+stats-'+entryID+'.txt ')
            execute = os.popen(cmd)
            output = execute.read()
            resultFiles.append(str(''+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-alive+stats-'+entryID+'.txt'))
            execute.close()
        if method == 'checkExposedPorts':
            pass
            
    for file in files.split():
        print('[*] Using file                  : '+file+'')

    print('[+] Resulting files created     : '+str(resultFiles)+'')
    Scan.query.filter_by(entryID=entryID).resultFiles = resultFiles
    db.session.commit()
    print('[+] Scanning completed! Check logs in '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+'')


def executeVulnerabilityScanning(domain, vulnerabilities, files, entryID=str(random.randint(MIN_NUMER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION))):
    print(); print('[*] Initiating vulnerability scanning!')
    print('[*] Gathering subdomains for '+domain+'')
    executeSubdomainEnumeration(domain=domain, tools="amass subfinder gau waybackurls", methods="customWordlist checkAliveSubdomains useScreenshotting", files="/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt", entryID=entryID)
    print(); print('[*] Starting vulnerability scanning!')
    print('[*] Using the following tools   : '+str(tools)+'')
    print('[*] Using the following methods : '+str(methods)+'')
    print('[*] Using the following files   : '+str(files)+'')

    resultFiles = []

    for vulnerability in vulnerabilities.split():
        print('[*] Executing scanning for      : '+str(tool)+'')
        if vulnerability == 'CRLF':
            cmd = str('cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-alive-'+entryID+'.txt | while read -r line; do echo && echo $line/%0D%0A%20Set-Cookie:%20testingForCRLF=true && curl -s -I -X GET $line/%0D%0A%20Set-Cookie:%20testingForCRLF=true && echo $line/%E5%98%8D%E5%98%8Set-Cookie:%20testingForCRLF=true && curl -s -I -X GET $line/%E5%98%8D%E5%98%8Set-Cookie:%20testingForCRLF=true && echo ; done | tee '+VULNERABILITY_SCAN_OUTPUT_DIRECTORY+''+domain+'-crlf-'+entryID+'.txt')
            execute = os.popen(cmd);
            output = execute.read();
            resultFiles.append(str(''+VULNERABILITY_SCAN_OUTPUT_DIRECTORY+''+domain+'-crlf-'+entryID+'.txt'))
            execute.close()
        elif vulnerability == 'XSS':
            cmd = str('dalfox file '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-alive-'+entryID+'.txt --only-poc="g,r,v" --skip-mining-dict -S --no-color | tee '+VULNERABILITY_SCAN_OUTPUT_DIRECTORY+''+domain+'-xss-'+entryID+'.txt')
            execute = os.popen(cmd);
            output = execute.read();
            resultFiles.append(str(''+VULNERABILITY_SCAN_OUTPUT_DIRECTORY+''+domain+'-xss-'+entryID+'.txt'))
            execute.close()
        elif vulnerability == 'Nuclei':
            cmd = str('nuclei -l '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-alive-'+entryID+'.txt -es info -silent -rl 80 -o '+VULNERABILITY_SCAN_OUTPUT_DIRECTORY+''+domain+'-nuclei-'+entryID+'.txt')
            execute = os.popen(cmd); 
            output = execute.read();
            resultFiles.append(str(''+VULNERABILITY_SCAN_OUTPUT_DIRECTORY+''+domain+'-nuclei-'+entryID+'.txt'))
            execute.close()
        elif vulnerability == 'SQLi':
            pass
        elif vulnerability == 'Github':
            pass

    print('[+] Scanning completed! Check logs in '+VULNERABILITY_SCAN_OUTPUT_DIRECTORY+'')


def executeURLScanning():
    pass