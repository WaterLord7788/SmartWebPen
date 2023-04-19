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
    print(); print('[+] Starting subdomain enumeration against '+str(domain)+'!')
    print('[*] Using the following tools   : '+str(tools)+'')
    print('[*] Using the following methods : '+str(methods)+'')
    print('[*] Using the following files   : '+str(files)+'')

    resultFiles = []
    S_DIR = SUBDOMAIN_SCAN_OUTPUT_DIRECTORY # To make code less confusing. Less text = more understandable.
    S_DIR = S_DIR + entryID + '/'           # Example: /root/Desktop/SmartWebPen/website/generated/subdomains/<entryID>/
    #os.system('mkdir '+S_DIR+'')            # Create a folder, in case if it is missing.

    for tool in tools.split():
        print('[*] Executing                   : '+tool+'')
        if tool == 'amass':
            cmd = str('amass enum -active -brute -d '+domain+' | tee '+S_DIR+''+domain+'-amass-'+entryID+'.txt')
            execute = os.popen(cmd)
            output = execute.read()
            execute.close()
            resultFiles.append(str(''+S_DIR+''+domain+'-amass-'+entryID+'.txt'))
        elif tool == 'subfinder':
            cmd = str('subfinder -all -d '+domain+' -o '+S_DIR+''+domain+'-subfinder-'+entryID+'.txt -rl 10 -silent')
            execute = os.popen(cmd)
            output = execute.read()
            resultFiles.append(str(''+S_DIR+''+domain+'-subfinder-'+entryID+'.txt'))
            execute.close()
        elif tool == 'gau':
            cmd = str('printf '+domain+' | gau --subs --blacklist png,jpg,css,js | unfurl domains | sort -u | tee '+S_DIR+''+domain+'-gau-'+entryID+'.txt')
            execute = os.popen(cmd)
            output = execute.read()
            resultFiles.append(str(''+S_DIR+''+domain+'-gau-'+entryID+'.txt'))
            execute.close()
        elif tool == 'waybackurls':
            # Gather only subdomains from root domain.
            cmd = str('waybackurls '+domain+' | unfurl domains | sort -u | tee '+S_DIR+''+domain+'-waybackurls-'+entryID+'.txt')
            execute = os.popen(cmd)
            output = execute.read()
            resultFiles.append(str(''+S_DIR+''+domain+'-waybackurls-'+entryID+'.txt'))
            execute.close()

            # Gather all urls from root domain
            cmd2 = str('waybackurls '+domain+' | sort -u | tee '+S_DIR+''+domain+'-waybackurls+raw-'+entryID+'.txt')
            execute2 = os.popen(cmd2)
            output2 = execute2.read()
            resultFiles.append(str(''+S_DIR+''+domain+'-waybackurls+raw-'+entryID+'.txt'))
            execute2.close()

            # Gather everything from all domains
            cmd3 = str('cat '+S_DIR+''+domain+'-*-'+entryID+'.txt | unfurl format %d | sort -u | waybackurls | sort -u | tee '+S_DIR+''+domain+'-waybackurls+all-'+entryID+'.txt')
            execute3 = os.popen(cmd3)
            output3 = execute3.read()
            resultFiles.append(str(''+S_DIR+''+domain+'-waybackurls+all-'+entryID+'.txt'))
            execute3.close()
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
            cmd = str('cat '+S_DIR+''+domain+'-*-'+entryID+'.txt | unfurl format %d | httpx -no-color -silent | sort -u | tee '+S_DIR+''+domain+'-alive-'+entryID+'.txt ')
            execute = os.popen(cmd)
            output = execute.read()
            resultFiles.append(str(''+S_DIR+''+domain+'-alive-'+entryID+'.txt'))
            execute.close()
            # Output subdomains with additional data. For user to read through.
            cmd = str('cat '+S_DIR+''+domain+'-*-'+entryID+'.txt | unfurl format %d | httpx -title -cl -sc -tech-detect -fr -server -no-color -silent | sort -u | tee '+S_DIR+''+domain+'-alive+stats-'+entryID+'.txt ')
            execute = os.popen(cmd)
            output = execute.read()
            resultFiles.append(str(''+S_DIR+''+domain+'-alive+stats-'+entryID+'.txt'))
            execute.close()
        elif method == 'useScreenshotting':
            pass
        elif method == 'checkExposedPorts':
            # <!-- Also, implement this: https://m7arm4n.medium.com/default-credentials-on-sony-swag-time-8e35681ad39e-->
            pass
        elif method == 'checkVulnerableParameters':
            vulns = ['debug_logic', 'idor', 'img-traversal', 'interestingEXT', 'interestingparams', 'interestingsubs', 
                     'jsvar', 'lfi', 'rce', 'redirect', 'sqli', 'ssrf', 'ssti', 'xss']
            for vuln in vulns:
                cmd = str('cat '+S_DIR+''+domain+'-*-'+entryID+'.txt | unfurl format %d | sort -u | gf '+vuln+' | tee -a '+S_DIR+''+domain+'-params-'+vuln+'-'+entryID+'.txt ')
                execute = os.popen(cmd)
                output = execute.read()
                resultFiles.append(str(''+S_DIR+''+domain+'-params-'+vuln+'-'+entryID+'.txt'))
                execute.close()

    for file in files.split():
        print('[*] Using file                  : '+file+'')

    print('[+] Resulting files created     : '+str(resultFiles)+'')
    resultFiles = str(resultFiles).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
    Scan.query.filter_by(entryID=entryID).first().resultFiles = str(Scan.query.filter_by(entryID=entryID).first().resultFiles) + ' ' + str(resultFiles)
    db.session.commit()
    print('[+] Subdomain scanning completed! Check logs in '+S_DIR+'')


def executeVulnerabilityScanning(domain, vulnerabilities, files, entryID):
    print(); print('[*] Starting vulnerability scanning against '+str(domain)+'!')
    print('[*] Exploiting vulnerabilities  : '+str(vulnerabilities)+'')
    print('[*] Using the following files   : '+str(files)+'')

    resultFiles = []
    S_DIR = SUBDOMAIN_SCAN_OUTPUT_DIRECTORY     # To make code less confusing. Less text = more understandable.
    S_DIR = S_DIR + entryID + '/'               # Example: /root/Desktop/SmartWebPen/website/generated/subdomains/<entryID>/
    V_DIR = VULNERABILITY_SCAN_OUTPUT_DIRECTORY
    V_DIR = V_DIR + entryID + '/'               # Example: /root/Desktop/SmartWebPen/website/generated/vulnerabilities/<entryID>/
    #os.system('mkdir '+V_DIR+'')                # Create a folder, in case if it is missing.

    for vulnerability in vulnerabilities.split():
        print('[*] Executing scanning for      : '+str(vulnerability)+'')
        if vulnerability == 'CRLF':
            cmd = str('cat '+S_DIR+''+domain+'-alive-'+entryID+'.txt | while read -r line; do echo && echo $line/%0D%0A%20Set-Cookie:%20testingForCRLF=true && curl -s -I -X GET $line/%0D%0A%20Set-Cookie:%20testingForCRLF=true && echo $line/%E5%98%8D%E5%98%8Set-Cookie:%20testingForCRLF=true && curl -s -I -X GET $line/%E5%98%8D%E5%98%8Set-Cookie:%20testingForCRLF=true && echo ; done | tee '+V_DIR+''+domain+'-crlf-'+entryID+'.txt')
            execute = os.popen(cmd);
            output = execute.read();
            resultFiles.append(str(''+V_DIR+''+domain+'-crlf-'+entryID+'.txt'))
            execute.close()
        elif vulnerability == 'XSS':
            cmd = str('dalfox file '+S_DIR+''+domain+'-alive-'+entryID+'.txt --only-poc="g,r,v" --skip-mining-dict -S --no-color | tee '+V_DIR+''+domain+'-xss-'+entryID+'.txt')
            execute = os.popen(cmd);
            output = execute.read();
            resultFiles.append(str(''+V_DIR+''+domain+'-xss-'+entryID+'.txt'))
            execute.close()
        elif vulnerability == 'Nuclei':
            cmd = str('nuclei -l '+S_DIR+''+domain+'-alive-'+entryID+'.txt -es info -silent -rl 80 -o '+V_DIR+''+domain+'-nuclei-'+entryID+'.txt')
            execute = os.popen(cmd); 
            output = execute.read();
            resultFiles.append(str(''+V_DIR+''+domain+'-nuclei-'+entryID+'.txt'))
            execute.close()
        elif vulnerability == 'SQLi':
            pass
        elif vulnerability == 'Github':
            pass

    print('[+] Resulting files created     : '+str(resultFiles)+'')
    resultFiles = str(resultFiles).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
    Scan.query.filter_by(entryID=entryID).first().resultFiles = str(Scan.query.filter_by(entryID=entryID).first().resultFiles) + ' ' + str(resultFiles)
    db.session.commit()
    print('[+] Vulnerability scanning completed! Check logs in '+V_DIR+'')


def executeURLScanning():
    # This function will: 
    # - Screenshot alive subdomains
    # - Collect web-pages with non-common HTTP reponse codes, such as 302,403,405,406,500 and so on - more data: https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
    # - Grep URLs with sensitive words, such as admin,register,login,upload,signup,panel,file and so on
    # - Try to fetch old URLs and files, probably forgotten and sensitive, from Waybackurls
    pass