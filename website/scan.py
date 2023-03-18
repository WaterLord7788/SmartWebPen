from flask import Blueprint, request, flash, jsonify, flash, redirect, url_for
from flask import Flask, render_template, session
from flask_login import login_required, current_user
from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, MIN_NUMER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from werkzeug.utils import secure_filename
from os.path import join, dirname, realpath
from .models import User, Subdomains
from bs4 import BeautifulSoup
import requests
import asyncio
import random
import json
import os


def intializeEnumeration(domain, tools, methods, files): executeSubdomainEnumeration(domain, tools, methods, files)
def executeSubdomainEnumeration(domain, tools, methods, files, entryID=str(random.randint(MIN_NUMER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION))):
    """"
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
    entryID = entryID
    
    print('[+] Starting subdomain enumeration!')
    print('[*] Using the following tools   : '+str(tools)+'')
    print('[*] Using the following methods : '+str(methods)+'')
    print('[*] Using the following files   : '+str(files)+'')
    for tool in tools.split():
        print('[*] Executing '+tool+'')
        if tool == 'amass':
            #if files: cmd = str('amass --wordlist '+files+' ')
            cmd = str('amass enum -active -brute -o '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-amass-'+entryID+'.txt -d '+domain+'')
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()
        elif tool == 'subfinder':
            #if files: cmd = str('subfinder --wordlist '+files+' ')
            print(SUBDOMAIN_SCAN_OUTPUT_DIRECTORY)
            cmd = str('subfinder -all -d '+domain+' -o '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-subfinder-'+entryID+'.txt -rl 10 -silent')
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()
        elif tool == 'gau':
            #if files: cmd = str('gau --wordlist '+files+' ')
            cmd = str('printf '+domain+' | gau --subs --blacklist png,jpg,css,js | unfurl domains | sort -u | tee '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-gau-'+entryID+'.txt')
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()
        elif tool == 'waybackurls':
            cmd = str('waybackurls '+domain+' | unfurl domains | sort -u | tee '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-waybackurls-'+entryID+'.txt')
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()
        
        """ # Currently not working - One of To-Do's
        elif tool == 'crt.sh':
            cmd = str("curl 'https://crt.sh/?q="+domain+"&output=json' | jq -r '.[].common_name' | sed 's/\*//g' | sort -u | tee "+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+""+domain+"-crt.sh-"+entryID+".txt")
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()"""
    for method in methods.split():
        print('[*] Using method '+method+'')
        if method == 'checkAliveSubdomains':
            cmd = str('(cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-amass-'+entryID+'.txt && cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-subfinder-'+entryID+'.txt && cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-gau-'+entryID+'.txt && cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-waybackurls-'+entryID+'.txt && cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-crt.sh-'+entryID+'.txt) | httpx -title -sc -tech-detect -server -no-color | sort -u | tee '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-ALIVE-'+entryID+'.txt ')
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()
    for file in files.split():
        print('[*] Using file '+file+'')
    print('[+] Scanning completed! Check logs in website/generated/subdomains')

def intializeVulnerabilityScanning(domain, tools, methods, files): executeVulnerabilityScanning(domain, tools, methods, files)
def executeVulnerabilityScanning(domain, tools, methods, files):
    entryID = str(random.randint(MIN_NUMER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION))
    
    print()
    print('[*] Initiating vulnerability scanning!')
    print('[*] Gathering subdomains for '+domain+'')
    executeSubdomainEnumeration(domain=domain, tools="amass subfinder gau waybackurls",
                                methods="customWordlist checkAliveSubdomains useScreenshotting",
                                files="/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt",
                                entryID=entryID)
    print()
    print('[*] Starting vulnerability scanning!')
    print('[*] Using the following tools   : '+str(tools)+'')
    print('[*] Using the following methods : '+str(methods)+'')
    print('[*] Using the following files   : '+str(files)+'')

    for tool in tools.split():
        print('[*] Executing scanning for '+tool+'')
        if tool == 'CRLF':
            #if files: cmd = str('amass --wordlist '+files+' ')
            cmd = str('cat '+VULNERABILITY_SCAN_OUTPUT_DIRECTORY+''+domain+'-ALIVE-'+entryID+'.txt | while read -r line; do curl -iL http://$line/%0D%0A%20Set-Cookie:testingForCRLF=true && curl -iL http://$line/%E5%98%8D%E5%98%8Set-Cookie:testingForCRLF=true ; done | tee '+VULNERABILITY_SCAN_OUTPUT_DIRECTORY+''+domain+'-CRLF-'+entryID+'.txt')
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()
    print('[+] Scanning completed! Check logs in website/generated/vulnerabilities')