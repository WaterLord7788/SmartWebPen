from flask import Blueprint, request, flash, jsonify, flash, redirect, url_for
from flask import Flask, render_template, session
from flask_login import login_required, current_user
from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, MIN_NUMER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY
from werkzeug.utils import secure_filename
from os.path import join, dirname, realpath
from .models import User, Subdomains
from bs4 import BeautifulSoup
import requests
import asyncio
import random
import json
import os


async def intializeEnumeration(domain, tools, methods, files): await executeSubdomainEnumeration(domain, tools, methods, files)
async def executeSubdomainEnumeration(domain, tools, methods, files):
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
    entryID = str(random.randint(MIN_NUMER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION))
    
    print('[+] Starting subdomain enumeration!   : '+str(tools)+'')
    print('[*] Using the following tools   : '+str(tools)+'')
    print('[*] Using the following methods : '+str(methods)+'')
    print('[*] Using the following files   : '+str(files)+'')
    for tool in tools.split():
        print(tool)
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
            cmd = str('printf '+domain+' | gau --subs --blacklist png,jpg,css,js | unfurl domains | tee '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-gau-'+entryID+'.txt')
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()
        elif tool == 'waybackurls':
            cmd = str('waybackurls '+domain+' | unfurl domains | sort -u | tee '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-waybackurls-'+entryID+'.txt')
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()
        elif tool == 'crt.sh':
            cmd = str("curl https://crt.sh/\?q="+domain+"\&output=json | jq -r '.[].common_name' | sed 's/\*//g' | sort -u | tee "+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+""+domain+"-crt.sh-"+entryID+".txt")
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()
    for method in methods.split():
        print(method)
        if method == 'checkAliveSubdomains':
            cmd = str('(cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-amass-'+entryID+'.txt && cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-subfinder-'+entryID+'.txt && cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-gau-'+entryID+'.txt && cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-waybackurls-'+entryID+'.txt && cat '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-crt.sh-'+entryID+'.txt) | httpx -title -sc -tech-detect -server | tee '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+''+domain+'-ALIVE.txt ')
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()
    for file in files.split():
        print(file)
    print('[+] Scanning completed! Check logs in website/generated/subdomains')