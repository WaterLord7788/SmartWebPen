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


async def intializeEnumeration(tools, methods, files): await executeSubdomainEnumeration(tools, methods, files)
async def executeSubdomainEnumeration(tools, methods, files):
    print(tools)
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
    for tool in tools.split():
        print(tool)
        if tool == 'amass':
            if files:
                cmd = str('amass --wordlist '+files+' ')
            cmd = str('amass')
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()
        elif tool == 'subfinder':
            if files:
                cmd = str('subfinder --wordlist '+files+' ')
            cmd = str('subfinder')
            print(cmd)
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()
        elif tool == 'gau':
            if files:
                cmd = str('gau --wordlist '+files+' ')
            cmd = str('gau')
            print(cmd)
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()
        elif tool == 'waybackurls':
            cmd = str('waybackurls')
            print(cmd)
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()
        elif tool == 'crt.sh':
            cmd = str('curl http://crt.sh/?query=...')
            print(cmd)
            execute = os.popen(cmd); 
            output = execute.read(); 
            execute.close()
    """