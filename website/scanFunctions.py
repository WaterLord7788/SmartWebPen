from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from os.path import join, dirname, realpath
import requests
import asyncio
import random
import json
import os

def amass(domain, entryID, S_DIR):
    resultFiles = []
    resultingFile = str(''+S_DIR+''+domain+'-amass-'+entryID+'.txt')
    cmd = str('touch '+resultingFile+' && amass enum -active -brute -d '+domain+' > '+resultingFile)
    execute = os.popen(cmd)
    execute.close()
    resultFiles.append(resultingFile)
    return resultFiles

def subfinder(domain, entryID, S_DIR):
    resultFiles = []
    resultingFile = str(''+S_DIR+''+domain+'-subfinder-'+entryID+'.txt')
    cmd = str('subfinder -all -d '+domain+' -o '+resultingFile+' -rl 10 -silent')
    execute = os.popen(cmd)
    resultFiles.append(resultingFile)
    execute.close()
    return resultFiles

def gau(domain, entryID, S_DIR):
    resultFiles = []
    resultingFile = str(''+S_DIR+''+domain+'-gau-'+entryID+'.txt')
    cmd = str('printf '+domain+' | gau --subs --blacklist png,jpg,css,js | unfurl domains | sort -u | tee '+resultingFile)
    execute = os.popen(cmd)
    resultFiles.append(resultingFile)
    execute.close()
    return resultFiles

def waybackurls(domain, entryID, S_DIR):
    resultFiles = []
    # Gather only subdomains from root domain.
    resultingFile = str(''+S_DIR+''+domain+'-waybackurls-'+entryID+'.txt')
    cmd = str('waybackurls '+domain+' | unfurl domains | sort -u | tee '+resultingFile)
    execute = os.popen(cmd)
    resultFiles.append(resultingFile)
    execute.close()
    # Gather all urls from root domain
    resultingFile = str(''+S_DIR+''+domain+'-waybackurls+raw-'+entryID+'.txt')
    cmd = str('waybackurls '+domain+' | sort -u | tee '+resultingFile)
    execute = os.popen(cmd)
    resultFiles.append(resultingFile)
    execute.close()
    return resultFiles

def crtsh(domain, entryID, S_DIR):
    resultFiles = []
    resultingFile = str(''+S_DIR+''+domain+'-crt.sh-'+entryID+'.txt')
    cmd = str("curl 'https://crt.sh/?q="+domain+"&output=json' | jq -r '.[].common_name' | sed 's/\*//g' | sort -u | tee "+resultingFile)
    execute = os.popen(cmd);  
    resultFiles.append(resultingFile)
    execute.close()
    return resultFiles

def checkAliveSubdomains():
    resultFiles = []
    # Raw output.
    resultingFile = str(''+S_DIR+''+domain+'-alive-'+entryID+'.txt')
    cmd = str('cat '+S_DIR+''+domain+'-*-'+entryID+'.txt | unfurl format %d | httpx -no-color -silent | sort -u | tee '+resultingFile)
    execute = os.popen(cmd)
    resultFiles.append(resultingFile)
    execute.close()
    # Output subdomains with additional data. For user to read through more detailed information.
    resultingFile = str(''+S_DIR+''+domain+'-alive+stats-'+entryID+'.txt')
    cmd = str('cat '+S_DIR+''+domain+'-*-'+entryID+'.txt | unfurl format %d | httpx -title -cl -sc -tech-detect -fr -server -no-color -silent | sort -u | tee '+resultingFile)
    execute = os.popen(cmd)
    resultFiles.append(resultingFile)
    execute.close()
    return resultFiles

# To Do's:
# After completing system calls, it should move all captured images
# into a specific folder under subdomains.
def useScreenshotting(domain, entryID, S_DIR, V_DIR):
    resultFiles = []
    cmd = str('eyewitness -f '+S_DIR+''+domain+'-alive-'+entryID+'.txt --jitter 2 --delay 1 --web --max-retries 3 --no-prompt --selenium-log-path=/dev/null -d website/generated/vulnerabilities/'+entryID+'/')
    execute = os.popen(cmd)
    #resultFiles.append(str(''+V_DIR+''+domain+'-crlf-'+entryID+'.txt'))
    execute.close()
    return resultFiles

def checkExposedPorts(domain, entryID, S_DIR, V_DIR):
    resultFiles = []
    return resultFiles

def checkVulnerableParameters(domain, entryID, S_DIR, V_DIR):
    resultFiles = []
    return resultFiles

def noncommonResponseCodes(domain, entryID, S_DIR, V_DIR):
    resultFiles = []
    return resultFiles

def sensitiveKeywords(domain, entryID, S_DIR, V_DIR):
    resultFiles = []
    return resultFiles