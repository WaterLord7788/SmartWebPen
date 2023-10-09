from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from os.path import join, dirname, realpath
from .systemFunctions import executeCMD
import requests
import asyncio
import random
import json
import os

def amass(domain, entryID, S_DIR):
    resultFiles = []
    outputFile = str(''+S_DIR+''+domain+'-amass-'+entryID+'.txt')
    cmd = str('touch '+outputFile+' && amass enum -active -brute -d '+domain+' > '+outputFile)
    executeCMD(cmd)
    resultFiles.append(outputFile)
    return resultFiles

def subfinder(domain, entryID, S_DIR):
    resultFiles = []
    outputFile = str(''+S_DIR+''+domain+'-subfinder-'+entryID+'.txt')
    cmd = str('subfinder -all -d '+domain+' -o '+outputFile+' -rl 10 -silent')
    executeCMD(cmd)
    resultFiles.append(outputFile)
    return resultFiles

def gau(domain, entryID, S_DIR):
    resultFiles = []
    outputFile = str(''+S_DIR+''+domain+'-gau-'+entryID+'.txt')
    cmd = str('printf '+domain+' | gau --subs --blacklist png,jpg,css,js | unfurl domains | sort -u | tee '+outputFile)
    executeCMD(cmd)
    resultFiles.append(outputFile)
    return resultFiles

def waybackurls(domain, entryID, S_DIR):
    resultFiles = []
    # Gather only subdomains from root domain.
    outputFile = str(''+S_DIR+''+domain+'-waybackurls-'+entryID+'.txt')
    cmd = str('waybackurls '+domain+' | unfurl domains | sort -u | tee '+outputFile)
    executeCMD(cmd)
    resultFiles.append(outputFile)
    # Gather all urls from root domain
    outputFile = str(''+S_DIR+''+domain+'-waybackurls+raw-'+entryID+'.txt')
    cmd = str('waybackurls '+domain+' | sort -u | tee '+outputFile)
    executeCMD(cmd)
    resultFiles.append(outputFile)
    return resultFiles

def crtsh(domain, entryID, S_DIR):
    resultFiles = []
    outputFile = str(''+S_DIR+''+domain+'-crt.sh-'+entryID+'.txt')
    cmd = str("curl 'https://crt.sh/?q="+domain+"&output=json' | jq -r '.[].common_name' | sed 's/\*//g' | sort -u | tee "+outputFile)
    executeCMD(cmd);  
    resultFiles.append(outputFile)
    return resultFiles

def checkAliveSubdomains(domain, entryID, S_DIR):
    resultFiles = []
    # Raw output.
    outputFile = str(''+S_DIR+''+domain+'-alive-'+entryID+'.txt')
    cmd = str('cat '+S_DIR+''+domain+'-*-'+entryID+'.txt | unfurl format %d | httpx -no-color -silent | sort -u | tee '+outputFile)
    executeCMD(cmd)
    resultFiles.append(outputFile)
    # Output subdomains with additional data. For user to read through more detailed information.
    outputFile = str(''+S_DIR+''+domain+'-alive+stats-'+entryID+'.txt')
    cmd = str('cat '+S_DIR+''+domain+'-*-'+entryID+'.txt | unfurl format %d | httpx -title -cl -sc -tech-detect -fr -server -no-color -silent | sort -u | tee '+outputFile)
    executeCMD(cmd)
    resultFiles.append(outputFile)
    return resultFiles

def useScreenshotting(domain, entryID, S_DIR, V_DIR):
    # To Do's:
    # After completing system calls, it should move all captured images
    # into a specific folder under subdomains.
    resultFiles = []
    cmd = str('eyewitness -f '+S_DIR+''+domain+'-alive-'+entryID+'.txt --jitter 2 --delay 1 --web --max-retries 3 --no-prompt --selenium-log-path=/dev/null -d website/generated/vulnerabilities/'+entryID+'/')
    executeCMD(cmd)
    #resultFiles.append(str(''+V_DIR+''+domain+'-crlf-'+entryID+'.txt'))
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

def CRLF(domain, entryID, S_DIR, V_DIR):
    resultFiles = []
    outputFile = str(''+V_DIR+''+domain+'-crlf-'+entryID+'.txt')
    cmd = str('cat '+S_DIR+''+domain+'-alive-'+entryID+'.txt | while read -r line; do echo && echo $line/%0D%0A%20Set-Cookie:%20testingForCRLF=true && curl -s -I -X GET $line/%0D%0A%20Set-Cookie:%20testingForCRLF=true && echo $line/%E5%98%8D%E5%98%8Set-Cookie:%20testingForCRLF=true && curl -s -I -X GET $line/%E5%98%8D%E5%98%8Set-Cookie:%20testingForCRLF=true && echo ; done | tee '+outputFile)
    executeCMD(cmd)
    resultFiles.append(outputFile)
    return resultFiles

def XSS(domain, entryID, S_DIR, V_DIR):
    resultFiles = []
    outputFile = str(''+V_DIR+''+domain+'-xss-'+entryID+'.txt')
    cmd = str('dalfox file '+S_DIR+''+domain+'-alive-'+entryID+'.txt --only-poc="g,r,v" --skip-mining-dict -S --no-color | tee '+outputFile)
    executeCMD(cmd)
    resultFiles.append(outputFile)
    return resultFiles

def nuclei(domain, entryID, S_DIR, V_DIR):
    resultFiles = []
    outputFile = str(''+V_DIR+''+domain+'-nuclei-'+entryID+'.txt')
    cmd = str('nuclei -l '+S_DIR+''+domain+'-alive-'+entryID+'.txt -es info -silent -rl 80 -o '+outputFile)
    executeCMD(cmd)
    resultFiles.append(outputFile)
    return resultFiles