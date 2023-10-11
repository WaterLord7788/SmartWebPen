from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from os.path import join, dirname, realpath
from .systemFunctions import *
import requests
import asyncio
import random
import json
import os

def amass(domain, entryID, S_DIR):
    outputFile = str(''+S_DIR+''+domain+'-amass-'+entryID+'.txt')
    cmd = str('touch '+outputFile+' && amass enum -active -brute -d '+domain+' > '+outputFile)
    executeCMD(cmd)
    return outputFile

def subfinder(domain, entryID, S_DIR):
    outputFile = str(''+S_DIR+''+domain+'-subfinder-'+entryID+'.txt')
    cmd = str('subfinder -all -d '+domain+' -o '+outputFile+' -rl 10 -silent')
    executeCMD(cmd)
    return outputFile

def gau(domain, entryID, S_DIR):
    outputFile = str(''+S_DIR+''+domain+'-gau-'+entryID+'.txt')
    cmd = str('printf '+domain+' | gau --subs --blacklist png,jpg,css,js | unfurl domains | sort -u | tee '+outputFile)
    executeCMD(cmd)
    return outputFile

def waybackurls(domain, entryID, S_DIR, stage):
    if stage == 'onlySubdomains':
        outputFile = str(''+S_DIR+''+domain+'-waybackurls-'+entryID+'.txt')
        cmd = str('waybackurls '+domain+' | unfurl domains | sort -u | tee '+outputFile)
        executeCMD(cmd)
    elif stage == 'everything':
        outputFile = str(''+S_DIR+''+domain+'-waybackurls+raw-'+entryID+'.txt')
        cmd = str('waybackurls '+domain+' | sort -u | tee '+outputFile)
        executeCMD(cmd)
    return outputFile

def crtsh(domain, entryID, S_DIR):
    outputFile = str(''+S_DIR+''+domain+'-crt.sh-'+entryID+'.txt')
    cmd = str("curl -s 'https://crt.sh/?q="+domain+"&output=json' | jq -r '.[].common_name' | sed 's/\*//g' | sort -u | tee "+outputFile)
    executeCMD(cmd);  
    return outputFile

def checkAliveSubdomains(domain, entryID, S_DIR, stage):
    if stage == 'minimalDetails':
        outputFile = str(''+S_DIR+''+domain+'-alive-'+entryID+'.txt')
        cmd = str('cat '+S_DIR+''+domain+'-*-'+entryID+'.txt | unfurl format %d | httpx -no-color -silent | sort -u | tee '+outputFile)
        executeCMD(cmd)
    elif stage == 'additionalDetails':
        outputFile = str(''+S_DIR+''+domain+'-alive+stats-'+entryID+'.txt')
        cmd = str('cat '+S_DIR+''+domain+'-*-'+entryID+'.txt | unfurl format %d | httpx -title -cl -sc -tech-detect -fr -server -no-color -silent | sort -u | tee '+outputFile)
        executeCMD(cmd)
    return outputFile

def useScreenshotting(domain, entryID, S_DIR, V_DIR, threads):
    # To Do's:
    # After completing system calls, it should move all captured images
    # into a specific folder under subdomains.
    #cmd = str('eyewitness -f '+S_DIR+''+domain+'-alive-'+entryID+'.txt --threads '+threads+' --jitter 2 --delay 1 --web --max-retries 3 --no-prompt --selenium-log-path=/dev/null -d '+V_DIR)
    return

def searchTargetsByASN(domain, entryID, S_DIR):
    ip = getIPAddress(domain)
    content = getContentsOfURL(str('https://bgp.he.net/ip/'+ip))
    descriptionElement = getElementsByCSSPath(content, CSSPath="html body div#content div#ipinfo.tabdata table tbody tr td", elementNumber=3) # Need to get the value of the last desired HTML element, therefore `elementNumber` = 3.
    description = cleanTextFromHTML(descriptionElement).replace(' ', '+')
    searchURL = str('https://bgp.he.net/search?search%5Bsearch%5D='+description+'&commit=Search')
    searchURLContent = getContentsOfURL(searchURL)
    ASNumbers = getElementsByCSSPath(searchURLContent, 
                                     CSSPath="html body div div#centerbody div#content div#search.tabdata table.w100p tbody tr td a", 
                                     maximum=5, cleanFromHTML=True)
    ASNumbers = checkValidASNumbers(ASNumbers)
    for ASN in ASNumbers:
        outputFile = getIPsFromASN(ASN, entryID, S_DIR)
    return outputFile

def checkExposedPorts(domain, entryID, S_DIR):
    # To Do's:
    # 1. From `...IPs-from-ASNs...` file check for alive targets.
    # 2. Check for exposed ports by implementing the methodogy below:
    #    https://m7arm4n.medium.com/default-credentials-on-sony-swag-time-8e35681ad39e
    
    # outputFile = str('cat '+S_DIR+''+domain+'-alive-IPs-from-ASNs-'+entryID+'.txt')
    # cmd = str('cat '+S_DIR+''+domain+'-IPs-from-ASNs-'+entryID+'.txt | httpx | tee '+outputFile)
    # executeCMD(cmd)
    # return outputFile
    
def checkVulnerableParameters(domain, entryID, S_DIR, sensitiveVulnerabilityType):
    outputFile = str(''+S_DIR+''+domain+'-params-'+sensitiveVulnerabilityType+'-'+entryID+'.txt')
    cmd = str('cat '+S_DIR+''+domain+'-*-'+entryID+'.txt | unfurl format %d | sort -u | gf '+sensitiveVulnerabilityType+' | tee -a '+outputFile)
    executeCMD(cmd)
    return outputFile

def interestingSubsAlive(domain, entryID, S_DIR):
    outputFile = str(''+S_DIR+''+domain+'-params-interestingsubs-alive-'+entryID+'.txt')
    cmd = str('cat '+S_DIR+''+domain+'-params-interestingsubs-'+entryID+'.txt | unfurl format %d | httpx -no-color -silent | sort -u | tee '+outputFile)
    executeCMD(cmd)
    return outputFile

def noncommonResponseCodes(domain, entryID, S_DIR, V_DIR):
    return

def sensitiveKeywords(domain, entryID, S_DIR, V_DIR):
    return

def CRLF(domain, entryID, S_DIR, V_DIR):
    outputFile = str(''+V_DIR+''+domain+'-crlf-'+entryID+'.txt')
    cmd = str('cat '+S_DIR+''+domain+'-alive-'+entryID+'.txt | while read -r line; do echo && echo $line/%0D%0A%20Set-Cookie:%20testingForCRLF=true && curl -s -I -X GET $line/%0D%0A%20Set-Cookie:%20testingForCRLF=true && echo $line/%E5%98%8D%E5%98%8Set-Cookie:%20testingForCRLF=true && curl -s -I -X GET $line/%E5%98%8D%E5%98%8Set-Cookie:%20testingForCRLF=true && echo ; done | tee '+outputFile)
    executeCMD(cmd)
    return outputFile

def XSS(domain, entryID, S_DIR, V_DIR):
    outputFile = str(''+V_DIR+''+domain+'-xss-'+entryID+'.txt')
    cmd = str('dalfox file '+S_DIR+''+domain+'-alive-'+entryID+'.txt --only-poc="g,r,v" --skip-mining-dict -S --no-color | tee '+outputFile)
    executeCMD(cmd)
    return outputFile

def nuclei(domain, entryID, S_DIR, V_DIR):
    outputFile = str(''+V_DIR+''+domain+'-nuclei-'+entryID+'.txt')
    cmd = str('nuclei -l '+S_DIR+''+domain+'-alive-'+entryID+'.txt -es info -silent -rl 80 -o '+outputFile)
    executeCMD(cmd)
    return outputFile

def SQLi(domain, entryID, S_DIR, V_DIR):
    return

def github(domain, entryID, S_DIR, V_DIR):
    return