from os.path import join, dirname, realpath
import requests
import socket
import uuid
import bs4
import os
import re

# Execute system command and return the output of the call.
def executeCMD(cmd):
    execute = os.popen(cmd)
    outputData = execute.read()
    execute.close()
    return outputData

# Generates safe UUID4 secret key, looks like: `3d6f45a5fc12445dbac2f59c3b6c7cb1`.
def generateSafeSecret():
    secret = uuid.uuid4().hex
    return secret

def getIPAddress(domain):
    ip = domain
    for i in range(1, len(domain)):
        print(ip)
        try:
            ip = socket.gethostbyname(ip)
            return ip
        except: # If failed to get IP by whatever reason, strip the `ip` variable of the subdomain.
            ip = ip[int(ip.find('.')+1):] # This will turn `dev.test.example.com` to `test.example.com`.
    return None

def getContentsOfURL(url):
    response = requests.get(url)
    content = response.text
    return content

def getElementsByCSSPath(content, CSSPath, elementNumber=None, maximum=None, cleanFromHTML=None):
    if elementNumber != None:
        soup = bs4.BeautifulSoup(content, features='lxml')
        elements = soup.select(CSSPath)
        rawDescription = str(elements[elementNumber-1]) # `number-1` because the third element but we need to start from 0 in programming. So, third = 3-1 = 2.
        return rawDescription
    else:
        desiredElements = []
        soup = bs4.BeautifulSoup(content, features='lxml')
        print(CSSPath)
        elements = soup.select(CSSPath)
        for i in range(0, maximum): # Limit maximum number of ASN numbers -> can take a long time.
            if '/AS' in str(elements[i]):
                if cleanFromHTML:
                    desiredElements.append(cleanTextFromHTML(str(elements[i])))
                else:
                    desiredElements.append(elements[i])
        return desiredElements

def cleanTextFromHTML(text):
    CLEAN = re.compile('<.*?>')
    cleanText = CLEAN.sub('', text)
    return cleanText