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
    
    desiredElements = []
    soup = bs4.BeautifulSoup(content, features='lxml')
    elements = soup.select(CSSPath)
    
    if maximum == 'max':
        maximum = len(elements)
    elif maximum > len(elements):
        maximum = len(elements)

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

def getIPsFromASN(domain, ASN, entryID, S_DIR):
    outputFile = f'{S_DIR}{domain}-IPs-from-ASNs-{entryID}.txt'
    cmd = """
    #!/bin/bash
    # one-liner to convert ASN to ip addresses. Results will be appended to `ips.out`. sander@cedsys.nl | 1-7-2017
    # requires: apt-get install prips

    touch """+outputFile+"""
    for asn in """+ASN+"""; #AS30548 - for Aruba;
        do $(for range in $(echo $(whois -h whois.radb.net -- "-i origin $asn" | grep -Eo "([0-9.]+){4}/[0-9]+") | sed ':a;N;$!ba;s/\\n/ /g'); 
            do prips $range >> """+outputFile+"""; 
        done);
    done
    """
    executeCMD(cmd)
    return outputFile

def getIPsFromAliveTargets(inputFile):
    IPAdresses = []
    with open(str(inputFile), 'r') as file:
        domains = list(set(file.readlines()))
    for domain in domains:
        domain = domain.replace('https://', '').replace('http://', '').replace(' ', '')
        ip = getIPAddress(domain)
        IPAdresses.append(ip)
    return IPAdresses

def checkValidASNumbers(ASNumbers):
    validASNumbers = []
    for ASN in ASNumbers:
        ASNDataContent = getContentsOfURL(str('https://bgp.he.net/'+ASN))
        if 'Prefixes Originated (v4): 0' not in ASNDataContent:
            if 'has not been visible in the global routing table since' not in ASNDataContent:
                validASNumbers.append(ASN)
    return validASNumbers

def getASNFromIPs(IPAdresses):
    # Implemented this: https://www.team-cymru.com/ip-asn-mapping
    ASNumbers = []
    for ip in IPAdresses:
        cmd = f'whois -h whois.cymru.com " -v {str(ip)}"'
        output = executeCMD(cmd)
        output = output.split('\n')

        information = output[0]
        data = output[1]
        data = data.split('|')

        cleanedData = []
        for entry in data:
            entry = entry.strip()
            cleanedData.append(entry)

        ASNumber = cleanedData[0]
        ASNumbers.append(ASNumber)
    ASNumbers = list(set(ASNumbers))
    return ASNumbers

def generateSubdomainWordlist(inputFile):
    subdomain_pattern = r'\b([a-zA-Z0-9-]+)(?=\.)'
    nonCleanSubdomains = []
    with open(inputFile, 'r') as file:
        for domain in file:
            subdomains = re.findall(subdomain_pattern, domain)
            for word in subdomains:
                nonCleanSubdomains.append(word)
    uniqueSubdomains = list(set(nonCleanSubdomains))
    return uniqueSubdomains

def sanitizeInput(string):
    semiSafeString = string.replace('http', '').replace('https', '').replace(':', '').replace(' ', '')
    dangerousCharacters = [
        '"', "'", '`', '!', '#', '$', 
        '<', '>', ';', '(', ')', '[', 
        ']', '%', '&', '{', '}', '@',
        '-', '|', '*', '^', ',', '=',
        '/', '\\']
    for character in dangerousCharacters:
        safeString = semiSafeString.replace(character, '')
    return safeString

def convertListToString(string):
    string = str(string).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
    return string