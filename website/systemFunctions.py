from os.path import join, dirname, realpath
import uuid
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