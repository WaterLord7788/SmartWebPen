from os.path import join, dirname, realpath
import socket
import uuid
import os

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
    