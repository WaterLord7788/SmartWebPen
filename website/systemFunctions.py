from os.path import join, dirname, realpath
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