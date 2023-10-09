from os.path import join, dirname, realpath
import os

# Execute system command and return the output of the call.
def executeCMD(cmd):
    execute = os.popen(cmd)
    outputData = execute.read()
    execute.close()
    return outputData
