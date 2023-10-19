from os.path import join, dirname, realpath
import os

def checkForFolders(GENERATED_OUTPUT_DIRECTORY, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, PORT_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY):
    # Check availability of required folders
    if os.path.exists(SUBDOMAIN_SCAN_OUTPUT_DIRECTORY): 
        pass
    else: 
        print('[-] No subdomain scan output folder found!')
        print('[*] Creating the necessary folder.')
        os.system('mkdir '+GENERATED_OUTPUT_DIRECTORY+'')
        os.system('mkdir '+SUBDOMAIN_SCAN_OUTPUT_DIRECTORY+'')
    if os.path.exists(PORT_SCAN_OUTPUT_DIRECTORY): 
        pass
    else: 
        print('[-] No port scan output folder found!')
        print('[*] Creating the necessary folder.')
        os.system('mkdir '+PORT_SCAN_OUTPUT_DIRECTORY+'')
    if os.path.exists(VULNERABILITY_SCAN_OUTPUT_DIRECTORY): 
        pass
    else: 
        print('[-] No vulnerability scan output folder found!')
        print('[*] Creating the necessary folder.')
        os.system('mkdir '+VULNERABILITY_SCAN_OUTPUT_DIRECTORY+'')

    # Check required dependencies
    # To Do