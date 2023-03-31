import os
import subprocess


def installTools():

    com_str = 'which dalfox'
    command = subprocess.Popen([com_str], stdout=subprocess.PIPE, shell=True)
    (output, error) = command.communicate()
    if 'dalfox' not in str(output):
        # Installing Dalfox
        print(); print('[*] Installing Dalfox')
        os.popen('go install github.com/hahwul/dalfox/v2@latest')
        print('[+] Done installing Dalfox!'); print()

    com_str = 'which waybackurls'
    command = subprocess.Popen([com_str], stdout=subprocess.PIPE, shell=True)
    (output, error) = command.communicate()
    if 'waybackurls' not in str(output):
        # Installing Waybackurls
        print('[*] Installing Waybackurls')
        os.popen('go install github.com/tomnomnom/waybackurls@latest')
        print('[+] Done installing Waybackurls!'); print()

    com_str = 'which amass'
    command = subprocess.Popen([com_str], stdout=subprocess.PIPE, shell=True)
    (output, error) = command.communicate()
    if 'amass' not in str(output):
        # Installing Amass
        print('[*] Installing Amass')
        os.popen('go install -v github.com/owasp-amass/amass/v3/...@master')
        print('[+] Done installing Amass!'); print()

    com_str = 'which subfinder'
    command = subprocess.Popen([com_str], stdout=subprocess.PIPE, shell=True)
    (output, error) = command.communicate()
    if 'subfinder' not in str(output):
        # Installing Subfinder
        print('[*] Installing Subfinder')
        os.popen('go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest')
        print('[+] Done installing Subfinder!'); print()

    com_str = 'which httpx'
    command = subprocess.Popen([com_str], stdout=subprocess.PIPE, shell=True)
    (output, error) = command.communicate()
    if 'httpx' not in str(output):
        # Installing httpx
        print('[*] Installing httpx')
        os.popen('go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest')
        print('[+] Done installing httpx!'); print()

installTools()