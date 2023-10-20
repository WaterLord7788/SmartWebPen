from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from os.path import join, dirname, realpath
from . import PING_COUNT_NUMBER
from .systemFunctions import *
import datetime
import requests
import asyncio
import random
import json
import os


def amass(domain, entryID, S_DIR, timeout=10):
    delaySeconds = int(timeout)*60
    outputFile = f'{S_DIR}{domain}-amass-{entryID}.txt'
    cmd = f'touch {outputFile} && timeout {delaySeconds} amass enum -active -brute -d {domain} > {outputFile}'
    executeCMD(cmd)
    return outputFile


def subfinder(domain, entryID, S_DIR):
    outputFile = f'{S_DIR}{domain}-subfinder-{entryID}.txt'
    cmd = f'subfinder -all -d {domain} -o {outputFile} -rl 10 -silent'
    executeCMD(cmd)
    return outputFile


def gau(domain, entryID, S_DIR):
    outputFile = f'{S_DIR}{domain}-gau-{entryID}.txt'
    cmd = f'printf {domain} | gau --subs --blacklist png,jpg,css,js | unfurl domains | sort -u | tee {outputFile}'
    executeCMD(cmd)
    return outputFile


def waybackurls(domain, entryID, S_DIR, stage):
    if stage == 'onlySubdomains':
        outputFile = f'{S_DIR}{domain}-waybackurls-{entryID}.txt'
        cmd = f'waybackurls {domain} | unfurl domains | sort -u | tee {outputFile}'
        executeCMD(cmd)
    elif stage == 'everything':
        outputFile = f'{S_DIR}{domain}-waybackurls+raw-{entryID}.txt'
        cmd = f'waybackurls {domain} | sort -u | tee {outputFile}'
        executeCMD(cmd)
    return outputFile


def crtsh(domain, entryID, S_DIR):
    outputFile = f'{S_DIR}{domain}-crt.sh-{entryID}.txt'
    cmd = f"curl -s 'https://crt.sh/?q={domain}&output=json' | jq -r '.[].common_name' | sed 's/\*//g' | sort -u | tee {outputFile}"
    executeCMD(cmd);  
    return outputFile


def waymore(domain, entryID, S_DIR):
    allOutputFiles = []

    outputDirectory = f'{S_DIR}{domain}-waymore/'
    resultFile = f'{S_DIR}{domain}-waymore-{entryID}.txt'
    cmd = f'python3 waymore/waymore.py -i {domain} -mode B -oR {outputDirectory} &>/dev/null && cp {outputDirectory}/waymore.txt {resultFile}'
    executeCMD(cmd)

    allOutputFiles.append(outputDirectory)
    allOutputFiles.append(resultFile)
    return allOutputFiles


def gofinder(domain, entryID, S_DIR, depth=5):
    outputFile = f'{S_DIR}{domain}-gofinder-{entryID}.txt'
    cmd = f'gospider -s {domain} --depth {depth} | tee {outputFile}'
    executeCMD(cmd)
    return outputFile


def xLinkFinder(domain, entryID, S_DIR):
    return


def checkAliveSubdomains(domain, entryID, S_DIR, moreDetails):
    if moreDetails == False:
        outputFile = f'{S_DIR}{domain}-alive-{entryID}.txt'
        cmd = f'cat {S_DIR}{domain}-*-{entryID}.txt | unfurl format %d | sort -u | httpx -no-color -silent | sort -u | tee {outputFile}'
        executeCMD(cmd)

    else:
        outputFile = f'{S_DIR}{domain}-alive+stats-{entryID}.txt'
        flags = '-title -cl -sc -tech-detect -web-server -fr -server -no-color -silent -web-server -asn -threads 50'
        cmd = f'cat {S_DIR}{domain}-*-{entryID}.txt | unfurl format %d | sort -u | httpx {flags} | sort -u | tee {outputFile}'
        executeCMD(cmd)

    return outputFile


def useScreenshotting(domain, entryID, S_DIR, V_DIR, threads, delay):
    allOutputFiles = []
    date = datetime.date.today()
    domains = f'{S_DIR}{domain}-alive-{entryID}.txt'
    reportDirectory = f'{S_DIR}{domain}-report/'
    screenshotsDirectory = f'{S_DIR}{domain}-report/screens/'
    eyewitnessCmd = f'eyewitness -f {domains} --threads {threads} --jitter 2 --delay 1 --web --max-retries 3 --no-prompt --selenium-log-path=/dev/null'

    cmd = f"""
    mkdir {reportDirectory}
    mkdir {screenshotsDirectory}
    {eyewitnessCmd}
    mv {date}*/screens/*.png {screenshotsDirectory}
    mv {date}*/report*.html {reportDirectory}
    rm {date}*/ -r
    rm geckodriver.log
    """.format(
        screenshotsDirectory=screenshotsDirectory,
        reportDirectory=reportDirectory,
        eyewitnessCmd=eyewitnessCmd,
        date=date
    )
    executeCMD(cmd)

    allOutputFiles.append(screenshotsDirectory)
    allOutputFiles.append(reportDirectory)
    return allOutputFiles


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
        outputFile = getIPsFromASN(domain, ASN, entryID, S_DIR)
    return outputFile


def checkExposedPorts(domain, entryID, S_DIR, includeASN=False):
    # Implemented: https://m7arm4n.medium.com/default-credentials-on-sony-swag-time-8e35681ad39e
    cmd = """
    #!/bin/bash
    for sub in $(cat {inputFile}); 
        do naabu -host $sub -p "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389" -exclude-ports 80,443,21,25,22 -silent >> {outputFile};
    done
    """

    if includeASN == False:
        outputFile = f'{S_DIR}{domain}-exposed-ports-of-alive-{entryID}.txt'
        inputFile = f'{S_DIR}{domain}-alive-{entryID}.txt'
        cmd = cmd.format(inputFile=inputFile, outputFile=outputFile)
        executeCMD(cmd)
        return outputFile
    
    outputFile = f'{S_DIR}{domain}-exposed-ports-of-IPs-{entryID}.txt'
    inputFile = f'{S_DIR}{domain}-IPs-from-ASNs-{entryID}.txt'
    cmd = cmd.format(inputFile=inputFile, outputFile=outputFile)
    executeCMD(cmd)

    return outputFile
    

def checkVulnerableParameters(domain, entryID, S_DIR, sensitiveVulnerabilityType):
    outputFile = f'{S_DIR}{domain}-params-{sensitiveVulnerabilityType}-{entryID}.txt'
    cmd = f'cat {S_DIR}{domain}-*-{entryID}.txt | unfurl format %d | sort -u | gf {sensitiveVulnerabilityType} | tee -a {outputFile}'
    executeCMD(cmd)
    return outputFile


def interestingSubsAlive(domain, entryID, S_DIR):
    outputFile = f'{S_DIR}{domain}-params-interestingsubs-alive-{entryID}.txt'
    cmd = f'cat {S_DIR}{domain}-params-interestingsubs-{entryID}.txt | unfurl format %d | httpx -no-color -silent | sort -u | tee {outputFile}'
    executeCMD(cmd)
    return outputFile


def noncommonResponseCodes(domain, entryID, S_DIR, V_DIR):
    return


def sensitiveKeywords(domain, entryID, S_DIR, V_DIR):
    return


def CRLF(domain, entryID, S_DIR, V_DIR):
    outputFile = f'{V_DIR}{domain}-crlf-{entryID}.txt'
    cmd = f'cat {S_DIR}{domain}-alive-{entryID}.txt | while read -r line; do echo && echo $line/%0D%0A%20Set-Cookie:%20testingForCRLF=true && curl -s -I -X GET $line/%0D%0A%20Set-Cookie:%20testingForCRLF=true && echo $line/%E5%98%8D%E5%98%8Set-Cookie:%20testingForCRLF=true && curl -s -I -X GET $line/%E5%98%8D%E5%98%8Set-Cookie:%20testingForCRLF=true && echo ; done | tee {outputFile}'
    executeCMD(cmd)
    return outputFile


def XSS(domain, entryID, S_DIR, V_DIR):
    outputFile = f'{V_DIR}{domain}-xss-{entryID}.txt'
    cmd = f'dalfox file {S_DIR}{domain}-alive-{entryID}.txt --only-poc="g,r,v" --skip-mining-dict -S --no-color | tee {outputFile}'
    executeCMD(cmd)
    return outputFile


def SQLi(domain, entryID, S_DIR, V_DIR):
    return


def nuclei(domain, entryID, S_DIR, V_DIR):
    outputFile = f'{V_DIR}{domain}-nuclei-{entryID}.txt'
    cmd = f'nuclei -l {S_DIR}{domain}-alive-{entryID}.txt -es info -silent -rl 80 -o {outputFile}'
    executeCMD(cmd)
    return outputFile


def retireJS(domain, entryID, S_DIR, V_DIR, willRunWaymore=False):
    if willRunWaymore == False: return None
    inputFolder = f'{S_DIR}{domain}-waymore/'
    outputFile = f'{V_DIR}{domain}-retireJS-{entryID}.txt'
    cmd = f'retire --path {inputFolder} --insecure | tee {outputFile}'
    executeCMD(cmd)
    return outputFile


def github(domain, entryID, S_DIR, V_DIR):
    return

def generateWordlist(domain, entryID, S_DIR, wordlist):
    if wordlist == 'subdomain':
        inputFile = f'{S_DIR}{domain}-alive-{entryID}.txt'
        uniqueSubdomains = generateSubdomainWordlist(inputFile)

        outputFile = f'{S_DIR}{domain}-subdomain-wordlist-{entryID}.txt'
        with open(outputFile, 'w') as file:
            for word in uniqueSubdomains:
                file.write(f'{word}\n')
        return outputFile


def nmap(domain, entryID, P_DIR, flags, HTMLReport):
    allOutputFiles =  []

    XMLOutputFile = f'{P_DIR}{domain}-nmap-{entryID}.xml'
    HTMLOutputFile = f'{P_DIR}{domain}-nmap-{entryID}.html'
    TXTOutputFile = f'{P_DIR}{domain}-nmap-{entryID}.txt'

    allOutputFiles.append(XMLOutputFile)
    allOutputFiles.append(HTMLOutputFile)

    if HTMLReport:
        cmd = f'nmap {flags} {domain} -oX {XMLOutputFile} | tee {TXTOutputFile} && xsltproc {XMLOutputFile} | tee {HTMLOutputFile}'
        print(cmd)
        executeCMD(cmd)
        return allOutputFiles
    
    cmd = f'nmap {flags} {domain} -oX {XMLOutputFile} | tee {TXTOutputFile}'
    print(cmd)
    executeCMD(cmd)
    return allOutputFiles
