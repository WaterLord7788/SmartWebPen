import bs4
import requests
import re

def getContentsOfURL(url):
    response = requests.get(url)
    content = response.text
    return content

def getElementsByCSSPath(content, CSSPath, elementNumber):
    soup = bs4.BeautifulSoup(content, features="lxml")
    elements = soup.select(CSSPath)
    rawDescription = str(elements[elementNumber-1]) # `number-1` because the third element but we need to start from 0 in programming. So, third = 3-1 = 2.
    return rawDescription

def cleanTextFromHTML(text):
    CLEAN = re.compile('<.*?>')
    cleanText = CLEAN.sub('', text)
    return cleanText

content = getContentsOfURL("https://bgp.he.net/ip/156.112.108.76")
# Need to get the value of the last `<td>` HTML element, therefore `elementNumber` = 3.
element = getElementsByCSSPath(content, CSSPath="html body div#content div#ipinfo.tabdata table tbody tr td", elementNumber=1)
description = cleanTextFromHTML(element)
print(description)