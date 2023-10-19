from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, DEBUG_ENABLED, MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, GENERATED_OUTPUT_DIRECTORY, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, PORT_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from .models import User, Scan, Vulnerability, PortScan

def addScanFileDB(entryID, file):
    Scan.query.filter_by(entryID=entryID).first().resultFiles = str(Scan.query.filter_by(entryID=entryID).first().resultFiles) + ' ' + str(file)
    db.session.commit()

def addVulnFileDB(entryID, file):
    Vulnerability.query.filter_by(entryID=entryID).first().resultFiles = str(Vulnerability.query.filter_by(entryID=entryID).first().resultFiles) + ' ' + str(file)
    db.session.commit()

def cleanResultFilesDB(type, entryID):
    if type == 'Scan':
        resultFiles = Scan.query.filter_by(entryID=entryID).first().resultFiles
        resultFiles = str(resultFiles).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
        Scan.query.filter_by(entryID=entryID).first().resultFiles = resultFiles
    elif type == 'Vulnerability':
        resultFiles = Vulnerability.query.filter_by(entryID=entryID).first().resultFiles
        resultFiles = str(resultFiles).replace('[', '').replace(']', '').replace(',', '').replace("'", '')
        Vulnerability.query.filter_by(entryID=entryID).first().resultFiles = resultFiles
    db.session.commit()

def saveDB():
    db.session.commit()

def getResultFilesDB(type, entryID):
    if type == 'Scan':
        resultFiles = Scan.query.filter_by(entryID=entryID).first().resultFiles
        return resultFiles
    elif type == 'Vulnerability':
        resultFiles = Vulnerability.query.filter_by(entryID=entryID).first().resultFiles
        return resultFiles
    elif type == 'PortScan':
        resultFiles = PortScan.query.filter_by(entryID=entryID).first().resultFiles
        return resultFiles

def addPortScanFileDB(entryID, file):
    PortScan.query.filter_by(entryID=entryID).first().resultFiles = str(PortScan.query.filter_by(entryID=entryID).first().resultFiles) + ' ' + str(file)
    db.session.commit()