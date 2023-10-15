from . import db, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, ADMIN, DEBUG_ENABLED, MIN_NUMBER_FILEGENERATOR, MAX_NUMBER_FILEGENERATION, 
from . import SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, GENERATED_OUTPUT_DIRECTORY, SUBDOMAIN_SCAN_OUTPUT_DIRECTORY, PORT_SCAN_OUTPUT_DIRECTORY, VULNERABILITY_SCAN_OUTPUT_DIRECTORY
from .models import User, Scan, Vulnerability

def addScanFileDB(entryID, file):
    Scan.query.filter_by(entryID=entryID).first().resultFiles = str(Scan.query.filter_by(entryID=entryID).first().resultFiles) + ' ' + str(file)
    db.session.commit()

def addVulnerabilityFileDB(entryID, file):
    Vulnerability.query.filter_by(entryID=entryID).first().resultFiles = str(Vulnerability.query.filter_by(entryID=entryID).first().resultFiles) + ' ' + str(file)
    db.session.commit()