#!/usr/bin/env python3
import json
import os
import shutil
import libutils as utils

logger = None       # set by calling setLogger

# Make common folders if not already present
dataFolder = "data/"
userConfigFolder = f"{dataFolder}userConfigs/"
userEventsFolder = f"{dataFolder}userEvents/"
userLedgerFolder = f"{dataFolder}userLedgers/"
userReportsFolder = f"{dataFolder}userReports/"
logFolder = f"{dataFolder}logs/"
utils.makeFolderIfNotExists(dataFolder)
utils.makeFolderIfNotExists(userConfigFolder)
utils.makeFolderIfNotExists(userEventsFolder)
utils.makeFolderIfNotExists(userLedgerFolder)
utils.makeFolderIfNotExists(userReportsFolder)
utils.makeFolderIfNotExists(logFolder)

def loadJsonFile(filename, default=None):
    if filename is None: return default
    if not os.path.exists(filename): return default
    with open(filename) as f:
        return(json.load(f))

def saveJsonFile(filename, obj):
    # first as temp file
    tempfile = f"{filename}.tmp"
    with open(tempfile, "w") as f:
        f.write(json.dumps(obj=obj,indent=2))
    # then move over top
    shutil.move(tempfile, filename)

def getConfig(filename):
    c = utils.getCommandArg("config") # allow overriding default filename
    if c is not None: filename = c
    logger.debug(f"Loading config from {filename}")
    if not os.path.exists(filename):
        logger.warning(f"Config file does not exist at {filename}")
        return {}
    return loadJsonFile(filename)    

def loadInvoices():
    filename = f"{dataFolder}outstandingInvoices.json"
    return loadJsonFile(filename, [])

def saveInvoices(outstandingInvoices):
    filename = f"{dataFolder}outstandingInvoices.json"
    saveJsonFile(filename, outstandingInvoices)

def listUserConfigs():
    return os.listdir(userConfigFolder)