#!/usr/bin/env python3
import libfiles as files
import libutils as utils

def getUserLedgerFilename(npub):
    filename = f"{files.userLedgerFolder}{npub}.ledger.json"
    return filename

def getCreditBalance(npub):
    filename = getUserLedgerFilename(npub)
    ledger = files.loadJsonFile(filename)
    if ledger is None: return 0
    balance = int(ledger[-1]["balance"])
    return balance

def recordEntry(npub, type, credits, mcredits, description):
    filename = getUserLedgerFilename(npub)
    ledger = files.loadJsonFile(filename)
    if ledger is None: 
        # initialize first entry
        ledger = []
        balance = 0.000
        created_at, created_at_iso = utils.getTimes()
        firstEntry = {
            "created_at": created_at,
            "created_at_iso": created_at_iso,
            "type": "INITIALIZED",
            "credits": 0,
            "mcredits": 0,
            "balance": balance,
            "description": "Initialized Balance",
            }
        ledger.append(firstEntry)
    else:
        # get current balance from existing, last record
        balance = ledger[-1]["balance"]
    # Determine new balance based on amounts passed in
    balance += credits
    balance += (mcredits/1000)
    # Add the new entry
    created_at, created_at_iso = utils.getTimes()
    newEntry = {
        "created_at": created_at,
        "created_at_iso": created_at_iso,
        "type": type,
        "credits": credits,
        "mcredits": mcredits,
        "balance": balance,
        "description": description,
        }
    ledger.append(newEntry)
    # Save to disk
    files.saveJsonFile(filename, ledger)
    # Rotate if needed
    if len(ledger) > 500:
        rotateLedger(npub, ledger)
    # return new balance
    return balance

def rotateLedger(npub, ledger):
    # first save current contents to the archive
    archivedLedgerFolder = f"{files.userLedgerFolder}archived/"
    utils.makeFolderIfNotExists(archivedLedgerFolder)
    t, tISO = utils.getTimes()
    archivedFilename = f"{archivedLedgerFolder}{npub}.{t}.ledger.json"
    files.saveJsonFile(archivedFilename, ledger)
    # now get balance
    ledgerSummary = {
        "CREDITS APPLIED": {"credits": 0, "mcredits": 0},
        "REPLY MESSAGE": {"credits": 0, "mcredits": 0},
        "ZAPS": {"credits": 0, "mcredits": 0},
        "ROUTING FEES": {"credits": 0, "mcredits": 0},
        "SERVICE FEES": {"credits": 0, "mcredits": 0}
    }
    for ledgerEntry in ledger:
        type = ledgerEntry["type"]
        credits = ledgerEntry["credits"]
        mcredits = ledgerEntry["mcredits"]
        if type in ledgerSummary:
            ledgerSummary[type]["credits"] = ledgerSummary[type]["credits"] + credits
            ledgerSummary[type]["mcredits"] = ledgerSummary[type]["mcredits"] + mcredits
    newLedger = []
    balance = 0
    for ledgerSummaryType, ledgerSummaryItem in ledgerSummary.items():
        balance = balance + ledgerSummaryItem["credits"]
        balance = balance + (ledgerSummaryItem["mcredits"]/1000)
        newLedger.append({
            "created_at": t,
            "created_at_iso": tISO,
            "type": ledgerSummaryType,
            "credits": ledgerSummaryItem["credits"],
            "mcredits": ledgerSummaryItem["mcredits"],
            "balance": balance,
            "description": "Carry over from ledger rotation",
            })
    filename = getUserLedgerFilename(npub)
    files.saveJsonFile(filename, newLedger)
    
    
