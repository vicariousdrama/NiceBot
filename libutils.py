#!/usr/bin/env python3
import bech32
import datetime
import os
import sys

def bech32ToHex(bech32Input):
    hrp, e2 = bech32.bech32_decode(bech32Input)
    if hrp is None: return ""
    tlv_bytes = bech32.convertbits(e2, 5, 8)[:-1]
    if len(tlv_bytes) > 32:
        tlv_length = tlv_bytes[1]
        tlv_value = tlv_bytes[2:tlv_length+2]
        hexOutput = bytes(tlv_value).hex()
    else:
        hexOutput = bytes(tlv_bytes).hex()
    return hexOutput

def hexToBech32(hexInput, hrp):
    b = bytes.fromhex(hexInput)
    bits = bech32.convertbits(b,8,5)
    bech32output = bech32.bech32_encode(hrp, bits)
    return bech32output

def isHex(s):
    return set(s).issubset(set('abcdefABCDEF0123456789'))

def normalizeToBech32(v, hrp):
    # v can be hex of length 64, or bech32
    if v == "0": v = ""
    if str(v).startswith("nostr:"): v = v[6:]
    if len(v) > 0:
        if str(v).startswith("n"):
            v = bech32ToHex(v)
        if isHex(v) and len(v) == 64:
            return hexToBech32(v, hrp)
    return None

def normalizeToHex(v):
    if len(v) == 0: return ""
    if str(v).startswith("n"): v = bech32ToHex(v)
    if isHex(v): return v
    return None

def getCommandArg(p):
    b = False
    v = None
    l = str(p).lower()
    for a in sys.argv:
        if b:
            v = a
            b = False
        elif f"--{l}" == str(a).lower():
            b = True
    return v

def getTimes(aDate=None):
    theDate = aDate
    if aDate is None: theDate = datetime.datetime.now() # utcnow()
    secTime = int(theDate.timestamp())
    isoTime = theDate.utcfromtimestamp(theDate.timestamp()).isoformat(timespec="seconds")
    return secTime, isoTime    

def getMidnight():
    theDate = datetime.datetime.now()
    midnight = theDate.replace(hour=0, minute=0, second=0, microsecond=0)
    secTime = int(midnight.timestamp())
    return secTime

def makeFolderIfNotExists(path):
    if not os.path.exists(path): os.makedirs(path)

def getListFieldCount(list, fieldname, value=None):
    count = 0
    for item in list:
        if type(list) is dict:
            v = list[item]
            if type(v) is dict:
                if fieldname in v:
                    if value is None: count += 1
                    elif v[fieldname] == value: count += 1
        if type(item) is dict:
            if fieldname in item:
                if value is None: count += 1
                elif item[fieldname] == value: count += 1
        if isinstance(item, type([])):
            if fieldname in item: count += 1
    return count