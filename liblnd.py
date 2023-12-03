#!/usr/bin/env python3
from urllib3.exceptions import InsecureRequestWarning
import base64
import json
import os
import requests
import urllib
import libfiles as files
import libnostr as nostr
import libutils as utils
import libledger as ledger

# suppress warnings as verify will be set to false for self-signed nodes
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logger = None
config = None
activeConfig = None

def getLNDServerConfig():
    global activeConfig
    if activeConfig is not None: return activeConfig
    if not all(k in config for k in ("activeServer","servers")): activeConfig = dict(config); return activeConfig
    activeServerId = config["activeServer"]
    if activeServerId is None: activeConfig = dict(config); return activeConfig
    servers = config["servers"]
    if activeServerId not in servers: activeConfig = dict(config); return activeConfig
    activeServer = servers[activeServerId]
    if all(k in activeServer for k in ("address","port","macaroon")): activeConfig = dict(activeServer); return activeConfig
    return config

def getLNDUrl(suffix):
    lndServerConfig = getLNDServerConfig()
    serverAddress = lndServerConfig["address"]
    serverPort = lndServerConfig["port"]
    url = f"https://{serverAddress}:{serverPort}{suffix}"
    return url

def getLNDHeaders():
    lndServerConfig = getLNDServerConfig()
    serverMacaroon = lndServerConfig["macaroon"]
    headers = {
        "Grpc-Metadata-macaroon": serverMacaroon,
        "Connection": "close"
        }
    return headers

def getLNDTimeouts():
    lndServerConfig = getLNDServerConfig()
    connectTimeout = 5
    readTimeout = 30
    if "connectTimeout" in lndServerConfig: connectTimeout = lndServerConfig["connectTimeout"]
    if "readTimeout" in lndServerConfig: readTimeout = lndServerConfig["readTimeout"]
    return (connectTimeout, readTimeout)

def getLNDProxies():
    lndServerConfig = getLNDServerConfig()
    if str(lndServerConfig["address"]).endswith(".onion"):
        return {'http': 'socks5h://127.0.0.1:9050','https': 'socks5h://127.0.0.1:9050'}
    else:
        return {}

def restLndGET(suffix):
    try:
        url = getLNDUrl(suffix)
        timeout = getLNDTimeouts()
        proxies = getLNDProxies()
        headers = getLNDHeaders()
        # Call it, non streaming
        response = requests.get(url=url,timeout=timeout,proxies=proxies,headers=headers,verify=False)
        response.status_code 
        output = response.text
        return json.loads(output)
    except Exception as e:
        logger.warning(f"Error retrieving data from LND for {suffix}: {e}")
        return None

def restLndPOST(suffix, lndPostData):
    try:
        url = getLNDUrl(suffix)
        timeout = getLNDTimeouts()
        proxies = getLNDProxies()
        headers = getLNDHeaders()
        # Call it, non streaming
        response = requests.post(url=url,data=json.dumps(lndPostData),timeout=timeout,proxies=proxies,headers=headers,verify=False)
        response.status_code 
        output = response.text
        return json.loads(output)
    except Exception as e:
        logger.warning(f"Error retrieving data from LND for {suffix}: {e}")
        return None

def createInvoice(amount=21000, memo=None, expiry=86400):
    # need to set r_preimage: The hex-encoded preimage (32 byte) which 
    # will allow settling an incoming HTLC payable to this preimage. 
    # When using REST, this field must be encoded as base64.
    r_preimage_bytes = os.urandom(32)
    r_preimage_base64_bytes = base64.b64encode(r_preimage_bytes)
    r_preimage_base64_message = r_preimage_base64_bytes.decode('ascii')
    data = {
        "memo": memo,
        "r_preimage": r_preimage_base64_message,
        "value": amount,
        "expiry": expiry
    }
    suffix = f"/v1/invoices"
    result = restLndPOST(suffix, data)
    if result is not None:
        if "message" in result:
            message = result["message"]
            if message == "permission denied":
                logger.warning("LND reports Permission Denied to create invoice. Check macaroon permissions")
                return None
    return result

# Returns invoice
def lookupInvoice(paymentHash):
    # Setup
    base64paymentHash = paymentHash
    if utils.isHex(paymentHash):
        base64paymentHash = base64.b64encode(bytes.fromhex(paymentHash))
    base64decoded = base64.b64decode(base64paymentHash)
    base64encodedurlsafe = base64.urlsafe_b64encode(base64decoded)
    base64paymentHash = urllib.parse.quote(base64encodedurlsafe)
    suffix = f"/v2/invoices/lookup?payment_hash={base64paymentHash}"
    return restLndGET(suffix)

def decodeInvoice(paymentRequest):
    suffix = f"/v1/payreq/{paymentRequest}"
    return restLndGET(suffix)

# Returns payment status and fee_msat paid
def trackPayment(paymentHash):
    # Setup
    base64paymentHash = base64.urlsafe_b64encode(bytes.fromhex(paymentHash))
    base64paymentHash = urllib.parse.quote(base64paymentHash)
    suffix = f"/v2/router/track/{base64paymentHash}?no_inflight_updates=True"
    url = getLNDUrl(suffix)
    timeout = getLNDTimeouts()
    proxies = getLNDProxies()
    headers = getLNDHeaders()
    status = None
    fee_msat = None
    json_response = None
    response = None
    try:
        response = requests.get(url=url,stream=True,timeout=timeout,proxies=proxies,headers=headers,verify=False)
        for raw_response in response.iter_lines():
            json_response = json.loads(raw_response)
            if "result" in json_response: json_response = json_response["result"]
            if "message" in json_response:
                message = json_response["message"]
                logger.info(f"message: {message}")
            if "status" not in json_response:
                return "NOTFOUND", fee_msat
            status = json_response["status"]
            if status == "FAILED":
                failureReason = "unknown failure reason"
                if "failure_reason" in json_response:
                    failureReason = json_response["failure_reason"]
                logger.warning(f"{status}:{failureReason}")
            if "fee_msat" not in json_response:
                return status, fee_msat
            fee_msat = int(json_response["fee_msat"])
            return status, fee_msat
    except Exception as rte: # (ConnectionError, TimeoutError, ReadTimeoutError) as rte:
        logger.warning(f"Error tracking payment: {str(rte)}")
        if json_response is not None: logger.debug(json_response)
        return "TIMEOUT", fee_msat
    finally:
        try:
            if response is not None: response.close()
        except Exception as e:
            logger.warning(f"Error closing connection in trackPayment: {str(e)}")
    return status, fee_msat

def payInvoice(paymentRequest):
    lndServerConfig = getLNDServerConfig()
    logger.debug(f"Paying invoice")
    feeLimit = 2
    paymentTimeout = 30
    if "feeLimit" in lndServerConfig: lndServerConfig["feeLimit"]
    if "paymentTimeout" in lndServerConfig: paymentTimeout = lndServerConfig["paymentTimeout"]
    suffix = "/v2/router/send"
    lndPostData = {
        "payment_request": paymentRequest,
        "fee_limit_sat": feeLimit,
        "timeout_seconds": paymentTimeout
    }
    url = getLNDUrl(suffix)
    timeout = getLNDTimeouts()
    proxies = getLNDProxies()
    headers = getLNDHeaders()
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    resultStatus = "UNKNOWNPAYING"
    resultFeeMSat = 0
    json_response = None
    payment_hash = None
    payment_index = None
    r = requests.post(url=url,stream=True,data=json.dumps(lndPostData),timeout=timeout,proxies=proxies,headers=headers,verify=False)
    try:
        for raw_response in r.iter_lines():
            json_response = json.loads(raw_response)
            if "result" in json_response: json_response = json_response["result"]
            newStatus = resultStatus
            if "status" in json_response:
                newStatus = json_response["status"]
            if "fee_msat" in json_response:
                resultFeeMSat = int(json_response["fee_msat"])
            if "payment_hash" in json_response:
                new_payment_hash = json_response["payment_hash"]
                if payment_hash is not None: 
                    if new_payment_hash != payment_hash:
                        logger.info(f"PAYMENT HASH changed from {payment_hash} to {new_payment_hash}")
                payment_hash = new_payment_hash
            if "payment_index" in json_response:
                payment_index = int(json_response["payment_index"])
            #if newStatus == resultStatus: continue
            resultStatus = newStatus
            if resultStatus == "SUCCEEDED":
                logger.debug(f" - {resultStatus}, routing fee paid: {resultFeeMSat} msat")
            elif resultStatus == "FAILED":
                failureReason = "unknown failure reason"
                if "failure_reason" in json_response:
                    failureReason = json_response["failure_reason"]
                logger.warning(f" - {resultStatus} : {failureReason}")
            elif resultStatus == "IN_FLIGHT":
                logger.debug(f" - {resultStatus}")
            else:
                logger.info(f" - {resultStatus}")
                logger.info(json_response)
    except Exception as rte: # (ConnectionError, TimeoutError, ReadTimeoutError) as rte:
        try:
            r.close()
        except Exception as e:
            logger.warning(f"Error closing connection after exception in payInvoice: {str(e)}")
        if json_response is not None: logger.debug(json_response)
        return "TIMEOUT", (feeLimit * 1000), payment_hash, payment_index
    r.close()
    return resultStatus, resultFeeMSat, payment_hash, payment_index

_invoices = None

def monitorInvoice(theInvoice):
    global _invoices
    if _invoices is None: _invoices = files.loadInvoices()
    _invoices.append(theInvoice)
    files.saveInvoices(_invoices)

def checkInvoices():
    global _invoices
    # currentInvoice["npub"] = npub
    # currentInvoice["created_at"] = created_at
    # currentInvoice["created_at_iso"] = created_at_iso
    # currentInvoice["amount"] = amount
    # currentInvoice["memo"] = memo
    # currentInvoice["expiry"] = expiry
    # currentInvoice["expiry_time"] = expiry_time_int
    # currentInvoice["expiry_time_iso"] = expiry_time_iso
    # currentInvoice["r_hash"] = newInvoice["r_hash"]
    # currentInvoice["payment_request"] = payment_request
    # currentInvoice["add_index"] = newInvoice["add_index"]
    if _invoices is None: _invoices = files.loadInvoices()
    if len(_invoices) == 0: return
    logger.debug("Checking outstanding invoices")
    openInvoices = []
    for invoice in _invoices:
        payment_hash = None
        if "r_hash" in invoice: payment_hash = invoice["r_hash"]
        if "payment_hash" in invoice: payment_hash = invoice["payment_hash"]
        npub = invoice["npub"]
        status = lookupInvoice(payment_hash)
        if status is None: 
            openInvoices.append(invoice) # consider still open, temp glitch?
            logger.warning(f"invoice for {npub} has no status. payment_hash for lookup is {payment_hash}")
            continue
        if "STATE" not in status and "state" not in status:
            openInvoices.append(invoice) # could be temp error?
            logger.warning(f"invoice for {npub} does not have a STATE. payment_hash for lookup is {payment_hash}")
            logger.warning(f"response of lookupInvoice: ")
            logger.warning(json.dumps(obj=status,indent=2))
            continue
        state = 0
        if "state" in status: state = status["state"]
        if state == "OPEN":
            # keep considering as outstanding
            logger.debug(f"invoice for npub {npub} still open")
            openInvoices.append(invoice)
        elif state == "SETTLED":
            logger.debug(f"invoice for npub {npub} reported as settled")
            handlePaidInvoice(invoice)
        elif state == "CANCELED":
            logger.debug(f"invoice for npub {npub} has been canceled")
            handleCanceledInvoice(invoice)
        elif state == "ACCEPTED":
            # keep considering as outstanding
            logger.debug(f"invoice for npub {npub} accepted, not yet settled")
            openInvoices.append(invoice)
        else:
            logger.warning(f"invoice for {npub} has unrecognized state ({state}). payment_hash for lookup is {payment_hash}")
            logger.warning(f"response of lookupInvoice: ")
            logger.warning(json.dumps(obj=status,indent=2))
    if len(_invoices) != len(openInvoices):
        _invoices = openInvoices
        files.saveInvoices(openInvoices)

def handlePaidInvoice(invoice):
    npub = invoice["npub"]
    amount = invoice["amount"]
    # Description
    message = f"Invoice paid. {amount} credits have been applied to your account"
    # Credit account
    ledger.recordEntry(npub, "CREDITS APPLIED", amount, 0, message)
    # DM user that invoice was paid
    nostr.sendDirectMessage(npub, message)
    # Clear current invoice from nostr config for pub
    nostr.setNostrFieldForNpub(npub, "currentInvoice", {})
    # Clear warning sent to allow it to trigger again when balance is low
    nostr.setNostrFieldForNpub(npub, "balanceWarningSent", None)

def handleCanceledInvoice(invoice):
    npub = invoice["npub"]
    amount = invoice["amount"]
    message = f"Invoice for {amount} was canceled"
    # Credit account
    ledger.recordEntry(npub, "INVOICE CANCELED", 0, 0, message)
    # DM user that invoice was canceled
    nostr.sendDirectMessage(npub, message)
    # Clear current invoice from nostr config for pub
    nostr.setNostrFieldForNpub(npub, "currentInvoice", {})

def getPaymentDestinationFilename():
    filename = f"{files.dataFolder}paymentdestination.json"
    return filename

def recordPaymentDestination(decodedInvoice):
    if not all(k in decodedInvoice for k in ("destination","num_satoshis","num_msat")): 
        return
    destination_pubkey = decodedInvoice["destination"]
    num_satoshis = int(decodedInvoice["num_satoshis"])
    _, diso = utils.getTimes()
    diso = diso[0:10]
    filename = getPaymentDestinationFilename()
    pddata = files.loadJsonFile(filename, {})
    d = {}
    if diso in pddata.keys(): d = pddata[diso]
    dpk = {"qty":0, "amount": 0}
    if destination_pubkey in d.keys(): dpk = d[destination_pubkey]
    dpk["qty"] = dpk["qty"] + 1
    dpk["amount"] = dpk["amount"] + num_satoshis
    d[destination_pubkey] = dpk
    pddata[diso] = d
    files.saveJsonFile(filename, pddata)
