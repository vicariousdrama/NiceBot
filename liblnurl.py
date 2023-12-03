#!/usr/bin/env python3
import json
import requests
import urllib.parse

logger = None
config = None

def gettimeouts():
    connectTimeout = 5
    readTimeout = 30
    if "connectTimeout" in config: connectTimeout = config["connectTimeout"]
    if "readTimeout" in config: readTimeout = config["readTimeout"]
    return (connectTimeout, readTimeout)

def gettorproxies():
    # with tor service installed, default port is 9050
    # to find the port to use, can run the following
    #     cat /etc/tor/torrc | grep SOCKSPort | grep -v "#" | awk '{print $2}'
    return {'http': 'socks5h://127.0.0.1:9050','https': 'socks5h://127.0.0.1:9050'}

def geturl(useTor=True, url=None, defaultResponse="{}", headers={}, description=None):
    try:
        proxies = gettorproxies() if useTor else {}
        timeout = gettimeouts()
        resp = requests.get(url,timeout=timeout,allow_redirects=True,proxies=proxies,headers=headers,verify=True)
        cmdoutput = resp.text
        return json.loads(cmdoutput)
    except Exception as e:
        if description is not None: logger.info(description)
        logger.warning(f"Error getting data from LN URL Provider from url ({url}): {str(e)}")
        return json.loads(defaultResponse)
    
def getLNURLPayInfo(identity):
    identityParts = identity.split("@")
    if len(identityParts) != 2: 
        return None, None
    username = identityParts[0]
    domainname = identityParts[1]
    useTor = False
    protocol = "https"
    if domainname.endswith(".onion"): 
        protocol = "http"
        useTor = True
    url = f"{protocol}://{domainname}/.well-known/lnurlp/{username}"
    j = geturl(useTor, url, "{}", {}, "Get LNURL Pay Info")
    return j, url

def isDomainAllowed(domainname):
    if "allowProviders" in config:
        allowed = config["allowProviders"]
        if len(allowed) > 0 and domainname not in allowed:
            return False
    if "denyProviders" in config:
        denied = config["denyProviders"]
        if len(denied) > 0 and domainname in denied:
            return False
    return True

def isLNURLProviderAllowed(identity):
    if identity is None: return False
    identityParts = identity.split("@")
    if len(identityParts) != 2: return False
    domainname = identityParts[1]
    return isDomainAllowed(domainname)

def isLNURLCallbackAllowed(callback):
    if callback is None: return False
    parseresult = urllib.parse.urlparse(callback)
    domainname = parseresult.netloc
    return isDomainAllowed(domainname)

def getInvoiceFromZapRequest(callback, satsToZap, zapRequest, bech32lnurl):
    logger.debug(f"Requesting invoice from LNURL service using zap request")
    encoded = getEncodedZapRequest(zapRequest)
    amountMillisatoshi = satsToZap*1000
    useTor = False
    if ".onion" in callback: useTor = True
    if "?" in callback:
        url = f"{callback}&"
    else:
        url = f"{callback}?"
    url = f"{url}amount={amountMillisatoshi}&nostr={encoded}&lnurl={bech32lnurl}"
    j = geturl(useTor, url, "{}", {}, "Get Invoice from LN Url Provider")
    return j

def getEncodedZapRequest(zapRequest):
    o = {
            "id": zapRequest.id,
            "pubkey": zapRequest.public_key,
            "created_at": zapRequest.created_at,
            "kind": zapRequest.kind,
            "tags": zapRequest.tags,
            "content": zapRequest.content,
            "sig": zapRequest.signature,
        }
    jd = json.dumps(o)
    encoded = urllib.parse.quote(jd)
    return encoded

def isValidInvoiceResponse(invoiceResponse):
    if "status" in invoiceResponse:
        if invoiceResponse["status"] == "ERROR":
            errReason = "unreported reason"
            if "reason" in invoiceResponse: errReason = invoiceResponse["reason"]
            logger.warning(f"Invoice request error: {errReason}")
            return False
    if "pr" not in invoiceResponse: return False
    return True

def isValidInvoiceAmount(decodedInvoice, amountToZap):
    logger.debug(f"Checking if invoice is valid")
    amountMillisatoshi = amountToZap*1000
    if not all(k in decodedInvoice for k in ("num_satoshis","num_msat")): 
        logger.warning(f"Invoice did not set amount")
        return False
    num_satoshis = int(decodedInvoice["num_satoshis"])
    if num_satoshis != amountToZap:
        logger.warning(f"Invoice amount ({num_satoshis}) does not match requested amount ({amountToZap}) to zap")
        return False
    num_msat = int(decodedInvoice["num_msat"])
    if num_msat != amountMillisatoshi:
        logger.warning(f"Invoice amount of msats ({num_msat}) does not match requested amount ({amountMillisatoshi}) to zap")
        return False
    return True
