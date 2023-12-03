#!/usr/bin/env python3
from nostr.key import PrivateKey, PublicKey
from nostr.event import Event, EventKind, EncryptedDirectMessage, AuthMessage
from nostr.filter import Filter, Filters
from nostr.message_type import ClientMessageType
from nostr.relay_manager import RelayManager
import bech32
import json
import random
import ssl
import time
import libfiles as files
import libutils as utils
import liblnurl as lnurl

logger = None
config = None
handledMessages = {}
handledEvents = {}
lightningIdCache = {}
_relayManager = None
_relayPublishTime = 2.50
_relayConnectTime = 1.25
_relayReconnectExisting = False     # when  true, locks up in r.check_reconnect
_privkey = None
_pubkey = None
_pubkeyhex = None

def getPrivateKey():
    global _privkey
    if _privkey is None: 
        if "nsec" not in config: 
            logger.warning("Config missing 'nsec' in nostr section.")
            quit()
        nsec = config["nsec"]
        if nsec is None or len(nsec) == 0:
            logger.warning("Config missing 'nsec' in nostr section.")
            quit()
        _privkey = PrivateKey().from_nsec(nsec)
    return _privkey

def getPubkey():
    global _pubkey
    global _pubkeyhex
    if _pubkey is None:
        privkey = getPrivateKey()
        _pubkey = privkey.public_key
        _pubkeyhex = _pubkey.hex()
    return _pubkey

def makeRelayManager(relays):
    newRelayManager = RelayManager()
    random.shuffle(relays)    
    relaysLeftToAdd = 50
    for nostrRelay in relays:
        relaysLeftToAdd -= 1
        if relaysLeftToAdd <= 0: break
        if type(nostrRelay) is dict:
            newRelayManager.add_relay(url=nostrRelay["url"],read=nostrRelay["read"],write=nostrRelay["write"])
        if type(nostrRelay) is str:
            newRelayManager.add_relay(url=nostrRelay)
    newRelayManager.open_connections({"cert_reqs": ssl.CERT_NONE}) # NOTE: This disables ssl certificate verification
    time.sleep(_relayConnectTime)
    return newRelayManager

def connectToRelays():
    logger.debug("Connecting to relays")
    global _relayManager
    relays = getNostrRelaysFromConfig(config).copy()
    _relayManager = makeRelayManager(relays)

def disconnectRelays():
    logger.debug("Disconnecting from relays")
    global _relayManager
    _relayManager.close_connections()

def reconnectRelays():
    if _relayReconnectExisting:
        for r in _relayManager.relays.values():
            logger.debug(f"Reconnecting relay {r.url}")
            r.check_reconnect()     # seems to cause a lockup
            logger.debug(f"- relay reconnection complete")
    else:
        disconnectRelays()
        connectToRelays()

def getNostrRelaysFromConfig(aConfig):
    relays = []
    relayUrls = []
    if "relays" in aConfig:
        for relay in aConfig["relays"]:
            relayUrl = ""
            canRead = True
            canWrite = True
            if type(relay) is str:
                relayUrl = relay
            if type(relay) is dict:
                if "url" not in relay: continue
                relayUrl = relay["url"]
                canRead = relay["read"] if "read" in relay else canRead
                canWrite = relay["write"] if "write" in relay else canWrite
            relayUrl = relayUrl if str(relayUrl).startswith("wss://") else f"wss://{relayUrl}"
            if relayUrl not in relayUrls:
                relayUrls.append(relayUrl)
                relays.append({"url":relayUrl,"read":canRead,"write":canWrite})
    return relays

def removeSubscription(relaymanager, subid):
    request = [ClientMessageType.CLOSE, subid]
    message = json.dumps(request)
    relaymanager.publish_message(message)
    time.sleep(_relayPublishTime)
    relaymanager.close_subscription(subid)

def sendDirectMessage(fromPK, toUserNpubOrHex, message):
    if fromPK is None:
        logger.warning("Unable to send direct message to user.")
        logger.warning(f" - user: {toUserNpubOrHex}")
        logger.warning(f" - message: {message}")
        return
    if toUserNpubOrHex is None:
        logger.warning("Unable to send direct message to user (value is None).")
        logger.warning(f" - message: {message}")
        return
    recipient_pubkey = utils.normalizeToHex(toUserNpubOrHex)
    if "excludeFromDirectMessages" in config:
        excludes = config["excludeFromDirectMessages"]
        for exclude in excludes:
            if exclude["npub"] == toUserNpubOrHex:
                logger.debug("Not sending direct message to excluded: {toUserNpubOrHex}")
                return
            if exclude["npub"] == recipient_pubkey: 
                logger.debug("Not sending direct message to excluded pubkey: {recipient_pubkey}")
                return
    dm = EncryptedDirectMessage(
        recipient_pubkey=recipient_pubkey,
        cleartext_content=message
    )
    fromPK.sign_event(dm)
    _relayManager.publish_event(dm)
    time.sleep(_relayPublishTime)

def checkDirectMessages():
    global handledMessages          # tracked in this file, and only this function
    logger.debug("Checking messages")
    newMessages = []
    events = getDirectMessages()
    for event in events:
        # only add those not already in the handledMessages list
        if event.id not in handledMessages:
            newMessages.append(event)
            handledMessages[event.id] = event.created_at
    return newMessages

def isValidSignature(event): 
    sig = event.signature
    id = event.id
    publisherPubkey = event.public_key
    pubkey = PublicKey(raw_bytes=bytes.fromhex(publisherPubkey))
    return pubkey.verify_signed_message_hash(hash=id, sig=sig)

def getProfile(pubkeyHex):
    global _monitoredProfiles
    logger.debug(f"Getting profile information for {pubkeyHex}")
    filters = Filters([Filter(kinds=[EventKind.SET_METADATA],authors=[pubkeyHex])])
    privkey = getPrivateKey()
    t, _ = utils.getTimes()
    subscription_id = f"my_profiles_{t}"
    request = [ClientMessageType.REQUEST, subscription_id]
    request.extend(filters.to_json_array())
    message = json.dumps(request)
    _relayManager.add_subscription(subscription_id, filters)
    _relayManager.publish_message(message)
    time.sleep(_relayPublishTime)
    # Check if needed to authenticate and publish again if need be
    if authenticateRelays(_relayManager, privkey):
        _relayManager.publish_message(message)
        time.sleep(_relayPublishTime)
    # Sift through messages
    siftMessagePool()
    # Remove this subscription
    removeSubscription(_relayManager, subscription_id)
    # Find the profile
    profileToUse = None
    profileToReturn = None
    created_at = 0
    _monitoredProfilesTmp = []
    for profile in _monitoredProfiles:
        if profile.public_key != pubkeyHex:
            _monitoredProfilesTmp.append(profile)
            continue
        if profile.created_at < created_at: continue
        if not isValidSignature(profile): continue
        try:
            ec = json.loads(profile.content)
            created_at = profile.created_at
            profileToUse = profile
            profileToReturn = dict(ec)
        except Exception as err:
            logger.warning(f"Error while getting profile for {pubkeyHex}")
            logger.eception(err)
            continue
    if profileToUse is not None: _monitoredProfilesTmp.append(profileToUse)
    _monitoredProfiles = _monitoredProfilesTmp
    return profileToReturn, created_at

def getEventByID(eventHex):
    global _monitoredEvent
    logger.debug(f"Getting event information for {eventHex}")
    filters = Filters([Filter(event_ids=[eventHex])])
    events = []
    privkey = getPrivateKey()
    t, _ = utils.getTimes()
    subscription_id = f"my_eventbyid_{t}"
    request = [ClientMessageType.REQUEST, subscription_id]
    request.extend(filters.to_json_array())
    message = json.dumps(request)
    _relayManager.add_subscription(subscription_id, filters)
    _relayManager.publish_message(message)
    time.sleep(_relayPublishTime)
    # Check if needed to authenticate and publish again if need be
    if authenticateRelays(_relayManager, privkey):
        _relayManager.publish_message(message)
        time.sleep(_relayPublishTime)
    # Sift through messages
    siftMessagePool()
    # Remove this subscription
    removeSubscription(_relayManager, subscription_id)
    # Find the event
    _monitoredEventTmp = []
    for event in _monitoredEvent:
        if event.id == eventHex:
            events.append(event)
        else:
            _monitoredEventTmp.append(event)
    _monitoredEvent = _monitoredEventTmp                
    if len(events) > 0: return events[0]
    return None

def authenticateRelays(theRelayManager, pk):
    if not theRelayManager.message_pool.has_auths(): return False
    while theRelayManager.message_pool.has_auths():
        auth_msg = theRelayManager.message_pool.get_auth()
        logger.info(f"AUTH request received from {auth_msg.url} with challenge: {auth_msg.challenge}")
        am = AuthMessage(challenge=auth_msg.challenge,relay_url=auth_msg.url)
        pk.sign_event(am)
        logger.debug(f"Sending signed AUTH message to {auth_msg.url}")
        theRelayManager.publish_auth(am)
        theRelayManager.message_pool.auths.task_done()
    return True

_directMessageSince = None
_directMessages = []
_monitoredEvents = []
_monitoredPubkeys = []
_monitoredProfiles = []
_monitoredEvent = []
# This proc must understand all subscriptions
def siftMessagePool():
    global _directMessages
    global _monitoredEvents
    global _monitoredPubkeys
    global _monitoredProfiles
    global _monitoredEvent
    privkey = getPrivateKey()
    # AUTH
    authenticateRelays(_relayManager, privkey)
    # EVENT
    while _relayManager.message_pool.has_events():
        event_msg = _relayManager.message_pool.get_event()
        subid = event_msg.subscription_id
        if subid.startswith("my_dms"): _directMessages.append(event_msg.event)
        elif subid.startswith("my_events"): _monitoredEvents.append(event_msg.event)
        elif subid.startswith("my_pubkeys"): _monitoredPubkeys.append(event_msg.event)
        elif subid.startswith("my_profiles"): _monitoredProfiles.append(event_msg.event)
        elif subid.startswith("my_eventbyid"): _monitoredEvent.append(event_msg.event)
        else:
            u = event_msg.url
            c = event_msg.event.content
            logger.debug(f"Unexpected event from relay {u} with subscription {subid}: {c}")
        _relayManager.message_pool.events.task_done()
    # NOTICES
    while _relayManager.message_pool.has_notices():
        notice = _relayManager.message_pool.get_notice()
        message = f"RELAY NOTICE FROM {notice.url}: {notice.content}"
        logger.info(message)
        _relayManager.message_pool.notices.task_done()
    # EOSE NOTICES
    while _relayManager.message_pool.has_eose_notices():
        _relayManager.message_pool.get_eose_notice()
        _relayManager.message_pool.eose_notices.task_done()

def getDirectMessages():
    global _directMessageSince
    subscription_dm = "my_dms"
    if _directMessageSince is None:
        _directMessageSince, _ = utils.getTimes()
    newSubscriptionEachCall = True
    filtersince=None
    if newSubscriptionEachCall:
        t, _ = utils.getTimes()
        subscription_dm = f"{subscription_dm}_{t}"
        filtersince=t-300
    else:
        filtersince=_directMessageSince
    added = False
    privKey = getPrivateKey()
    pubkey = getPubkey()
    filters = Filters([Filter(since=filtersince,pubkey_refs=[pubkey],kinds=[EventKind.ENCRYPTED_DIRECT_MESSAGE])])
    # Check relays we've configured, adding subscription if not yet present
    for relayConfig in _relayManager.relays.values():
        found = False
        for subId in relayConfig.subscriptions.keys():
            if subId == subscription_dm: 
                found = True
                break
        if found: continue
        relayConfig.add_subscription(id=subscription_dm, filters=filters)
        added = True
    # If we added to any relay, publish it
    if added:
        request = [ClientMessageType.REQUEST, subscription_dm]
        request.extend(filters.to_json_array())
        message = json.dumps(request)
        _relayManager.publish_message(message)
        time.sleep(_relayPublishTime)
        # Check if needed to authenticate and publish again if need be
        if authenticateRelays(_relayManager, privKey):
            _relayManager.publish_message(message)
            time.sleep(_relayPublishTime)
    # Sift through messages
    siftMessagePool()
    # Remove this subscription if making new each time
    if newSubscriptionEachCall:
        removeSubscription(_relayManager, subscription_dm)
    # Return outstanding messages array
    return _directMessages

def getEventRepliesForId(eventHex):
    global _monitoredEvents
    subscription_events = "my_events"
    newSubscriptionEachCall = True
    filtersince=None
    if newSubscriptionEachCall:
        t, _ = utils.getTimes()
        subscription_events = f"{subscription_events}_{t}"
        filtersince=t-86400
    # Check relays we've configured, adding subscription if not yet present
    # or updating if eventHex not present
    privkey = getPrivateKey()
    added = False
    updated = False
    filters_events = None
    for relayConfig in _relayManager.relays.values():
        found = False
        for subId in relayConfig.subscriptions.keys():
            if subId == subscription_events: 
                found = True
                break
        if found: 
            hasEvent = False
            needToAdd = False
            filters_events = relayConfig.subscriptions[subscription_events].filters
            if filters_events is None: 
                needToAdd = True
            elif len(filters_events) == 0:
                needToAdd = True
            elif filters_events[0].event_refs is None:
                needToAdd = True
            elif eventHex in filters_events[0].event_refs:
                hasEvent = True
                break
            else:
                filters_events[0].event_refs.append(eventHex)            
            if needToAdd:
                filters_events = Filters([Filter(event_refs=[eventHex],kinds=[EventKind.TEXT_NOTE],since=filtersince)])
                relayConfig.add_subscription(id=subscription_events, filters=filters_events)
                added = True
            elif not hasEvent:
                relayConfig.update_subscription(id=subscription_events, filters=filters_events)
                updated = True
        else:
            filters_events = Filters([Filter(event_refs=[eventHex],kinds=[EventKind.TEXT_NOTE],since=filtersince)])
            relayConfig.add_subscription(id=subscription_events, filters=filters_events)
            added = True
    # Send request message if filter and subscription is new or updated
    if added or updated:
        request = [ClientMessageType.REQUEST, subscription_events]
        request.extend(filters_events.to_json_array())
        message = json.dumps(request)
        _relayManager.publish_message(message)
        time.sleep(_relayPublishTime)
        # Check if needed to authenticate and publish again if need be
        if authenticateRelays(_relayManager, privkey):
            _relayManager.publish_message(message)
            time.sleep(_relayPublishTime)
    # Sift through messages
    siftMessagePool()
    # Remove this subscription if making new each time
    if newSubscriptionEachCall:
        removeSubscription(_relayManager, subscription_events)
    # Get events for just this eventHex
    _replyEvents = []
    _monitoredEventsTmp = []
    for eventReply in _monitoredEvents:
        removeFromMonitored = False
        addToReturnList = False
        if not isValidSignature(eventReply):
            removeFromMonitored = True
        else:
            for tagItem in eventReply.tags:
                if len(tagItem) < 2: continue # exclude tags without values
                if tagItem[0] != 'e': continue # not event tag
                if tagItem[1] != eventHex: # not a reply for event we want
                    if addToReturnList:
                        addToReturnList = False # event tag multiple times
                        break
                    continue
                addToReturnList = True
                removeFromMonitored = True
        if addToReturnList:
            _replyEvents.append(eventReply)
        elif not removeFromMonitored:
            _monitoredEventsTmp.append(eventReply)
    _monitoredEvents = _monitoredEventsTmp
    return _replyEvents

# returns single event
def popEventMatchingFilter(filter: Filter):
    # filter = Filters([Filter(kind=34550,authors=[ownerPubkey])])
    # filter.add_arbitrary_tag("d", communityId)
    global _monitoredEvents    
    monitoredEventsTmp = []
    eventToReturn = None
    for eventReply in _monitoredEvents:
        removeFromMonitored = False
        if not isValidSignature(eventReply):
            removeFromMonitored = True
        else:
            if eventToReturn is None and filter.matches(eventReply):
                removeFromMonitored = True
                eventToReturn = eventReply
        if not removeFromMonitored:
            monitoredEventsTmp.append(eventReply)
    _monitoredEvents = monitoredEventsTmp
    return eventToReturn

# returns all events matching filter
def popEventsMatchingFilter(filter: Filter) -> list[Event]:
    global _monitoredEvents    
    monitoredEventsTmp = []
    eventsToReturn = []
    for eventReply in _monitoredEvents:
        if isValidSignature(eventReply):
            if filter.matches(eventReply):
                eventsToReturn.append(eventReply)
            else:
                monitoredEventsTmp.append(eventReply)
    _monitoredEvents = monitoredEventsTmp
    return eventsToReturn

def getEventsByPubkey(pubkeyHex):
    global _monitoredPubkeys
    subscription_pubkeys = "my_pubkeys"
    newSubscriptionEachCall = True
    filtersince=None
    if newSubscriptionEachCall:
        t, _ = utils.getTimes()
        subscription_pubkeys = f"{subscription_pubkeys}_{t}"
        filtersince=t-86400
    # Check relays we've configured, adding subscription if not yet present
    # or updating if eventHex not present
    privkey = getPrivateKey()
    added = False
    updated = False
    filters_pubkeys = None
    for relayConfig in _relayManager.relays.values():
        found = False
        for subId in relayConfig.subscriptions.keys():
            if subId == subscription_pubkeys: 
                found = True
                break
        if found: 
            hasPubkey = False
            filters_pubkeys = relayConfig.subscriptions[subscription_pubkeys].filters
            for filter in filters_pubkeys:
                if filter is None: continue
                if filter.authors is None:
                    filter.authors = [pubkeyHex]
                elif pubkeyHex in filter.authors:
                    hasPubkey = True
                    break
                else:
                    filter.authors.append(pubkeyHex)
            if not hasPubkey:
                relayConfig.update_subscription(id=subscription_pubkeys, filters=filters_pubkeys)
                updated = True
        else:
            filters_pubkeys = Filters([Filter(authors=[pubkeyHex],kinds=[EventKind.TEXT_NOTE],since=filtersince)])
            relayConfig.add_subscription(id=subscription_pubkeys, filters=filters_pubkeys)
            added = True
    # Send request message if filter and subscription is new or updated
    if added or updated:
        request = [ClientMessageType.REQUEST, subscription_pubkeys]
        request.extend(filters_pubkeys.to_json_array())
        message = json.dumps(request)
        _relayManager.publish_message(message)
        time.sleep(_relayPublishTime)
        # Check if needed to authenticate and publish again if need be
        if authenticateRelays(_relayManager, privkey):
            _relayManager.publish_message(message)
            time.sleep(_relayPublishTime)
    # Sift through messages
    siftMessagePool()
    # Remove this subscription if making new each time
    if newSubscriptionEachCall:
        removeSubscription(_relayManager, subscription_pubkeys)
    # Get events for just this pubkeyHex
    _replyEvents = []
    _monitoredPubkeysTmp = []
    for eventReply in _monitoredPubkeys:
        removeFromMonitored = False
        addToReturnList = False
        if eventReply.public_key == pubkeyHex:
            addToReturnList = True
            removeFromMonitored = True
        if addToReturnList: 
            _replyEvents.append(eventReply)
        elif not removeFromMonitored: 
            _monitoredPubkeysTmp.append(eventReply)
    _monitoredPubkeys = _monitoredPubkeysTmp
    return _replyEvents

# candidate for removal
def isMessageInReplies(replies, k, pubkey, replyMessage):
    for r in replies:
        if type(r) is str: continue
        if type(r) is dict:
            if "id" not in r: continue
            if "pubkey" not in r: continue
            if "message" not in r: continue
            if r["id"] != k: continue
            if r["pubkey"] != pubkey: continue
            if r["message"] != replyMessage: continue
            return True
    return False

def signAndSend(withPK, preparedEvent, customRelayManager=None):
    withPK.sign_event(preparedEvent)
    if customRelayManager is not None:
        customRelayManager.publish_event(preparedEvent)
    else:
        _relayManager.publish_event(preparedEvent)
    time.sleep(_relayPublishTime)

def replyToEvent(withPK, eventHex, content, customRelayManager=None):
    replyTags = [["e", eventHex]]
    replyEvent = Event(content=content,tags=replyTags)
    signAndSend(withPK, replyEvent, customRelayManager)

def reactToEvent(withPK, pubkeyHex, eventHex, content, customRelayManager=None):
    reactTags = []
    reactTags.append(["p",pubkeyHex])
    reactTags.append(["e",eventHex])
    reactEvent = Event(content=content,kind=7,tags=reactTags)
    signAndSend(withPK, reactEvent, customRelayManager)

# note, we sign this event but dont send to relays. instead, this should be encoded
# and sent to the LNURLP Callback to generate the invoice
def makeZapRequest(withPK, amountToZap, zapMessage, recipientPubkey, eventId, bech32lnurl):
    amountMillisatoshi = amountToZap*1000
    zapTags = []    
    relaysTagList = []
    relaysTagList.append("relays")
    relays = getNostrRelaysFromConfig(config).copy()
    random.shuffle(relays)
    relaysLeftToAdd = 15
    relays4zapReceipt = []
    for relay in relays:
        if relaysLeftToAdd <= 0: break
        if type(relay) is str:
            relays4zapReceipt.append(relay)
        if type(relay) is dict:
            canread = relay["read"] if "read" in relay else True
            if canread and "url" in relay: relays4zapReceipt.append(relay["url"])
        relaysLeftToAdd -= 1
    relaysTagList.extend(relays4zapReceipt)
    zapTags.append(relaysTagList)
    zapTags.append(["amount", str(amountMillisatoshi)])
    zapTags.append(["lnurl", bech32lnurl])
    zapTags.append(["p",recipientPubkey])
    zapTags.append(["e",eventId])
    zapEvent = Event(content=zapMessage,kind=9734,tags=zapTags)
    withPK.sign_event(zapEvent)
    return zapEvent

def loadLightningIdCache():
    global lightningIdCache
    filename = f"{files.dataFolder}lightningIdcache.json"
    lightningIdCache = files.loadJsonFile(filename, {})

def saveLightningIdCache():
    global lightningIdCache
    filename = f"{files.dataFolder}lightningIdcache.json"
    files.saveJsonFile(filename, lightningIdCache)

def getLightningIdForPubkey(pubkeyHex):
    global lightningIdCache
    t, _ = utils.getTimes()
    lightningId = None
    name = None
    # look in cache for id set within past day
    for k, v in lightningIdCache.items():
        if k != pubkeyHex: continue
        if type(v) is not dict: continue
        if "lightningId" not in v: continue
        if "created_at" not in v: continue
        if v["created_at"] > t - 86400: 
            lightningId = v["lightningId"]
            if str(lightningId).lower().startswith("lnurl"): 
                lightningId = makeLightningIdFromLNURL(lightningId)
            if lightningId is not None: 
                name = v["name"] if ("name" in v and v["name"] is not None) else "no name"
                return lightningId, name
    # get profile from relays
    profile, created_at = getProfile(pubkeyHex)
    if profile is None: return lightningId, name
    # favor lud16, with fallback support if a lnurl was provided instead of identity
    if lightningId is None and "lud16" in profile and profile["lud16"] is not None: 
        lightningId = profile["lud16"]
        name = profile["name"] if ("name" in profile and profile["name"] is not None) else "no name"
        if str(lightningId).lower().startswith("lnurl"): 
            lightningId = makeLightningIdFromLNURL(lightningId)
        if lightningId is not None:
            lightningIdCache[pubkeyHex] = {
                "lightningId": lightningId, "name":name, "created_at": t
                }
    # fallback to lud06 which should be lnurl
    if lightningId is None and "lud06" in profile and profile["lud06"] is not None:
        lnurl = profile["lud06"]
        if str(lnurl).lower().startswith("lnurl"):
            lightningId = makeLightningIdFromLNURL(lnurl)
            if lightningId is not None:
                name = profile["name"] if ("name" in profile and profile["name"] is not None) else "no name"
                lightningIdCache[pubkeyHex] = {
                    "lightningId": lightningId, "name":name, "created_at": t
                    }
    if lightningId is not None: saveLightningIdCache()
    return lightningId, name

# candidate to move to liblnurl
def makeLightningIdFromLNURL(lnurl):
    lightningId = None
    try:
        hrp, e2 = bech32.bech32_decode(lnurl)
        tlv_bytes = bech32.convertbits(e2, 5, 8)
        du = bytes.fromhex(bytes(tlv_bytes).hex()).decode('ASCII')
        # using the utils.bech32ToHex is chopping a byte on beginning and end
        # du = bytes.fromhex(utils.bech32ToHex(lnurl)).decode('ASCII')
        # 'tps://walletofsatoshi.com/.well-known/lnurlp/usernam'
        du = du.split("//")[1]
        domainpart = du.split("/")[0]
        usernamepart = du.split("/")[-1]
        lightningId = f"{usernamepart}@{domainpart}"
        logger.debug(f"Decoded {lightningId} from lnurl")
    except Exception as err:
        logger.warning(f"Could not decode lnurl ({lnurl}) to a lightning identity: {str(err)}")
    return lightningId

# candidate to move to liblnurl
def isValidLightningId(lightningId):
    if lightningId is None:
        return False, f"No lightning address"
    identityParts = lightningId.split("@")
    if len(identityParts) != 2: 
        return False, f"Lightning address {lightningId} is invalid - not in username@domain format"
    return True, None

# candidate to move to liblnurl
def validateLNURLPayInfo(lnurlPayInfo, lnurlp, lightningId, name, amount, pubkey):
    callback = None
    bech32lnurl = None
    userMessage = None
    if lnurlPayInfo is None:
        logger.warning(f"Could not get LNURLP info for address: {lightningId}")
        userMessage = f"LN Provider for {lightningId} did not return meta info. (Check lud16 or lud06 in profile)"
        return callback, bech32lnurl, userMessage
    if lnurlp is None:
        logger.debug(f"Invalid address {lightningId}: not in username@domain format")
        userMessage = f"Lightning address {lightningId} not in correct format. (Check lud16 in profile)"
        return callback, bech32lnurl, userMessage
    if "allowsNostr" not in lnurlPayInfo:
        logger.debug(f"LN Provider for {lightningId} does not support nostr.")
        userMessage = f"LN Provider for {lightningId} does not support Nostr"
        return callback, bech32lnurl, userMessage
    if not lnurlPayInfo["allowsNostr"]:
        logger.debug(f"LN Provider for {lightningId} does not allow nostr.")
        userMessage = f"LN Provider for {lightningId} does not allow Nostr"
        return callback, bech32lnurl, userMessage
    if "nostrPubkey" not in lnurlPayInfo:
        logger.warning(f"LN Provider for {lightningId} does not have nostrPubkey. Publisher of receipt could be anyone")
    if not all(k in lnurlPayInfo for k in ("callback","minSendable","maxSendable")): 
        logger.debug(f"LN Provider for {lightningId} does not have proper callback, minSendable, or maxSendable info.")
        userMessage = f"LN Provider for {lightningId} does not provide expected response format"
        return callback, bech32lnurl, userMessage
    minSendable = int(lnurlPayInfo["minSendable"])
    maxSendable = int(lnurlPayInfo["maxSendable"])
    if (amount * 1000) < minSendable:
        logger.debug(f"LN Provider for {lightningId} does not allow zaps less than {minSendable} msat.")
        userMessage = f"LN Provider for {lightningId} requires {minSendable} msats minimum to be zapped"
        return callback, bech32lnurl, userMessage
    if (amount * 1000) > maxSendable:
        logger.debug(f"LN Provider for {lightningId} does not allow zaps greater than {maxSendable} msat.")
        userMessage = f"LN Provider for {lightningId} permits no more than {maxSendable} msats to be zapped"
        return callback, bech32lnurl, userMessage
    callback = lnurlPayInfo["callback"]
    if callback is None:
        logger.debug(f"LN Provider for {lightningId} does not have a callback url.")
        userMessage = f"LN Provider for {lightningId} does not have a callback url."
        return callback, bech32lnurl, userMessage
    elif not lnurl.isLNURLCallbackAllowed(callback):
        logger.debug(f"LN Provider callback for {lightningId} is on the denyProviders list and cannot be zapped at this time ({name} with pubkey: {pubkey})")
        userMessage = f"LN Provider callback for {lightningId} is not allowed"
        return callback, bech32lnurl, userMessage
    lnurlpBytes = bytes(lnurlp,'utf-8')
    lnurlpBits = bech32.convertbits(lnurlpBytes,8,5)
    bech32lnurl = bech32.bech32_encode("lnurl", lnurlpBits)
    return callback, bech32lnurl, userMessage

