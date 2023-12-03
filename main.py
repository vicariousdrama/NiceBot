from logging.handlers import RotatingFileHandler
from nostr.event import Event
import logging
import requests
import shutil
import sys
import time
import libfiles as files
import libnostr as nostr
import libutils as utils

def validateConfig():
    if len(config.keys()) == 0:
        shutil.copy("sample-config.json", f"{files.dataFolder}config.json")
        logger.info(f"Copied sample-config.json to {files.dataFolder}config.json")
        logger.info("You will need to modify this file to setup nostr and bitcoin sections")
        quit()

def getBlockHeight():
    if "bitcoin" in config:
        if "url" in config["bitcoin"]:
            url = config["bitcoin"]["url"]
            try:
                response = requests.get(url=url)
                output = response.text
                if output.isnumeric():
                    return int(output)
            except Exception as e:
                logger.warning(f"Error fetching blockheight: {e}")
                return 0
    logger.warning(f"Could not get blockheight from API. Check config file for bitcoin.url")
    return 0

BLOCKHEIGHT_REPORTED_69 = "blockheightReported69"
BLOCKHEIGHT_SEEN = "blockheightSeen"
LOG_FILE = f"{files.logFolder}nicebot.log"
CONFIG_FILE = f"{files.dataFolder}config.json"
DATA_FILE = f"{files.dataFolder}saveddata.json"

if __name__ == '__main__':

    startTime, _ = utils.getTimes()

    # Logging to systemd
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(fmt="%(asctime)s %(name)s.%(levelname)s: %(message)s", datefmt="%Y.%m.%d %H:%M:%S")
    stdoutLoggingHandler = logging.StreamHandler(stream=sys.stdout)
    stdoutLoggingHandler.setFormatter(formatter)
    logging.Formatter.converter = time.gmtime
    logger.addHandler(stdoutLoggingHandler)
    logFile = LOG_FILE
    fileLoggingHandler = RotatingFileHandler(logFile, mode='a', maxBytes=10*1024*1024, 
                                 backupCount=21, encoding=None, delay=0)
    fileLoggingHandler.setFormatter(formatter)
    logger.addHandler(fileLoggingHandler)
    files.logger = logger
    nostr.logger = logger

    # Load server config
    config = files.getConfig(CONFIG_FILE)
    validateConfig()
    nostr.config = config["nostr"]

    # Report bot info
    logger.debug(f"Bot npub: {nostr.getPubkey().bech32()}")

    # Load last checked block height
    savedData = files.loadJsonFile(DATA_FILE, {})

    # Initialize empty data
    logger.debug("Initializing...")
    changed = False
    if BLOCKHEIGHT_SEEN not in savedData: 
        changed = True
        savedData[BLOCKHEIGHT_SEEN] = getBlockHeight()
    if BLOCKHEIGHT_REPORTED_69 not in savedData: 
        changed = True
        savedData[BLOCKHEIGHT_REPORTED_69] = 69
    if changed: 
        logger.debug("Saving state")
        files.saveJsonFile(DATA_FILE, savedData)
        time.sleep(5)

    # Run Forever
    while True:

        # just track if we made any changes this round
        changed = False

        # Check if new block
        blockheightCurrent = getBlockHeight()
        if blockheightCurrent > savedData[BLOCKHEIGHT_SEEN]:

            logger.debug(f"New Blockheight is {blockheightCurrent}") 

            # NEW BLOCK!
            changed = True
            isconnected = False

            # Process each block from already seen to the new block
            for blockHeight in range(savedData[BLOCKHEIGHT_SEEN] + 1, blockheightCurrent + 1):
                if "69" in str(blockHeight):

                    logger.info(f"Block {blockHeight} has a 69!")

                    # Connect to relays if not yet connected
                    if not isconnected: 
                        nostr.connectToRelays()
                        isconnected = True

                    # Prepare, sign, and publish message to nostr for this block
                    event = Event(content="NICE", kind=1, tags=[["blockheight",blockHeight]])
                    nostr.getPrivateKey().sign_event(event)
                    nostr._relayManager.publish_message(event)
                    time.sleep(nostr._relayPublishTime)

                    # Make note of last reported
                    savedData[BLOCKHEIGHT_REPORTED_69] = blockHeight

            # Disconnect if we connected
            if isconnected: nostr.disconnectRelays()

            # Update our last seen
            savedData[BLOCKHEIGHT_SEEN] = blockheightCurrent
            
            # Record state
            logger.debug("Saving state")
            files.saveJsonFile(DATA_FILE, savedData)

        # Rest a bit
        logger.debug("Sleeping for 1 minute")
        time.sleep(60)
