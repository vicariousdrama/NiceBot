# Nice Bot

This script monitors the Bitcoin blockchain and anytime the block height contains `69` it will write a note to Nostr using the defined relays

## Clone the repository

To setup bot, you'll first need to clone the repository

```sh
git clone https://github.com/vicariousdrama/NiceBot.git
```

## Preparation of Python Environment

To use this script, you'll need to run it with python 3.9 or higher and with the nostr, requests and bech32 packages installed.

First, create a virtual environment (or activate a common one)

```sh
python3 -m venv ~/.pyenv/nicebot
```

Activate it

```sh
source ~/.pyenv/nicebot/bin/activate
```

Install Dependencies

```sh
python3 -m pip install -r requirements.txt
```

## Configuring the Bot

A subdirectory for storing `data` will be created if one does not exist on first run of the script.  Otherwise you can create and copy the sample configuration as follows:

```sh
mkdir -p data
cp -n sample-config.json data/config.json
```

Within this directory, a configuration file named `config.json` is read.  If this file does not exist, one will be created using the `sample-config.json`.

The server configuration file is divided into a few key sections. One for each of Nostr and Bitcoin

### Nostr Config

Edit the configuration

```sh
nano data/config.json
```

The `nostr` configuration section has these keys

| key | description |
| --- | --- |
| nsec | The nsec for identity |
| relays | The list of relays the bot uses |

The most critical to define here is the `nsec`.  You should generate an nsec on your own, and not use an existing one such as that for your personal usage.

The `relays` section contains the list of relays that the bot will use to read events and direct messages, as well as publish profiles (kind 0 metadata), direct message responses (kind 4), replies (kind 1).  Each relay is configured with a url, and permissions for whether it can be read from or written to.

### Bitcoin configuration

Edit the configuration

```sh
nano data/config.json
```

The `bitcoin` configuration section has these keys

| key | description |
| --- | --- |
| url | A url for a service returning the current bitcoin block height |

## Running the Script

Once configured, run the bot using the previously established virtual environment

```sh
~/.pyenv/nicebot/bin/python main.py
```

Press `Control+C` to stop the bot process when satisfied its running properly.

For further assistance or customizations, reach out to the developer on Nostr
- NIP05: vicariousdrama@nodeyez.com
- NPUB: npub1yx6pjypd4r7qh2gysjhvjd9l2km6hnm4amdnjyjw3467fy05rf0qfp7kza
