# Nice Bot

This script monitors the Bitcoin blockchain and anytime the block height contains `69` it will write a note to Nostr using the defined relays

- [Clone the repository](#clone-the-repository)
- [Preparation of Python Environment](#preparation-of-python-environment)
- [Configuring the Bot](#configuring-the-bot)
  - [Nostr Config](#nostr-config)
  - [Bitcoin Config](#bitcoin-configuration)
  - [Matchon Config](#matchon-configuration)
- [Running the Script](#running-the-script)
- [Running as a Service](#running-as-a-service)
- [For More Help](#for-more-help)

## Clone the repository

To setup bot, you'll first need to clone the repository

```sh
git clone https://github.com/vicariousdrama/NiceBot.git
```

Change to the folder where the code is cloned to

```sh
cd NiceBot
```

If you need to update the bot's code, pull the latest changes

```sh
git pull
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

The server configuration file is divided into a few key sections. One for each of Nostr, Bitcoin, and Matchon

### Nostr Config

Edit the configuration

```sh
nano data/config.json
```

The `nostr` configuration section has these keys

| key | description |
| --- | --- |
| nsec | The nsec for identity |
| profile | The metadata fields for the bot's profile |
| relays | The list of relays the bot uses |

The most critical to define here is the `nsec`.  You should generate an nsec on your own, and not use an existing one such as that for your personal usage.

The `profile` section contains fields that map to a nostr profile.  The picture and banner should be URLs pointing to an image publicly available.  The lud16 field is the lightning address that should be associated with the bot. A nip05 can optionally be set for external DNS verification as a nostr address.

The `relays` section contains the list of relays that the bot will use to read events and direct messages, as well as publish profiles (kind 0 metadata), direct message responses (kind 4), replies (kind 1).  Each relay is configured with a url, and permissions for whether it can be read from or written to.

### Bitcoin Configuration

Edit the configuration

```sh
nano data/config.json
```

The `bitcoin` configuration section has these keys

| key | description |
| --- | --- |
| url | A url for a service returning the current bitcoin block height |

### Matchon Configuration

Edit the configuration

```sh
nano data/config.json
```

The `matchon` configuration section has these keys

| key | description |
| --- | --- |
| value | The value to look for related to the block height |
| type | The type of match to perform. Should be one of `contains`, `endswith`, `startswith`, or `modulus` |
| text | The text to write as the content of the nostr post when a match is found |

The default setup is `value` = 69, and `type` = contains.

If the `type` is set to `modulus` then the blockheight will be divided by the value, and if the result is 0, it is considered a success to write the `text` to a post.

## Running the Script

Once configured, run the bot using the previously established virtual environment

```sh
~/.pyenv/nicebot/bin/python main.py
```

Press `Control+C` to stop the bot process when satisfied its running properly.

## Running as a Service

You can install a service to run the bot in the background.  You will need to do this as sudo, and know the name of the user for which the code was installed under.

Copy the service file

```sh
sudo cp nostr-nicebot.service /etc/systemd/system/nostr-nicebot.service
```

Edit the contents

```sh
sudo nano -l /etc/systemd/system/nostr-nicebot.service
```

On lines 10, 11, and 12 change the username if you installed to a different user than `admin`.

Save (CTRL+O) and Exit (CTRL+X).

Enable and start the service

```sh
sudo systemctl enable nostr-nicebot.service

sudo systemctl start nostr-nicebot.service
```

## For More Help

For further assistance or customizations, reach out to the developer on Nostr
- NIP05: vicariousdrama@nodeyez.com
- NPUB: npub1yx6pjypd4r7qh2gysjhvjd9l2km6hnm4amdnjyjw3467fy05rf0qfp7kza
