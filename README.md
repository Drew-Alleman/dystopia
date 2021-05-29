# Dystopia
Low to medium Ubuntu Core honeypot coded in Python.
![preview](/media/preview.PNG)
# Features
* Optional Login Prompt
* Logs commands used and IP addresses
* Customize MOTD, Port, Hostname and how many clients can connect at once (default is unlimited)
* Save and load config
* Add support to a plethora of commands

# Todo
* Packet Capture
* Better Logging
* Service
* Geolocation 
* Email Alerts 
* Insights such as charts & graphs 
* Add Default Configurations 
* Optimize / Fix Code

# How to run
```bash
sudo apt update && sudo apt upgrade -y
python3 dystopy.py
```
# Command Line Arguments 
```
usage: dystopia.py [-h] [--port PORT] [--motd MOTD] [--max MAX] [--login]
                   [--username USERNAME] [--password PASSWORD]
                   [--hostname HOSTNAME] [--localhost] [--capture]
                   [--interface INTERFACE] [--save SAVE] [--load LOAD]

Dystopia | A python Honeypot.

optional arguments:
  -h, --help            show this help message and exit
  --port PORT, -P PORT  specify a port to bind to
  --motd MOTD, -m MOTD  specify the message of the day
  --max MAX, -M MAX     max number of clients allowed to be connected at once
                        default is unlimited
  --login, -f           create a fake login prompt (no encryption)
  --username USERNAME, -u USERNAME
                        username for fake login prompt and the user for the
                        Honeypot session default: 'ubuntu'
  --password PASSWORD, -p PASSWORD
                        password for fake login prompt. Default: 'P@$$W0RD'
  --hostname HOSTNAME, -H HOSTNAME
                        Hostname of the Honeypot default: 'localhost'
  --localhost, -L       start Honeypot on localhost
  --capture, -c         enable packet capturing using the tool Tcpdump
  --interface INTERFACE, -i INTERFACE
                        interface to capture traffic on if --capture / -c is
                        used and no interface is configured, the default is:
                        'eth0'
  --save SAVE, -s SAVE  save config to a json file E.g: '--save settings.json'
  --load LOAD, -l LOAD  load config from a json file E.g '--load
                        settings.json'
```
# How to add Support for More Commands
You can add support to new commands by editing the file "commands.json". The format is command:output <br>
for eg <br>
```json
{
  "dog":"Dog command activated!"
}
```
![example](/media/dog.png)
