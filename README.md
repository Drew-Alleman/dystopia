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
* Add more commands (Push towards being a ubuntu core IoT honeypot)
* Service
* Geolocation 
* Email Alerts 
* Insights such as charts & graphs 
* Add Default Configurations 
* Optimize / Fix Code


# Command Line Arguments // Usage
```
usage: dystopia.py [-h] [--port PORT] [--motd MOTD] [--max MAX] [--username USERNAME] [--password PASSWORD]
                   [--hostname HOSTNAME] [--localhost] [--save SAVE] [--load LOAD]

Dystopia | A python honeypot.

optional arguments:
  -h, --help            show this help message and exit
  --port PORT, -P PORT  specify a port to bind to
  --motd MOTD, -m MOTD  specify the message of the day
  --max MAX, -M MAX     max number of clients allowed to be connected at once.
  --username USERNAME, -u USERNAME
                        username for fake login prompt and the user for the honeypot session
  --password PASSWORD, -p PASSWORD
                        password for fake login prompt
  --hostname HOSTNAME, -H HOSTNAME
                        hostname of the honeypot
  --localhost, -L       host honeypot on localhost
  --save SAVE, -s SAVE  save config to a json file
  --load LOAD, -l LOAD  load a config file
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
