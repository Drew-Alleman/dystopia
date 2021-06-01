# Dystopia
Low to medium Ubuntu Core honeypot coded in Python.
![preview](/media/preview.PNG)
# Features
* Optional login prompt
* Logs who connects and what they do
* Capture session to pcap file 
* Automatically download links used by attackers
* Customize MOTD, Port, Hostname and how many clients can connect at once (default is unlimited)
* Save and load config
* Add support to a plethora of commands

# Todo
* Better Logging
* Service
* Geolocation 
* Email Alerts 
* Insights such as charts & graphs 
* Add Default Configurations 
* Optimize / Fix Code

# How to run
```bash
chmod 755 setup.sh
./setup.sh
Requirement already satisfied: attrs==20.3.0 in /usr/lib/python3.9/site-packages (from -r requirements.txt (line 6)) (20.3.0)
Requirement already satisfied: wcwidth>=0.1.7 in /home/drewa/.local/lib/python3.9/site-packages (from cmd2->cephfs-shell==0.0.1->-r requirements.txt (line 16)) (0.2.5)
Requirement already satisfied: colorama==0.4.4 in /usr/lib/python3.9/site-packages (from -r requirements.txt (line 20)) (0.4.4)
[+] Tcpdump is used to capture dystopia sessions!
[+] Would you like to install 'Tcpdump'? [Y/n] y
[+] 1 --> Install for Arch Linux
[+] 2 --> Install for Debian Users
1
[sudo] password for drewa: 
warning: tcpdump-4.99.0-1 is up to date -- reinstalling
resolving dependencies...
looking for conflicting packages...

Packages (1) tcpdump-4.99.0-1

Total Installed Size:  1.35 MiB
Net Upgrade Size:      0.00 MiB

:: Proceed with installation? [Y/n] y
(1/1) checking keys in keyring                     [######################] 100%
(1/1) checking package integrity                   [######################] 100%
(1/1) loading package files                        [######################] 100%
(1/1) checking for file conflicts                  [######################] 100%
(1/1) checking available disk space                [######################] 100%
:: Processing package changes...
(1/1) reinstalling tcpdump                         [######################] 100%
:: Running post-transaction hooks...
(1/1) Arming ConditionNeedsUpdate...
[+] Creating needed directorys!


python3 dystopy.py
```
# Command Line Arguments 
```
usage: dystopia.py [-h] [--host HOST] [--port PORT] [--motd MOTD] [--max MAX]
                   [--login] [--username USERNAME] [--password PASSWORD]
                   [--hostname HOSTNAME] [--localhost] [--capture]
                   [--interface INTERFACE] [--save SAVE] [--load LOAD]
                   [--download] [--version]

Dystopia | A python Honeypot.

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           IP Address to host the Honeypot. Default:
                        192.168.0.223
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
  --download, -a        Automatically download links used by attackers
  --version             print version and exit
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
