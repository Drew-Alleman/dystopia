import json
from json import JSONDecodeError
import socket
import logging
from colorama import Fore
from datetime import datetime

logging.basicConfig(
    filename="dystopia.log",
    level=logging.INFO,
    format="%(asctime)s:%(threadName)s:%(message)s",
)


class DisplayStatistics:
    def __init__(self):
        self.stats = read_json_file("/var/log/dystopia/statistics.json")
        self.ips = []
        for ip, stat in self.stats.items():
            self.ips.append(ip)

    def get_top_connector(self):
        times_connected = []
        for ip in self.ips:
            times_connected.append(self.stats[ip]["Times Connected"])
        max_times_connected = max(times_connected)
        index = times_connected.index(max_times_connected)
        if max_times_connected == 0:
            return "N/A", "N/A"
        return self.ips[index], max_times_connected

    def get_most_login_attempts(self):
        failed_logins = []
        for ip in self.ips:
            failed_logins.append(self.stats[ip]["Failed Logins"])
        top_attacker = max(failed_logins)
        index = failed_logins.index(top_attacker)
        if top_attacker == 0:
            return "N/A", "N/A"
        return self.ips[index], top_attacker


def print_banner():
    display = DisplayStatistics()
    top_login = DisplayStatistics.get_most_login_attempts(display)
    top_connector = DisplayStatistics.get_top_connector(display)
    banner_art = """{2}
    :::::::-. .-:.     ::-. .::::::.::::::::::::   ...   ::::::::::. :::  :::.     
     ;;,   `';,';;.   ;;;;';;;`    `;;;;;;;;''''.;;;;;;;. `;;;```.;;;;;;  ;;`;;    
     `[[     [[  '[[,[[['  '[==/[[[[,    [[    ,[[     \\[[,`]]nnn]]' [[[ ,[[ '[[,  
      $$,    $$    c$$"      '''    $    $$    $$$,     $$$ $$$""    $$$c$$$cc$$$c 
      888_,o8P'  ,8P"`      88b    dP    88,   "888,_ _,88P 888o     888 888   888,
      MMMMP"`   mM"          "YMmMY"     MMM     "YMMMMMP"  YMMMb    MMM YMM   ""` 
                  {3}[--]{1} {0}https://github.com/Drew-Alleman/dystopia    
                  {3}[--]{1} Top Connector: {0}{4} ({5})          
                  {3}[--]{1} Most Login Attempts: {0}{6} ({7}){1} 
                  {3}[--]{1} All downloaded files go into the 'Loot' directory!
      """.format(
        Fore.RED,
        Fore.WHITE,
        Fore.LIGHTBLUE_EX,
        Fore.YELLOW,
        top_connector[0],
        top_connector[1],
        top_login[0],
        top_login[1],
    )
    print(banner_art)


def get_time():
    now = datetime.now()  # Get time
    pretty_time = now.strftime("[%H:%M:%S] ")  # Format time
    return pretty_time


def print_message(message):
    print(Fore.GREEN + get_time() + Fore.WHITE + message)
    logging.info(message)


def print_error(message):
    print(Fore.RED + get_time() + Fore.WHITE + message)
    logging.error(message)


def print_warning(message):
    print(Fore.YELLOW + get_time() + Fore.WHITE + message)
    logging.warning(message)


def get_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(("8.8.8.8", 80))
    ipaddress = sock.getsockname()[0]
    sock.close()
    return ipaddress


def is_data_valid(data):
    if data is None or len(data) == 0:
        return False
    return True


def log_connector(ip_address):
    directory = "/var/log/dystopia/connections.txt"
    ips = get_file_content(directory)
    ips = [ip.strip() for ip in ips]
    if ip_address.strip() not in ips:
        with open(directory, "a+") as f:
            f.write(ip_address)


def read_json_file(filename):
    if filename is None:
        print_error("file was not found!")
        exit()
    try:
        with open(filename, "r") as outFile:
            data = json.load(outFile)
        return data
    except JSONDecodeError:
        print_error("JSONDecodeError in thread ")
    except FileNotFoundError:
        print_error("file: '{}' was not found.".format(filename))
        exit()


def get_file_content(filename):
    with open(filename, "r") as f:
        content = f.readlines()
    return content


def format_string(s):
    s = s.decode().strip()
    if s.endswith("\x00"):
        s = s[:-2]
    return s
