import re
import os
import json
from json import JSONDecodeError
import socket
import logging
from colorama import Fore
from datetime import datetime

logging.basicConfig(
    filename="dystopia.log",
    encoding="utf-8",
    level=logging.INFO,
    format="%(asctime)s:%(threadName)s:%(message)s",
)


class DisplayStatistics:
    def __init__(self):
        self.stats = readJsonFile("stats.json")
        self.ips = []
        for ip, stat in self.stats.items():
            self.ips.append(ip)

    def getTopConnector(self):
        timesConnected = []
        for ip in self.ips:
            timesConnected.append(self.stats[ip]["Times Connected"])
        maxTimesConnected = max(timesConnected)
        index = timesConnected.index(maxTimesConnected)
        if maxTimesConnected == 0:
            return ("N/A", "N/A")
        return (self.ips[index], maxTimesConnected)

    def getMostLoginAttempts(self):
        failedLogins = []
        for ip in self.ips:
            failedLogins.append(self.stats[ip]["Failed Logins"])
        topAttacker = max(failedLogins)
        index = failedLogins.index(topAttacker)
        if topAttacker == 0:
            return ("N/A", "N/A")
        return (self.ips[index], topAttacker)


def printBanner():
    display = DisplayStatistics()
    topLogin = DisplayStatistics.getMostLoginAttempts(display)
    topConnector = DisplayStatistics.getTopConnector(display)
    bannerArt = """{2}
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
        topConnector[0],
        topConnector[1],
        topLogin[0],
        topLogin[1],
    )
    print(bannerArt)


def getTime():
    now = datetime.now()  # Get time
    prettyTime = now.strftime("[%H:%M:%S] ")  # Format time
    return prettyTime


def printMessage(message):
    cTime = getTime()
    print(Fore.GREEN + cTime + Fore.WHITE + message)
    logging.info(message)


def printError(message):
    cTime = getTime()
    print(Fore.RED + cTime + Fore.WHITE + message)
    logging.error(message)


def printWarning(message):
    cTime = getTime()
    print(Fore.YELLOW + cTime + Fore.WHITE + message)
    logging.warning(message)


def getIP():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(("8.8.8.8", 80))
    ipaddress = sock.getsockname()[0]
    sock.close()
    return ipaddress


def writeJsonToFile(jsonData, fileName):
    if fileName.endswith(".json") == False:
        fileName = fileName + ".json"
        with open(fileName, "a+") as outFile:
            data = json.loads(fileName)
            outFile.seek(0)
            data.update(jsonData)


def isDataValid(data):
    if data is None or len(data) == 0:
        return False
    return True


def writeToBlacklist(clientIPAddress):
    with open("blacklist.txt", "a+") as f:
        ips = f.readlines()
        ips = [ip.strip() for ip in ips]
        if clientIPAddress not in ips:
            f.write(clientIPAddress)


def readJsonFile(fileName):
    if fileName is None:
        printError("file was not found!")
        quit()
    try:
        with open(fileName, "r") as outFile:
            data = json.load(outFile)
        return data
    except JSONDecodeError:
        printError("JSONDecodeError in thread ")
    except FileNotFoundError:
        printError("file: '{}' was not found.".format(fileName))
        quit()

def yn(message):
    try:
        prompt = (
            Fore.GREEN + " y" + Fore.WHITE + "/" + Fore.RED + "n" + Fore.WHITE + ": "
        )
        yes = ["y", "Y", "YES", "yes"]
        no = ["n", "N", "NO", "no"]
        choice = input(Fore.YELLOW + "[?] " + Fore.WHITE + message + prompt)
        if choice in yes:
            return True
        elif choice in no:
            return False
        else:
            printError(choice + " ??")
            quit()
    except KeyboardInterrupt:
        quit()


def formatString(s):
    s = s.decode().strip()
    if s.endswith("\x00"):
        s = s[:-2]
    return s
