import sys
# Check for python3
if int(sys.version[0]) < 3:
    print("[-] Please use python 3>")
    quit()
from core.utilities import *
import threading
import argparse
import textwrap
import socket
import json
import os

globalLock = threading.Lock()


class Statistics:
    def __init__(self, clientAddress):
        self.address = clientAddress[0]
        if not Statistics.load(self):
            self.failedLogins = 0
            self.correctLogins = 0
            self.seen = 0

    def save(self):
        with globalLock:
            with open("stats.json", "r") as jsonFile:
                data = json.load(jsonFile)
                try:
                    data[self.address]["Failed Logins"] = self.failedLogins
                    data[self.address]["Correct Logins"] = self.correctLogins
                    data[self.seen]["Times Connected"] = self.seen
                except KeyError:
                    newData = '{"'+self.address+'":{"Failed Logins":'+str(self.failedLogins)+',"Correct Logins":'+str(self.correctLogins)+', "Times Connected":'+str(self.seen)+'}}'
                    jsonData = json.loads(newData)
                    data.update(jsonData)
            with open("stats.json", "w") as jsonFile:
                json.dump(data, jsonFile,indent=4,ensure_ascii=False)

    def increaseFailedLogin(self):
        self.failedLogins += 1
    def increaseCorrectLogins(self):
        self.correctLogins += 1
    def increaseSeenCount(self):
        self.seen += 1

    def load(self):
        stats = readJsonFile("stats.json")
        try:
            self.failedLogins = stats[self.address]["Failed Logins"]
            self.correctLogins = stats[self.address]["Correct Logins"]
            self.seen = stats[self.address]["Times Connected"]
            return True
        except KeyError: # If information is not found.
            return False

class Honeypot:
    def __init__(self):
        if args.load is None:  # If user is not loading config from file
            self.port = args.port
            self.motd = args.motd
            self.max = args.max
            self.fake = args.login
            self.hostname = args.hostname
            self.localhost = args.localhost
            self.username = args.username
            self.password = args.password
            self.capture = args.capture
            self.interface = args.interface
        else:  # Load config
            print(args.load)
            Honeypot.loadConfig(self, args.load)

        if self.localhost:
            self.ipaddress = "127.0.0.1"
        else:
            self.ipaddress = getIP()

        if self.max != 0:
            printMessage("Max clients allowed: " + str(self.max))
        if args.save:
            Honeypot.exportConfig(self)

        self.clientList = []  # List for clients CURRENTLY connected.
        self.IPList = []  # List for all clients that connected in a session.
        self.commands = readJsonFile("commands.json")
        self.prompt = (self.username.strip().encode()
                    + b"@"
                    + self.hostname.strip().encode()
                    + b":~$ ")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def bind(self):
        try:
            message =(
            "Created Honeypot @ "
            + self.ipaddress
            + ":"
            + str(self.port)
            + " the motd is "
            + textwrap.shorten(self.motd, 35))
            self.sock.bind((self.ipaddress, self.port))
            printMessage(message)
            if args.capture:
                Honeypot.capturePot(self)
        except PermissionError:
            printError("Please run 'dystopia.py' as root")
            quit()
        except OSError as e:
            printError(str(e))
            quit()
    def handleClient(self, connection, clientAddress):
        stats = Statistics(clientAddress)
        Statistics.load(stats)
        Statistics.increaseSeenCount(stats)
        if self.fake:
            while not Honeypot.login(self, connection, clientAddress):
                Statistics.increaseFailedLogin(stats)
                Statistics.save(stats)
            else:
                Statistics.increaseCorrectLogins(stats)
        connection.sendto(self.motd.encode() + b"\n", clientAddress)  # Send MOTD
        while True:
            try:
                connection.sendto(self.prompt,clientAddress)
                data = formatString(connection.recv(1024))
                if isDataValid(data):  # if data is valid
                    Honeypot.commandResponse(self, connection, clientAddress, data)
                    printMessage("client " + clientAddress[0] + " tried command " + data)
            # If connection is dropped / lost then break from loop and remove client from the client list
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                break
            except UnicodeDecodeError:  # Telnet Error ???
                pass

        printWarning(clientAddress[0] + " disconnected!")
        Statistics.save(stats)
        self.clientList.remove(clientAddress[0])  # clientList is for only ACTIVE clients

    def commandResponse(self, connection, clientAddress, command):
        response = None
        if "sudo" in command and command != "sudo":  # No sudo for you!
            response = self.username.encode() + b" is not in the sudoers file. This incident will be reported.\n"
        elif command == "whoami":
            response = self.username.encode() + b"\n"
        elif command == "pwd":
            response = b"/home/" + self.username.encode() + b"/\n"
        elif command == "hostname":
            response = self.hostname.encode() + b"\n"
        elif command == "exit":
            connection.shutdown(1)
        elif "cd" in command:
            dir = command.split()
            if len(dir) > 1:
                response = b"cd: " + dir[1].encode() + b": No such file or directory\n"
        else:  # If command is unknown
            try:  # Try to see if it is in the commands.json file
                response = self.commands[command].encode()
            except KeyError:  # if it is not
                command = command.split()  # Split command by spaces
                response = b"bash: " + command[0].encode() + b": command not found\n"
        if response != None:
            connection.sendto(response, clientAddress)

    def login(self, connection, clientAddress):
        try:
            connection.sendto(b"Login: ", clientAddress)
            username = connection.recv(1024)
            connection.sendto(b"Password: ", clientAddress)
            password = connection.recv(1024)
            username = formatString(username)
            password = formatString(password)
            if username == self.username and password == self.password:
                printMessage("client "+ clientAddress[0] + " logged in ({0}:{1})".format(username, password))
                return True
            connection.sendto(b"\nLogin incorrect\n", clientAddress)
            printError("client " + clientAddress[0] + " tried {0}:{1}".format(username, password))
            return False
            # If connection is dropped / lost
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return False
        except UnicodeDecodeError:
            # resend
            Honeypot.handleClient(self, connection, clientAddress)

    def checkClientLimit(self):
        if self.max != 0:
            if len(self.clientList) >= int(self.max):
                return True
        return False

    def listen(self):
        if Honeypot.checkClientLimit(self):
            return
        self.sock.listen(1)
        connection, clientAddress = self.sock.accept()
        printMessage(clientAddress[0] + " connected.")
        self.clientList.append(clientAddress[0])  # Add connected client to client list
        if clientAddress[0] not in self.IPList:
            self.IPList.append(clientAddress[0])
            writeToBlacklist(clientAddress[0] + "\n")
        t = threading.Thread(
            target=Honeypot.handleClient, args=(self, connection, clientAddress)
        )  # Start thread to handle the connection
        t.daemon = True
        t.start()  # Start thread

    def capturePot(self):
        now = datetime.now()
        filename = now.strftime("%d-%m-%y-%H-%M-%S.pcap")
        os.system("tcpdump -i " + self.interface + " -w " + filename + " &")

    def exportConfig(self):
        j = {
            "port": self.port,
            "motd": self.motd,
            "max": self.max,
            "login": self.fake,
            "username": self.username,
            "password": self.password,
            "hostname": self.hostname,
            "localhost": self.localhost,
            "capture": self.capture,
            "interface": self.interface,
        }
        jsonSettings = json.dumps(j)  # Parse python dict to JSON
        jsonSettingsObj = json.loads(jsonSettings)  # Load as JSON object
        with open(args.save, "a") as outFile:
            json.dump(jsonSettingsObj, outFile)

    def loadConfig(self, fileName):
        config = readJsonFile(fileName)
        self.port = config["port"]
        self.motd = config["motd"]
        self.max = config["max"]
        self.fake = config["login"]
        self.username = config["username"]
        self.password = config["password"]
        self.hostname = config["hostname"]
        self.localhost = config["localhost"]
        self.capture = config["capture"]
        self.interface = config["interface"]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dystopia | A python Honeypot.")
    parser.add_argument(
        "--port","-P", help="specify a port to bind to", default=23, type=int
    )
    parser.add_argument(
        "--motd", "-m",
        help="specify the message of the day",
        default="Welcome to Ubuntu Core r18 (GNU/Linux 4.15.0-143-generic x86_64)\n* Ubuntu Core:     "
                "https://www.ubuntu.com/core\n* Community:       https://forum.snapcraft.io\n* Snaps:           "
                "https://snapcraft.io\nThis Ubuntu Core 18 machine is a tiny, transactional edition of Ubuntu,"
                "\ndesigned for appliances, firmware and fixed-function VMs.\n\nIf all the software you care about is "
                "available as snaps, you are in\nthe right place. If not, you will be more comfortable with "
                "classic\ndeb-based Ubuntu Server or Desktop, where you can mix snaps with\ntraditional debs. It's a "
                "brave new world here in Ubuntu Core!\n\nPlease see 'snap --help' for app installation and updates.\n",
    )
    parser.add_argument(
        "--max", "-M",
        help="max number of clients allowed to be connected at once default is unlimited",
        default=0,
        type=int,
    )
    parser.add_argument(
        "--login","-f", help="create a fake login prompt (no encryption)", action="store_true", default=False
    )
    parser.add_argument(
        "--username", "-u",
        help="username for fake login prompt and the user for the Honeypot session default: 'ubuntu'",
        default="ubuntu",
    )
    parser.add_argument(
        "--password","-p", help="password for fake login prompt. Default: 'P@$$W0RD'", default="P@$$W0RD"
    )
    parser.add_argument("--hostname", "-H", help="Hostname of the Honeypot default: 'localhost'", default="localhost")
    parser.add_argument(
        "--localhost", "-L",
        help="start Honeypot on localhost",
        default=False,
        action="store_true",
    )
    parser.add_argument("--capture", "-c", help="enable packet capturing using the tool Tcpdump", action="store_true", default=False)
    parser.add_argument(
        "--interface", "-i", help="interface to capture traffic on if --capture / -c is used and no interface is configured, the default is: 'eth0'", default="eth0"
    )
    parser.add_argument("--save", "-s", help="save config to a json file E.g: '--save settings.json'")
    parser.add_argument("--load", "-l", help="load config from a json file E.g '--load settings.json'")
    args = parser.parse_args()
    printBanner()
    s = Honeypot()
    Honeypot.bind(s)
    printMessage("Waiting for connections...")
    while True:
        try:
            Honeypot.listen(s)
        except KeyboardInterrupt:
            break
