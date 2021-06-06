#!/usr/bin/python3
from core.utilities import *
import threading
import argparse
import textwrap
import socket
import json
import sys
import os
import re

VERSION = "1.3.0"
# Check for python3
if int(sys.version[0]) < 3:
    print("[-] Please use python 3>")
    exit()

global_lock = threading.Lock()


class Statistics:
    def __init__(self, socket_address):
        self.address = socket_address[0]
        self.dir = "/var/log/dystopia/statistics.json"
        if not Statistics.load(self):
            self.failed_logins = 0
            self.correct_logins = 0
            self.count = 0

    def save(self):
        with global_lock:
            with open(self.dir, "r") as jsonFile:
                data = json.load(jsonFile)
                try:
                    data[self.address]["Failed Logins"] = self.failed_logins
                    data[self.address]["Correct Logins"] = self.correct_logins
                    data[self.count]["Times Connected"] = self.count
                except KeyError:
                    new_data = (
                        '{"'
                        + self.address
                        + '":{"Failed Logins":'
                        + str(self.failed_logins)
                        + ',"Correct Logins":'
                        + str(self.correct_logins)
                        + ', "Times Connected":'
                        + str(self.count)
                        + "}}"
                    )
                    json_data = json.loads(new_data)
                    data.update(json_data)
            with open(self.dir, "w") as jsonFile:
                json.dump(data, jsonFile, indent=4, ensure_ascii=False)

    def increase_failed_login(self):
        self.failed_logins += 1

    def increase_correct_logins(self):
        self.correct_logins += 1

    def increase_view_count(self):
        self.count += 1

    def load(self):
        stats = read_json_file(self.dir)
        try:
            self.failed_logins = stats[self.address]["Failed Logins"]
            self.correct_logins = stats[self.address]["Correct Logins"]
            self.count = stats[self.address]["Times Connected"]
            return True
        except KeyError:  # If information is not found.
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
            self.autoDownload = args.download
            self.username = args.username
            self.password = args.password
            self.capture = args.capture
            self.interface = args.interface
        else:  # Load config
            Honeypot.load_config(self, args.load)

        if self.localhost:
            self.ipaddress = "127.0.0.1"
        else:
            self.ipaddress = args.host

        if self.max != 0:
            print_message("Max clients allowed: " + str(self.max))
        if args.save:
            Honeypot.export_config(self)

        self.clientList = []  # List for clients CURRENTLY connected.
        self.IPList = []  # List for all clients that connected in a session.
        self.commands = read_json_file("commands.json")
        self.prompt = (
            self.username.strip().encode()
            + b"@"
            + self.hostname.strip().encode()
            + b":~$ "
        )
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def bind(self):
        try:
            message = (
                "Created Honeypot @ "
                + self.ipaddress
                + ":"
                + str(self.port)
                + " the motd is "
                + textwrap.shorten(self.motd, 35)
            )
            self.sock.bind((self.ipaddress, self.port))
            print_message(message)
            if args.capture:
                Honeypot.capture_session(self)
        except PermissionError:
            print_error("Please run 'dystopia.py' as root")
            exit()
        except OSError as e:
            print_error(str(e))
            exit()

    def handle_client(self, connection, socket_address):
        stats = Statistics(socket_address)
        Statistics.load(stats)
        Statistics.increase_view_count(stats)
        if self.fake:
            while not Honeypot.login(self, connection, socket_address):
                Statistics.increase_failed_login(stats)
                Statistics.save(stats)
            else:
                Statistics.increase_correct_logins(stats)
        connection.sendto(self.motd.encode() + b"\n", socket_address)  # Send MOTD
        while True:
            try:
                connection.sendto(self.prompt, socket_address)
                data = format_string(connection.recv(1024))
                if is_data_valid(data):  # if data is valid
                    Honeypot.command_response(self, connection, socket_address, data)
                    print_message(
                        "client " + socket_address[0] + " tried command " + data
                    )
            # If connection is dropped / lost then break from loop and remove client from the client list
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                break
            except UnicodeDecodeError:  # Telnet Error ???
                pass

        print_warning(socket_address[0] + " disconnected!")
        Statistics.save(stats)
        self.clientList.remove(
            socket_address[0]
        )  # clientList is for only ACTIVE clients

    def command_response(self, connection, socket_address, command):
        response = None
        Honeypot.find_urls(self, command, socket_address)
        if "sudo" in command and command != "sudo":  # No sudo for you!
            response = (
                self.username.encode()
                + b" is not in the sudoers file. This incident will be reported.\n"
            )
        elif command == "whoami":
            response = self.username.encode() + b"\n"
        elif command == "pwd":
            response = b"/home/" + self.username.encode() + b"/\n"
        elif command == "hostname":
            response = self.hostname.encode() + b"\n"
        elif command == "exit":
            connection.shutdown(1)
        elif "wget" in command and "wget" != command:
            response = b"\n\n"
        elif "cd" in command:
            directory = command.split()
            if len(directory) > 1:
                response = (
                    b"cd: " + directory[1].encode() + b": No such file or directory\n"
                )
        else:  # If command is unknown
            try:  # Try to see if it is in the commands.json file
                response = self.commands[command].encode()
            except KeyError:  # if it is not
                command = command.split()  # Split command by spaces
                response = b"bash: " + command[0].encode() + b": command not found\n"
        if response is not None:
            connection.sendto(response, socket_address)

    def login(self, connection, socket_address):
        try:
            connection.sendto(b"Login: ", socket_address)
            username = connection.recv(1024)
            connection.sendto(b"Password: ", socket_address)
            password = connection.recv(1024)
            username = format_string(username)
            password = format_string(password)
            if username == self.username and password == self.password:
                print_message(
                    "client "
                    + socket_address[0]
                    + " logged in ({0}:{1})".format(username, password)
                )
                return True
            connection.sendto(b"\nLogin incorrect\n", socket_address)
            print_error(
                "client "
                + socket_address[0]
                + " tried {0}:{1}".format(username, password)
            )
            return False
            # If connection is dropped / lost
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return False
        except UnicodeDecodeError:
            # resend
            Honeypot.handle_client(self, connection, socket_address)

    def check_client_limit(self):
        if self.max != 0:
            if len(self.clientList) >= int(self.max):
                return True
        return False

    def listen(self):
        if Honeypot.check_client_limit(self):
            return
        self.sock.listen(1)
        connection, socket_address = self.sock.accept()
        print_message(socket_address[0] + " connected.")
        self.clientList.append(socket_address[0])  # Add connected client to client list
        if socket_address[0] not in self.IPList:
            self.IPList.append(socket_address[0])
        log_connector(socket_address[0] + "\n")
        t = threading.Thread(
            target=Honeypot.handle_client, args=(self, connection, socket_address)
        )  # Start thread to handle the connection
        t.daemon = True
        t.start()  # Start thread

    def capture_session(self):
        now = datetime.now()
        filename = now.strftime("%d-%m-%y-%H-%M-%S.pcap")
        os.system("tcpdump -i " + self.interface + " -w sessions/" + filename + " &")

    def export_config(self):
        j = {
            "IP": self.ipaddress,
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
            "autodownload": self.autoDownload,
        }
        json_settings = json.dumps(j)  # Parse python dict to JSON
        json_settings_obj = json.loads(json_settings)  # Load as JSON object
        with open(args.save, "a") as outFile:
            json.dump(json_settings_obj, outFile)

    def load_config(self, filename):
        config = read_json_file(filename)
        self.ipaddress = config["IP"]
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
        self.autoDownload = config["autodownload"]

    def find_urls(self, data, socket_address):
        url_regex = r"""(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](
        ?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad
        |ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca
        |cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk
        |fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir
        |is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml
        |mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn
        |pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td
        |tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw
        )/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s(
        )]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](
        ?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad
        |ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca
        |cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk
        |fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir
        |is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml
        |mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn
        |pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td
        |tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw
        )\b/?(?!@))) """
        links = re.findall(url_regex, data)
        if self.autoDownload:
            for link in links:
                os.system("wget -q -P Loot/ " + link + "")
                print_message("Saved Link: " + link)
        else:
            for link in links:
                print_message(socket_address[0] + " tried to access: " + link)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dystopia | A python Honeypot.")
    parser.add_argument(
        "--host",
        help="IP Address to host the Honeypot. Default: " + get_ip(),
        default=get_ip(),
    )
    parser.add_argument(
        "--port", "-P", help="specify a port to bind to", default=23, type=int
    )
    parser.add_argument(
        "--motd",
        "-m",
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
        "--max",
        "-M",
        help="max number of clients allowed to be connected at once default is unlimited",
        default=0,
        type=int,
    )
    parser.add_argument(
        "--login",
        "-f",
        help="create a fake login prompt (no encryption)",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--username",
        "-u",
        help="username for fake login prompt and the user for the Honeypot session default: 'ubuntu'",
        default="ubuntu",
    )
    parser.add_argument(
        "--password",
        "-p",
        help="password for fake login prompt. Default: 'P@$$W0RD'",
        default="P@$$W0RD",
    )
    parser.add_argument(
        "--hostname",
        "-H",
        help="Hostname of the Honeypot default: 'localhost'",
        default="localhost",
    )
    parser.add_argument(
        "--localhost",
        "-L",
        help="start Honeypot on localhost",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--capture",
        "-c",
        help="enable packet capturing using the tool Tcpdump",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--interface",
        "-i",
        help="interface to capture traffic on if --capture / -c is used and no interface is configured, the default "
        "is: 'eth0'",
        default="eth0",
    )
    parser.add_argument(
        "--save", "-s", help="save config to a json file E.g: '--save settings.json'"
    )
    parser.add_argument(
        "--load", "-l", help="load config from a json file E.g '--load settings.json'"
    )
    parser.add_argument(
        "--download",
        "-a",
        help="Automatically download links used by attackers",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--version",
        help="print version and exit",
        action="store_true",
        default=False,
    )
    args = parser.parse_args()
    if args.version:
        print(VERSION)
        exit()
    print_banner()
    s = Honeypot()
    Honeypot.bind(s)
    print_message("Waiting for connections...")
    while True:
        try:
            Honeypot.listen(s)
        except KeyboardInterrupt:
            break
