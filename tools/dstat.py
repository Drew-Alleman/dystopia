#!/usr/bin/python3
import json
from json import JSONDecodeError
import argparse
import urllib.request
from colorama import Fore
from prettytable import PrettyTable


statistics = "/var/log/dystopia/statistics.json"
key_file = "/var/log/dystopia/ipstack.key"


def print_message(message):
    print(Fore.GREEN + "[*] " + Fore.WHITE + message)


def print_error(message):
    print(Fore.RED + "[-] " + Fore.WHITE + message)


def print_warning(message):
    print(Fore.YELLOW + "[!] " + Fore.WHITE + message)


def read_json_file(filename):
    if filename is None:
        print_error("file was not found!")
        exit()
    try:
        with open(filename, "r") as outfile:
            data = json.load(outfile)
        return data
    except JSONDecodeError as e:
        print_error(
            "file: " + statistics + " might be corrupted! JSONDecodeError: " + str(e)
        )
        exit()
    except FileNotFoundError:
        print_error("file: '{}' was not found.".format(filename))
        exit()


def write_to_file(filename, data):
    try:
        with open(filename, "a+") as f:
            f.write(data)
    except FileNotFoundError:
        print_error("file: '{}' was not found.".format(filename))
        exit()


def get_access_key():
    try:
        with open(key_file, "r") as f:
            content = f.readlines()
        return content[0]
    except FileNotFoundError:
        return None


def get_geo_data(address):
    key = get_access_key()
    key = key.strip()
    if key is None or len(key) == 0:
        return None
    url = "http://api.ipstack.com/"
    url  = url + address.strip() + "?access_key=" + key
    try:
        with urllib.request.urlopen(url) as url:
            data = json.loads(url.read().decode())
        return data
    except urllib.error.URLError:
        print_error("Connection refused: "+url)
        exit()


class Statistics:
    def __init__(self):
        self.ips = []
        self.sort = args.sort
        self.update = args.update
        if self.update:
            print_message("Updating geolocation data!")
        self.filename = args.filename
        self.table = PrettyTable()
        self.table.field_names = [
            "IP Address",
            "Times Connected",
            "Failed Logins",
            "Correct Logins",
            "Continent Name",
            "Country Name",
            "Region Name",
            "Zip",
            "latitude",
            "longitude",
        ]
        if args.address is not None:
            self.address = args.address
        self.data = read_json_file(statistics)
        for ip, stat in self.data.items():
            self.ips.append(ip)

    def show_report(self):
        for ip in self.ips:
            self.table.add_row(
                [
                    ip,
                    self.data[ip]["Times Connected"],
                    self.data[ip]["Failed Logins"],
                    self.data[ip]["Correct Logins"],
                    self.data[ip]["Continent Name"],
                    self.data[ip]["Country Name"],
                    self.data[ip]["Region Name"],
                    self.data[ip]["Zip"],
                    self.data[ip]["latitude"],
                    self.data[ip]["longitude"],
                ]
            )
        print(self.table.get_string(sortby=self.sort, sortKey=lambda row: int(row[0])))
        if self.save is not None:
            Statistics.save(self)

    def show_address_report(self):
        try:
            self.table.add_row(
                [
                    self.address,
                    self.data[self.address]["Times Connected"],
                    self.data[self.address]["Failed Logins"],
                    self.data[self.address]["Correct Logins"],
                    self.data[self.address]["Continent Name"],
                    self.data[self.address]["Country Name"],
                    self.data[self.address]["Region Name"],
                    self.data[self.address]["Zip"],
                    self.data[self.address]["latitude"],
                    self.data[self.address]["longitude"],
                ]
            )
        except KeyError:
            print_error("Address: " + self.address + " not found!")
            exit()
        print(self.table)
        if self.save is not None:
            Statistics.save(self)

    def geolocation(self):
        for ip in self.ips:
            try:
                _t = self.data[ip]["Zip"]
                if self.update:
                    raise KeyError
            except KeyError:
                json_data = get_geo_data(ip)
                if json_data is None:
                    print_warning(
                        "Could not fetch geolocation data please put your api key here:"
                        + key_file
                    )
                    self.data[ip]["Continent Name"] = None
                    self.data[ip]["Country Name"] = None
                    self.data[ip]["Region Name"] = None
                    self.data[ip]["Zip"] = None
                    self.data[ip]["latitude"] = None
                    self.data[ip]["longitude"] = None
                else:
                    self.data[ip]["Continent Name"] = json_data["continent_name"]
                    self.data[ip]["Country Name"] = json_data["country_name"]
                    self.data[ip]["Region Name"] = json_data["region_name"]
                    self.data[ip]["Zip"] = json_data["zip"]
                    self.data[ip]["latitude"] = json_data["latitude"]
                    self.data[ip]["longitude"] = json_data["longitude"]

    def update_statistics_file(self):
        with open(statistics, "w+") as f:
            json.dump(self.data, f, indent=4, ensure_ascii=False)

    def save(self):
        html = self.table.get_html_string()
        if self.filename is not None:
            if self.filename.endswith(".html"):
                write_to_file(self.filename, html)
            else:
                self.filename = self.filename + ".html"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="dstat | Statistics tool for Dystopia")
    parser.add_argument("--address", "-a", help="ip address to investigate")
    parser.add_argument(
        "--report",
        "-r",
        help="show a general report",
        action="store_true",
        default=False,
    )
    parser.add_argument("--sort", "-s", help="sort the report table by row name")
    parser.add_argument(
        "--update",
        "-U",
        help="update geolocation entries",
        action="store_true",
        default=False,
    )
    parser.add_argument("--filename", "-f", help="Filename of report file")
    args = parser.parse_args()
    s = Statistics()
    Statistics.geolocation(s)
    Statistics.update_statistics_file(s)
    if args.report:
        Statistics.show_report(s)
    elif args.address is not None:
        Statistics.show_address_report(s)
