#!/usr/bin/python3
import json
from json import JSONDecodeError
import argparse
from colorama import Fore
from prettytable import PrettyTable

statistics = "/var/log/dystopia/statistics.json"

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


class Statistics:
    def __init__(self):
        self.ips = []
        self.sort = args.sort
        self.filename = args.filename
        self.table = PrettyTable()
        self.table.field_names = [
            "IP Address",
            "Times Connected",
            "Failed Logins",
            "Correct Logins",
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
                ]
            )
        print(self.table.get_string(sortby=self.sort, sortKey=lambda row: int(row[0])))
        if self.save is not None:
            Statistics.save(self)

    def show_address_report(self):
        self.table.field_names = [
            "IP Address",
            "Times Connected",
            "Failed Logins",
            "Correct Logins",
        ]
        self.table.add_row(
            [
                self.address,
                self.data[self.address]["Times Connected"],
                self.data[self.address]["Failed Logins"],
                self.data[self.address]["Correct Logins"],
            ]
        )
        print(self.table)
        if self.save is not None:
            Statistics.save(self)

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
    parser.add_argument("--filename", "-f", help="Filename of report file")
    args = parser.parse_args()
    s = Statistics()
    if args.report:
        Statistics.show_report(s)
    elif args.address is not None:
        Statistics.show_address_report(s)
