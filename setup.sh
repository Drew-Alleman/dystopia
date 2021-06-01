#!/bin/bash

info_print() {
	echo -e "\e[32m[+]\e[0m $1" 

}

error_print() {
	echo -e "\e[31m[-]\e[0m $1"
}


warning_print() {
	echo -e "\e[93m $1"
}

install_tcpdump() {
echo -e -n "\e[32m[+]\e[0m Would you like to install 'Tcpdump'? [\e[33mY\e[0m/\e[31mn\e[0m] " 
read response
if [[ "$response" == "y"  ||  "$response" == "Y" ]]; then
	info_print "1 --> Install for Arch Linux"
	info_print "2 --> Install for Debian Users"
	read install_response
	if [ "$install_response" == "1" ]; then
		sudo pacman -S tcpdump
	elif [ "$install_response" == "2" ]; then
		sudo apt-get install tcpdump
	else
		error_print "Desired Input: '1,2'"
	fi
else
	error_print "Desired Input: Y/n"
fi

}

install_pips() {
	info_print "Installing required python packages."
	pip install -r requirements.txt
}

create_dirs_and_files() {
	info_print "Creating needed directorys!"
	mkdir Loot
	mkdir sessions
	touch blacklist.txt
}

if [ "$EUID" -ne 0 ]
  then error_print "Please run as root"
  exit
fi

install_pips
install_tcpdump
create_dirs_and_files
