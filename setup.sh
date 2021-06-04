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
info_print "Tcpdump is used to capture dystopia sessions!"
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
fi

}

install_pips() {
	info_print "Installing required python packages."
	pip install -r requirements.txt
	pip install prettytable
}

create_dirs_and_files() {
	info_print "Creating needed directorys!"
	mkdir -p Loot
	mkdir -p sessions
	sudo mkdir -p /var/log/dystopia
	sudo mv statistics.json /var/log/dystopia/statistics.json
	sudo touch /var/log/dystopia/connections.txt
	echo -e -n "\e[32m[+]\e[0m Would you like to setup geolocation tracking via ipstack (free) [\e[33mY\e[0m/\e[31mn\e[0m] "
	read response
	if [[ "$response" == "y"  ||  "$response" == "Y" ]]; then
		info_print "URL: https://ipstack.com/signup/free"
		echo -e -n "\e[32m[+]\e[0m API KEY: "
		read key
		sudo echo $key > /var/log/dystopia/ipstack.key
	fi

}


install_pips
install_tcpdump
create_dirs_and_files
