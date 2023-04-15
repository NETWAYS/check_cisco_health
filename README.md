check_cisco_health
==================

<<<<<<< HEAD
This plugin uses the bulk-get to get the enviroment state of cisco network equipment.
It supports SNMP version 2c and 3.

### Installation

In order to compile this plugin you will need the NET SNMP Development package (libsnmp-dev under Debian) and the standard compilation tools.

	make
	install -m755 check_cisco_health /usr/lib/nagios/plugins

### Usage
	SNMPv2c:
	check_cisco_health -h <hostname> -c <community> [-t <timeout>]
	
	SNMPv3:	
	check_cisco_health -h <hostname> -u <user> [-j (SHA|MD5) -J <auth phrase> -k (AES|DES) -K <priv phrase> -t <timeout>]


	Options:
	-h	address of device
	-c	community of the device with read permissions
	-j	SNMPv3 Auth Protocol (SHA|MD5)
	-J	SNMPv3 Auth Phrase
	-k	SNMPv3 Privacy Protocol (AES|DES)
	-K	SNMPv3 Privacy Phrase
	-u	SNMPv3 User
	-t	sets the timeout (in ms)
