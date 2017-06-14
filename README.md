check_cisco_health
==================

This plugin uses the bulk-get to get the enviroment state of cisco network equipment.

### Installation

In order to compile this plugin you will need the NET SNMP Development package (libsnmp-dev under Debian) and the standard compilation tools.

	make
	install -m755 check_cisco_health /usr/lib/nagios/plugins

### Usage

	check_cisco_health -h <hostname> -c <community> [-t <timeout>]

	Options:
	-h	address of device
	-c	community of the device with read permissions
	-t	sets the timeout (in ms)	
