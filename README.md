# check_cisco_health

This plugin uses the bulk-get to get the enviroment state of cisco network equipment.
It supports SNMP version 2c and 3.

## Installation

### Compilation

In order to compile this plugin you will need the NET SNMP Development package (`libsnmp-dev` under Debian) and the standard compilation tools (`make`, a C compiler like `gcc` or `clang`).

Executing

```
make
```

should then produce an executable called `check_cisco_health`.

### Installation

All runtime dependencies (shared objects) can be retrieved via `ldd check_cisco_health`.
Most notable is `libnetsnmp`, which can be install under Debian with the package `libsnmp`.

Apart from that, the executable can be placed in a directory of personal choice,
for example:

```
install -m755 check_cisco_health /usr/lib/nagios/plugins
```

or

```
install -m755 check_cisco_health /usr/local/bin
```

### Usage

```
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
```
