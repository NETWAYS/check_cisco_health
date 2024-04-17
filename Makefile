#
# Warning: you may need more libraries than are included here on the
# build line.  The agent frequently needs various libraries in order
# to compile pieces of it, but is OS dependent and we can't list all
# the combinations here.  Instead, look at the libraries that were
# used when linking the snmpd master agent and copy those to this
# file.
#

CC ?= gcc

OBJS1=check_cisco_health.o
TARGETS=check_cisco_health

CFLAGS += -I. `net-snmp-config --cflags` -Wall -Wextra
BUILDLIBS=`net-snmp-config --libs`
BUILDAGENTLIBS=`net-snmp-config --agent-libs`

# shared library flags (assumes gcc)
DLFLAGS=-fPIC -shared

.PHONY: debug clean all
all: build
build: $(TARGETS)

check_cisco_health: check_cisco_health.o
	$(CC) -o check_cisco_health $(OBJS1) $(BUILDLIBS)

debug: CFLAGS += -DDEBUG
debug: CFLAGS += -O0
debug: clean all


clean:
	rm -f $(OBJS1) $(TARGETS)

