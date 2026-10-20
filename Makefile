# SPDX-License-Identifier: GPL-2.0-or-later
CC ?= cc
PYTHON ?= python3
CFLAGS ?= -O2 -g
WARNINGS := -Wall -Wextra -Werror
PREFIX ?= /usr/local
sbindir ?= $(PREFIX)/sbin
INSTALL ?= install

.PHONY: all check install clean
all: pppoe-relay

pppoe-relay: src/pppoe-relay.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

tests/pppoe-peer: tests/pppoe-peer.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

check: pppoe-relay tests/pppoe-peer
	@test "$$(id -u)" -eq 0 || { echo 'Integration tests require root and network namespace capabilities.' >&2; exit 1; }
	$(PYTHON) tests/test_relay.py

install: pppoe-relay
	$(INSTALL) -d $(DESTDIR)$(sbindir)
	$(INSTALL) -m 0755 pppoe-relay $(DESTDIR)$(sbindir)/pppoe-relay

clean:
	$(RM) pppoe-relay tests/pppoe-peer
