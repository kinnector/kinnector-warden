# Makefile for kinnector-warden EDR daemon and operator CLI

PREFIX ?= /usr/local
SBINDIR = $(PREFIX)/sbin
BINDIR = $(PREFIX)/bin
CONFDIR = /etc/kinnector
VARDIR = /var/quarantine/kinnector
RUNDIR = /var/run/kinnector

DAEMON_BIN = target/release/kinnector-warden
CLI_BIN = target/release/warden-cli

.PHONY: all build install uninstall clean

all: build

build:
	cargo build --release
	cargo build --release --manifest-path warden-cli/Cargo.toml

install: build
	# Create required system directories
	install -d $(DESTDIR)$(SBINDIR)
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(CONFDIR)
	install -d $(DESTDIR)$(VARDIR)
	install -d $(DESTDIR)$(RUNDIR)

	# Install binaries
	install -m 0755 $(DAEMON_BIN) $(DESTDIR)$(SBINDIR)/kinnector-warden
	install -m 0755 $(CLI_BIN) $(DESTDIR)$(BINDIR)/warden-cli

	# Install default configuration if not already present
	if [ ! -f $(DESTDIR)$(CONFDIR)/core.conf ]; then \
		install -m 0640 core.conf.template $(DESTDIR)$(CONFDIR)/core.conf; \
	fi

	# Set quarantine directory permissions
	chmod 0750 $(DESTDIR)$(VARDIR)

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/kinnector-warden
	rm -f $(DESTDIR)$(BINDIR)/warden-cli
	@echo "Binaries removed. Configuration in $(CONFDIR) and quarantine in $(VARDIR) have been preserved."

clean:
	cargo clean
