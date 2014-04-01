prefix      := /usr/local
exec_prefix := $(prefix)
bindir       = $(exec_prefix)/bin

CC      = gcc
CFLAGS  = -std=gnu99 -Wall -Wextra -O3 -march=native
INSTALL = install

.PHONY: install clean
check-email: check-email.c
	$(CC) $(CFLAGS) $(shell curl-config --cflags) $(LDFLAGS) $(shell curl-config --libs) -lnetrc -o $@ $<
install: check-email
	$(INSTALL) check-email $(bindir)
clean:
	$(RM) check-email
