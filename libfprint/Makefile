# SPDX-License-Identifier: GPL-2.0-or-later

ifeq ($(origin CC), default)
CC := $(CROSS_COMPILE)gcc
endif

# linux-api-headers carries the TEE object ABI, so the system headers do.
CPPFLAGS += -D__EXPORTED_HEADERS__
CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -Wformat=2 -Wstrict-prototypes

all: gfpia-test

gfpia-test: gfpia-test.c gfpia.c gfpia-tee.c gfpia.h gfpia-tee.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ gfpia-test.c gfpia.c gfpia-tee.c $(LDFLAGS)

clean:
	$(RM) gfpia-test

.PHONY: all clean
