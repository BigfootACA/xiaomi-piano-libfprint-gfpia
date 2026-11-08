# SPDX-License-Identifier: GPL-2.0-or-later
#
# These used to live in the kernel tree and include its uapi headers directly.
# They do not need to: linux-api-headers has carried the TEE object ABI since
# 7.2, so the system headers are enough and this builds anywhere.

CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -Wformat=2 -Wstrict-prototypes

all: qcomtee-qseecom qcomtee-fs-supplicant xiaomi-fp-run

qcomtee-qseecom: qcomtee-qseecom.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

qcomtee-fs-supplicant: qcomtee-fs-supplicant.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -pthread -o $@ $< $(LDFLAGS)

xiaomi-fp-run: xiaomi-fp-run.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	$(RM) qcomtee-qseecom qcomtee-fs-supplicant xiaomi-fp-run

.PHONY: all clean
