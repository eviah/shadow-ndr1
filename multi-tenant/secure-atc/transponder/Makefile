# SHADOW-ATC transponder reference build.
#
# Two targets:
#   make host    - POSIX smoke build with stub HSM/AEAD primitives.
#                  Validates that the C source is syntactically clean
#                  and the protocol logic links.
#   make flight  - Cross-compiled flight build. Requires the BSP
#                  to provide real HSM/AEAD/RNG drivers (see
#                  docs/02-hsm-config.md). Fails by design if BSP
#                  is not present in the include/lib path.

CC      ?= cc
CSTD    ?= -std=c11
INCLUDE := -Iinclude -Isrc

WARN := -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow \
        -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition \
        -Wpointer-arith -Wcast-qual -Wcast-align \
        -Wstack-usage=2048 -Wno-unused-parameter

HARDEN_HOST := -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2 -g
HARDEN_FLIGHT := -ffreestanding -fno-builtin -fno-common \
                 -fstack-protector-strong -fdata-sections -ffunction-sections \
                 -O2 -g

SRC_LIB := src/protocol.c src/knock.c src/crypto.c src/session.c
SRC_HOST := $(SRC_LIB) src/stubs.c src/main.c
OBJ_HOST := $(SRC_HOST:.c=.o)

.PHONY: host flight clean

host: shadow-atc-transponder

shadow-atc-transponder: $(OBJ_HOST)
	$(CC) $(CSTD) $(WARN) $(HARDEN_HOST) $(INCLUDE) -o $@ $^

%.o: %.c
	$(CC) $(CSTD) $(WARN) $(HARDEN_HOST) $(INCLUDE) -c -o $@ $<

flight:
	$(error 'flight' target requires the BSP — supply CC, ARFLAGS, and BSP_OBJS)

clean:
	rm -f shadow-atc-transponder $(OBJ_HOST)
