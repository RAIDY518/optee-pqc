CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

KEM_DIR  := ../ta/pqclean/kem
SIG_DIR  := ../ta/pqclean/sig
COMM_DIR := ../ta/pqclean/common

# ML-KEM-512 sources compiled into the host (normal-world encapsulation).
# Compiled with KEM_DIR in include path only — must not see SIG_DIR headers.
KEM_OBJS  := kem.o indcpa.o poly.o polyvec.o ntt.o cbd.o reduce.o \
             symmetric-shake.o verify.o

# ML-DSA-44 sources compiled into the host (normal-world verification).
# Compiled with SIG_DIR in include path only — must not see KEM_DIR headers.
# Prefixed "s-" to avoid object name collision with KEM objects of same name.
SIG_OBJS  := s-sign.o s-packing.o s-poly.o s-polyvec.o s-ntt.o \
             s-reduce.o s-rounding.o s-symmetric-shake.o

COMM_OBJS := fips202.o

OBJS := main.o randombytes_host.o $(KEM_OBJS) $(SIG_OBJS) $(COMM_OBJS)

SYSROOT  ?= $(TEEC_EXPORT)/..
CFLAGS   += -Wall --sysroot=$(SYSROOT) \
            -I../ta/include -I$(TEEC_EXPORT)/include -I./include \
            -I$(COMM_DIR)
LDADD    += --sysroot=$(SYSROOT) -lteec -L$(TEEC_EXPORT)/lib

# Per-library CFLAGS (only the relevant crypto include dir, not both).
KEM_CFLAGS := $(CFLAGS) -I$(KEM_DIR)
SIG_CFLAGS := $(CFLAGS) -I$(SIG_DIR)

BINARY = optee_example_pqc_ping

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)

# Files in the host directory (main.c, randombytes_host.c)
# main.c needs both KEM and SIG includes for the api.h headers
main.o: main.c
	$(CC) $(CFLAGS) -I$(KEM_DIR) -I$(SIG_DIR) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ML-KEM-512 library sources (compiled for normal world, KEM includes only)
$(KEM_OBJS): %.o: $(KEM_DIR)/%.c
	$(CC) $(KEM_CFLAGS) -c $< -o $@

# ML-DSA-44 library sources (compiled for normal world, SIG includes only)
$(SIG_OBJS): s-%.o: $(SIG_DIR)/%.c
	$(CC) $(SIG_CFLAGS) -c $< -o $@

# Common PQClean sources (fips202 / SHAKE)
$(COMM_OBJS): %.o: $(COMM_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@
