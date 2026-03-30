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

# ML-KEM-512 sources — compiled with KEM_DIR only (avoids sig/ header collision)
KEM_OBJS  := kem.o indcpa.o poly.o polyvec.o ntt.o cbd.o reduce.o \
             symmetric-shake.o verify.o

# ML-DSA-44 sources — compiled with SIG_DIR only (prefixed to avoid name clash)
SIG_OBJS  := s-sign.o s-packing.o s-poly.o s-polyvec.o s-ntt.o \
             s-reduce.o s-rounding.o s-symmetric-shake.o

COMM_OBJS := fips202.o

HOST_OBJS := main.o bench.o cmd_kem.o cmd_sig.o cmd_store.o cmd_bench.o cmd_harden.o randombytes_host.o

OBJS := $(HOST_OBJS) $(KEM_OBJS) $(SIG_OBJS) $(COMM_OBJS)

SYSROOT  ?= $(TEEC_EXPORT)/..
CFLAGS   += -Wall --sysroot=$(SYSROOT) \
            -I../ta/include -I$(TEEC_EXPORT)/include -I./include \
            -I$(COMM_DIR)
LDADD    += --sysroot=$(SYSROOT) -lteec -L$(TEEC_EXPORT)/lib

KEM_CFLAGS := $(CFLAGS) -I$(KEM_DIR)
SIG_CFLAGS := $(CFLAGS) -I$(SIG_DIR)

BINARY = optee_example_pqc_ping
ALIAS  = pqc_ping

.PHONY: all
all: $(BINARY)
	ln -sf $(BINARY) $(ALIAS)

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY) $(ALIAS)

# Host sources — main.c and cmd_kem/sig include both crypto api headers
main.o: main.c
	$(CC) $(CFLAGS) -I$(KEM_DIR) -I$(SIG_DIR) -c $< -o $@

cmd_kem.o: cmd_kem.c
	$(CC) $(KEM_CFLAGS) -c $< -o $@

cmd_sig.o: cmd_sig.c
	$(CC) $(SIG_CFLAGS) -c $< -o $@

cmd_harden.o: cmd_harden.c
	$(CC) $(CFLAGS) -I$(KEM_DIR) -I$(SIG_DIR) -c $< -o $@

# Generic rule for remaining host sources (bench.o, randombytes_host.o)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ML-KEM-512 library sources
$(KEM_OBJS): %.o: $(KEM_DIR)/%.c
	$(CC) $(KEM_CFLAGS) -c $< -o $@

# ML-DSA-44 library sources
$(SIG_OBJS): s-%.o: $(SIG_DIR)/%.c
	$(CC) $(SIG_CFLAGS) -c $< -o $@

# Common PQClean sources
$(COMM_OBJS): %.o: $(COMM_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@
