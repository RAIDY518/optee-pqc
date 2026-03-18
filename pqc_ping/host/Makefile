CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

KEM_DIR  := ../ta/pqclean/kem
COMM_DIR := ../ta/pqclean/common

# ML-KEM-512 sources compiled into the host so that the normal world can
# perform encapsulation independently of the TA (cross-boundary workflow).
KEM_OBJS  := kem.o indcpa.o poly.o polyvec.o ntt.o cbd.o reduce.o \
             symmetric-shake.o verify.o
COMM_OBJS := fips202.o

OBJS := main.o randombytes_host.o $(KEM_OBJS) $(COMM_OBJS)

SYSROOT  ?= $(TEEC_EXPORT)/..
CFLAGS   += -Wall --sysroot=$(SYSROOT) \
            -I../ta/include -I$(TEEC_EXPORT)/include -I./include \
            -I$(KEM_DIR) -I$(COMM_DIR)
LDADD    += --sysroot=$(SYSROOT) -lteec -L$(TEEC_EXPORT)/lib

BINARY = optee_example_pqc_ping

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)

# Files in the host directory
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ML-KEM-512 library sources (compiled for normal world)
$(KEM_OBJS): %.o: $(KEM_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Common PQClean sources (fips202 / SHAKE)
$(COMM_OBJS): %.o: $(COMM_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@
