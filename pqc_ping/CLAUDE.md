# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

### Prerequisites (environment variables)
```bash
export TEEC_EXPORT=/home/raidy518/tee-pqc/optee/out-br/per-package/optee_examples_ext/host/aarch64-buildroot-linux-gnu/sysroot/usr
export TA_DEV_KIT_DIR=/home/raidy518/tee-pqc/optee/optee_os/out/arm/export-ta_arm64
export CROSS_COMPILE=/home/raidy518/tee-pqc/optee/toolchains/aarch64/bin/aarch64-linux-gnu-
```

### Build / Clean
```bash
make        # builds both host binary and TA
make clean
```

### Build outputs
- Host binary: `host/optee_example_pqc_ping`
- TA binary: `ta/49d90b2c-dcb4-4f62-8bdf-ce538fc14dca.ta`

### Deployment
- Copy `*.ta` to `/lib/optee_armtz/` on target device
- Copy host binary to `/usr/bin/` on target
- Ensure `tee-supplicant` daemon is running

### Runtime usage (on target)
```bash
./optee_example_pqc_ping --cmd empty|ping|info [--loop N] [--warmup M] [--csv path]
```

## Architecture

This is an **OP-TEE Trusted Application** split into two worlds:

### Normal World (REE): `host/main.c`
Benchmarking client that:
- Connects to the TEE via `TEEC_InitializeContext()` / `TEEC_OpenSession()`
- Invokes TA commands and measures round-trip latency using `clock_gettime(CLOCK_MONOTONIC_RAW)`
- Computes statistics: min/avg/p50/p95/p99/max
- Optionally exports per-iteration data to CSV

### Trusted World (TEE): `ta/pqc_ping_ta.c`
Trusted Application (UUID: `49d90b2c-dcb4-4f62-8bdf-ce538fc14dca`) that handles three commands:
- `TA_PQC_PING_CMD_EMPTY (0)` — no-op baseline
- `TA_PQC_PING_CMD_PING (1)` — increments a value (round-trip cost)
- `TA_PQC_PING_CMD_INFO (2)` — returns key/signature sizes for ML-KEM-512 and ML-DSA-44

### PQClean Crypto Libraries: `ta/pqclean/`
Vendored post-quantum implementations compiled into the TA:
- `kem/` — ML-KEM-512 (NIST FIPS 203): keypair, encaps, decaps
- `sig/` — ML-DSA-44 (NIST FIPS 204): keypair, sign, verify
- `common/` — Shared utilities: `randombytes.c` wraps `TEE_GenerateRandom()`, FIPS 202 (SHA-3/Keccak), SHA-2, SP 800-185 (cSHAKE/KMAC)

### Key interface files
- `ta/include/pqc_ping_ta.h` — TA UUID, command IDs, shared data structures (`pqc_info_out`)
- `ta/include/pqc_algo.h` — Conditional compilation macros for algorithm selection (ML-KEM-512 / ML-DSA-44 vs. legacy Kyber/Dilithium names)
- `ta/user_ta_header_defines.h` — TA metadata: UUID, stack size (2 KB), heap size (32 KB)

### TA source list: `ta/sub.mk`
Defines which `.c` files are compiled into the TA (add new source files here).

### Algorithm sizes (for reference)
| | ML-KEM-512 | ML-DSA-44 |
|---|---|---|
| Public key | 800 B | 1312 B |
| Secret key | 1632 B | 2560 B |
| Ciphertext/Signature | 768 B | 2420 B |
| Shared secret | 32 B | — |
