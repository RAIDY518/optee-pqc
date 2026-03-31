
# pqc_ping — Post-Quantum Cryptography on OP-TEE

An OP-TEE Trusted Application that integrates ML-KEM-512 (FIPS 203) and ML-DSA-44 (FIPS 204) inside the ARM TrustZone secure world. The project provides a benchmarking and validation framework for evaluating PQC feasibility on constrained TEE platforms.

## Architecture

```
Normal World (REE)                     Secure World (TEE)
  host/main.c                           ta/pqc_ping_ta.c
    |                                     |
    |--- TEEC_InvokeCommand() -------->   TA_InvokeCommandEntryPoint()
    |                                     |--- cmd_kem.c    (ML-KEM-512)
    |<-- shared secret / signature ---    |--- cmd_sig.c    (ML-DSA-44)
    |                                     |--- cmd_store.c  (secure storage)
    |                                     |--- cmd_bench.c  (micro-benchmarks)
    |                                     |--- pqclean/     (vendored PQClean)
```

**Crypto libraries:** PQClean clean-room C implementations compiled directly into the TA. Random bytes from `TEE_GenerateRandom()`. No external crypto dependencies.

## Algorithm sizes

| | ML-KEM-512 | ML-DSA-44 |
|---|---|---|
| Public key | 800 B | 1312 B |
| Secret key | 1632 B | 2560 B |
| Ciphertext / Signature | 768 B | 2420 B |
| Shared secret | 32 B | -- |

## Build

### Prerequisites

```bash
export TEEC_EXPORT=<sysroot>/usr
export TA_DEV_KIT_DIR=<optee_os>/out/arm/export-ta_arm64
export CROSS_COMPILE=<toolchain>/aarch64-linux-gnu-
```

### Compile

```bash
make        # builds host binary + TA
make clean
```

### Outputs

- Host binary: `host/optee_example_pqc_ping` (symlinked as `host/pqc_ping`)
- TA binary: `ta/49d90b2c-dcb4-4f62-8bdf-ce538fc14dca.ta`

## Deploy to target

```bash
# Copy to QEMU guest or physical board
cp ta/*.ta   /lib/optee_armtz/
cp host/pqc_ping /usr/bin/
cp -r scripts/ /root/scripts/
```

## QEMU run

```bash
cd <optee>/build && make run \
  QEMU_EXTRA_ARGS="-virtfs local,path=<optee>/tee-storage,mount_tag=teestore,security_model=mapped-file,id=teestore"
```

The `-virtfs` flag is required for secure storage tests (`kem-validate`, `sig-validate`, key lifecycle commands).

## Usage

### One-click test scripts (recommended)

```bash
# Functional validation (15 tests including harden-test)
./scripts/run_func.sh

# Full benchmark suite (12 path + 4 micro, all with CSV)
./scripts/run_bench.sh

# Quick smoke test with fewer iterations
LOOP=10 WARMUP=2 MICRO_LOOP=5 MICRO_WARMUP=2 ./scripts/run_bench.sh /tmp/quick
```

### Individual commands

```bash
pqc_ping --cmd <command> [--loop N] [--warmup M] [--csv path]
```

#### Baseline
| Command | Description |
|---|---|
| `empty` | No-op TEE round-trip (baseline latency) |
| `ping` | Increment value round-trip |
| `info` | Report algorithm sizes (one-shot) |

#### KEM (ML-KEM-512)
| Command | Description |
|---|---|
| `kem-selftest` | Full keygen+encaps+decaps inside TA, returns PASS/FAIL |
| `kem-keygen` | Generate keypair, return pk+sk to host |
| `kem-encaps` | Encapsulate with pk, return ct+ss |
| `kem-decaps` | Decapsulate with sk+ct, return ss |
| `kem-crosstest` | **Cross-boundary:** TA holds sk, host encaps, TA decaps, compare shared secrets |
| `kem-stress` | keygen+encaps+decaps all on TA stack (memory pressure test) |

#### SIG (ML-DSA-44)
| Command | Description |
|---|---|
| `sig-keygen` | Generate signing keypair, sk stays in session |
| `sig-sign` | Sign message with session sk |
| `sig-crosstest` | **Cross-boundary:** TA signs, host verifies with PQClean |
| `sig-stress` | keygen+sign+verify all on TA stack (memory pressure test) |

#### Key lifecycle (secure storage)
| Command | Description |
|---|---|
| `kem-keygen-save` / `sig-keygen-save` | Keygen + persist to secure storage |
| `kem-load` / `sig-load` | Restore sk from secure storage |
| `kem-status` / `sig-status` | Report key state (absent/in-memory/persisted) |
| `kem-destroy` / `sig-destroy` | Zeroize memory + delete from storage |
| `kem-validate` / `sig-validate` | End-to-end: load + get-pk + crosstest (one-shot) |

#### Micro-benchmarks (TA-internal timing)
| Command | Description |
|---|---|
| `kem-keygen-micro` | Batched keygen timed inside TA via `TEE_GetSystemTime()` |
| `kem-decaps-micro` | Batched decaps timed inside TA |
| `sig-keygen-micro` | Batched keygen timed inside TA |
| `sig-sign-micro` | Batched sign timed inside TA |

#### Hardening
| Command | Description |
|---|---|
| `harden-test` | 10 malformed-input tests + 2 normal-path checks |
| `mem-info` | Report TA stack/data/heap configuration |

### Benchmark types explained

**Path benchmarks** (`--loop N --warmup M`) measure the full REE-to-TEE round-trip latency using `clock_gettime(CLOCK_MONOTONIC_RAW)` on the host side. They include world-switch overhead and parameter marshalling. Output: min/avg/p50/p95/p99/max in nanoseconds.

**Micro-benchmarks** (`kem-keygen-micro` etc.) time crypto operations inside the TA using `TEE_GetSystemTime()` (1 ms granularity). Each outer sample batches N_INNER iterations to overcome the low resolution. They isolate the pure crypto cost from TEE boundary overhead.

**Crosstest** commands split work across worlds: one side generates a key, the other performs the complementary operation, then both compare results. This validates that the PQClean implementations produce interoperable outputs across the REE/TEE boundary.

## Result directory layout

```
results/
  logs/          # Full terminal output per run
    func_20260330_143022.log
    bench_20260330_143022.log
  csv/           # Per-command CSV: iter,cmd,delta_ns,pass
    kem_crosstest_20260330_143022.csv
    sig_sign_micro_20260330_143022.csv
    ...
  summary/       # One-line pass/fail + metadata
    func_20260330_143022.txt
    bench_20260330_143022.txt
    final_summary.md
```

## TA memory configuration

Current defaults in `ta/user_ta_header_defines.h`:

```c
#define TA_STACK_SIZE  (64 * 1024)   /* 64 KB */
#define TA_DATA_SIZE   (32 * 1024)   /* 32 KB */
```

**64 KB stack** is confirmed sufficient for all commands including `sig-stress` (which places ~6.3 KB of ML-DSA-44 buffers on the stack plus crypto library call-chain overhead).

**32 KB heap** is sufficient for micro-benchmarks (which heap-allocate crypto buffers) and secure storage operations.

Use `ta/memprof.sh` to binary-search for minimum values:
```bash
./ta/memprof.sh --stack 32 --data 16    # try smaller
./ta/memprof.sh --show                  # display current
./ta/memprof.sh --restore               # reset to original
```

Note: fine-grained minimum profiling (the table in `ta/memprof_results.md`) was not completed. The 64/32 KB defaults are conservative and validated by stress tests, but the exact minimums are not characterized.

## Code size overhead (day 11)

Measured via `ta/sizeprof.sh`:

| Config | .text | .ta file | Delta vs baseline |
|---|---|---|---|
| baseline | 84,048 | 118,312 | -- |
| KEM (ML-KEM-512) | 93,140 | 130,632 | +9 KB .text, +12 KB .ta |
| SIG (ML-DSA-44) | 96,284 | 134,696 | +12 KB .text, +16 KB .ta |
| KEM+SIG | 104,148 | 147,016 | +20 KB .text, +29 KB .ta |

## Hardening (day 12)

- All sensitive buffers (sk, ss) explicitly zeroized before free
- Session state zeroized on close
- Host-side sensitive buffers zeroized at exit
- Ciphertext size strictly validated (exact match required)
- Message size validated (reject empty and >4096)
- Session logs demoted to DMSG (not visible in production)
- Failed storage loads zeroize destination buffer

## Conditional compilation

The TA supports building with only KEM, only SIG, or both via flags in `ta/sub.mk`:

```makefile
cflags-y += -DPQC_ENABLE_KEM    # comment out to exclude ML-KEM-512
cflags-y += -DPQC_ENABLE_SIG    # comment out to exclude ML-DSA-44
```

## Known limitations

1. **Not production-grade.** This is a research prototype for evaluating PQC feasibility on TEE. The PQClean implementations are reference C (not constant-time on all platforms, not formally verified).

2. **Secure storage is development-mode.** OP-TEE's `TEE_STORAGE_PRIVATE` on QEMU uses an emulated REE filesystem (`tee-supplicant`). Production deployments require hardware-backed storage (eMMC RPMB or similar).

3. **Memory profiling is partial.** The 64/32 KB stack/data defaults are validated by stress tests but the exact minimum thresholds were not fully characterized via binary search.

4. **Micro-benchmark resolution is limited.** `TEE_GetSystemTime()` has 1 ms granularity. Batching (N_INNER=100 for KEM, N_INNER=5 for SIG) provides ~10-200 us effective resolution, which may be insufficient for sub-microsecond operations.

5. **Single algorithm per family.** Only ML-KEM-512 and ML-DSA-44 are integrated. Higher security levels (ML-KEM-768/1024, ML-DSA-65/87) would require larger stack/heap and increase code size.

6. **No hybrid mode.** There is no classical+PQC hybrid key exchange or signature. This is pure PQC only.

7. **Host-side zeroization uses `memset`.** A sufficiently aggressive compiler could optimize away `memset` on buffers that are not subsequently read. TA-side uses `TEE_MemFill` which is guaranteed not to be elided.

## Development timeline

| Day | Milestone |
|---|---|
| 1-4 | Baseline TA: empty, ping, info commands with latency benchmarking |
| 5 | ML-KEM-512 integration: keygen, encaps, decaps, kem-crosstest |
| 6 | ML-DSA-44 integration: sig-keygen, sig-sign, sig-crosstest |
| 7 | Secure storage: key persistence and lifecycle management |
| 8-9 | Refactor into focused files, TA-internal micro-benchmarks |
| 10 | Memory profiling tools, stress tests, benchmarked stress output |
| 11 | Code size profiling: conditional compilation, 4-config delta table |
| 12 | Hardening: zeroization, input validation, harden-test |
| 13 | Reproducible test scripts: run_func.sh, run_bench.sh |
| 14 | Documentation, final summary, handoff |
