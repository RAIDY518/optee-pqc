# pqc_ping — Final Summary

**Project:** Post-Quantum Cryptography on OP-TEE (ARM TrustZone)
**Date:** 2026-03-30
**Duration:** 14 days

## What was built

A complete OP-TEE Trusted Application integrating ML-KEM-512 (FIPS 203) and ML-DSA-44 (FIPS 204) inside the ARM TrustZone secure world, with benchmarking, secure storage, and hardening.

## Deliverables

| Component | Description |
|---|---|
| TA binary | `49d90b2c-dcb4-4f62-8bdf-ce538fc14dca.ta` — PQC-enabled Trusted Application |
| Host binary | `pqc_ping` — CLI benchmarking and validation client |
| 28 commands | Baseline (3), KEM (6), SIG (4), key lifecycle (10), micro-bench (4), hardening (1) |
| Test scripts | `run_func.sh` (15 tests), `run_bench.sh` (16 benchmarks with CSV) |
| Profiling tools | `memprof.sh` (memory), `sizeprof.sh` (code size) |

## Key metrics

### Code size overhead (compiled into TA)

| Config | .text | .ta file | Delta |
|---|---|---|---|
| baseline | 84 KB | 118 KB | -- |
| KEM only | 93 KB | 131 KB | +9 / +12 KB |
| SIG only | 96 KB | 135 KB | +12 / +16 KB |
| KEM+SIG | 104 KB | 147 KB | +20 / +29 KB |

### Memory requirements

| Resource | Value | Notes |
|---|---|---|
| TA_STACK_SIZE | 64 KB | Sufficient for all paths including sig-stress |
| TA_DATA_SIZE | 32 KB | Sufficient for micro-benchmarks and storage |

## Hardening

- All sensitive buffers (sk, ss) zeroized before free
- Session state zeroized on close
- Ciphertext size strictly validated (exact match)
- Message size validated (reject empty and >4096 B)
- Session logs demoted to DMSG
- 10 malformed-input tests + 2 normal-path checks in `harden-test`

## Known limitations

1. Research prototype, not production-grade (reference C, not constant-time on all platforms)
2. Secure storage is development-mode (QEMU emulated filesystem)
3. Memory profiling partial (64/32 KB validated but exact minimums not characterized)
4. Micro-benchmark resolution limited by 1 ms TEE_GetSystemTime granularity
5. Single algorithm per family (ML-KEM-512 and ML-DSA-44 only)
6. No hybrid classical+PQC mode
7. Host-side zeroization uses `memset` (compiler may optimize away)

## Reproduction

```bash
# Build
make

# Deploy to target
cp ta/*.ta /lib/optee_armtz/
cp host/pqc_ping /usr/bin/
cp -r scripts/ /root/scripts/

# Run all functional tests
./scripts/run_func.sh

# Run all benchmarks
./scripts/run_bench.sh
```

## Development timeline

| Day | Milestone |
|---|---|
| 1-4 | Baseline TA: empty, ping, info + latency benchmarking |
| 5 | ML-KEM-512: keygen, encaps, decaps, kem-crosstest |
| 6 | ML-DSA-44: sig-keygen, sig-sign, sig-crosstest |
| 7 | Secure storage: key persistence and lifecycle |
| 8-9 | Refactor + TA-internal micro-benchmarks |
| 10 | Memory profiling, stress tests |
| 11 | Code size profiling, conditional compilation |
| 12 | Hardening: zeroization, input validation, harden-test |
| 13 | Reproducible test scripts |
| 14 | Documentation, final summary, handoff |
