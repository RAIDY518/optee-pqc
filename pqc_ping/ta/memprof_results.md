# Day 10 — TA Memory Profiling Results

## Failure Mode Definitions

| Mode | Description |
|------|-------------|
| **build_fail** | TA fails to compile or link (e.g., size too small for static data) |
| **boot_fail** | TA binary loads but `TEEC_OpenSession()` fails (OP-TEE rejects the TA at load time) |
| **runtime_fail** | Session opens but command returns error, crashes, or hangs during execution |

## Search Strategy

Halving descent from current defaults, then 1 KB fine-grain sweep near the boundary:
- Start at current value (stack 128 KB, data 32 KB)
- Halve repeatedly until first failure
- Sweep upward in 1 KB steps from failure to find minimum passing value

One dimension varied at a time; the other held at its known-good default.

## Results Table

| config | validation_cmd | min_pass_stack | fail_stack | stack_failure_mode | min_pass_data | fail_data | data_failure_mode |
|--------|----------------|----------------|------------|--------------------|---------------|-----------|-------------------|
| baseline | `ping --loop 10` | KB | KB | | KB | KB | |
| KEM | `kem-crosstest --loop 5` | KB | KB | | KB | KB | |
| SIG | `sig-crosstest --loop 5` | KB | KB | | KB | KB | |

## Heavier-Path Spot Check

> **Note:** After completing the table above, perform an extra spot check at the
> determined minimum sizes using the stress commands. These allocate **all** crypto
> buffers on the TA stack simultaneously (not heap), representing peak stack pressure:
>
> - KEM: `pqc_ping --cmd kem-stress` — keygen+encaps+decaps, ~3.2 KB on stack
> - SIG: `pqc_ping --cmd sig-stress` — keygen+sign+verify, ~6.1 KB on stack
>
> If either fails at the minimum sizes from the table, increase the corresponding
> value by 1 KB increments until the stress command passes, and update the table.

| config | stress_cmd | result | notes |
|--------|------------|--------|-------|
| KEM | `kem-stress` | | |
| SIG | `sig-stress` | | |

## Recommended Production Values

Based on the profiling above, recommended values with safety margin (~20%):

```c
#define TA_STACK_SIZE  (??? * 1024)   /* min_pass_sig + 20% */
#define TA_DATA_SIZE   (??? * 1024)   /* min_pass_sig + 20% */
```
