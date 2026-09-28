# Performance report

Generated: 2026-09-28T02:58:11.113437+00:00

Environment: Linux 6.8.0-139-generic (aarch64)

Profile: `representative`; fixed decision rounds per sample: 24; workload CPU: 0; monitor CPU: 1.

Method: adjacent paired samples with alternating order. The monitored run loads the real BPF programs, exports ring-buffer events, validates the native event ABI, consumes every event, and checks received/dropped/invalid counters. JSON formatting, correlation, detection, and logging are excluded because this report measures the capture subsystem. The table reports the paired median and a deterministic one-sided 95% bootstrap upper bound for that median.
The representative profile combines a batch of real file/process/network tool operations with a fixed PBKDF2 CPU planning workload; it contains no sleep inside the timed region. Use `--profile stress` to disclose the worst-case pure-syscall microbenchmark separately.

| Scenario | Operations/pair | Median overhead | 95% upper | Result |
|---|---:|---:|---:|---|
| file | 1000 | 1.125% | 2.675% | PASS |
| exec | 40 | 0.031% | 1.037% | PASS |
| network | 500 | 1.307% | 2.264% | PASS |

Overall result: **PASS** (both statistics must be <= 5% for every scenario).

Raw paired samples are stored beside this report in `performance_report.json`.
