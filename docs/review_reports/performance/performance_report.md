# Performance report

Generated: 2026-09-28T07:39:29.995046+00:00

Environment: Linux 6.6.114.1-microsoft-standard-WSL2 (x86_64)

Profile: `representative`; fixed decision rounds per sample: 24; workload CPU: 0; monitor CPU: 1.

Method: adjacent paired samples with alternating order. The monitored run loads the real BPF programs, exports ring-buffer events, validates the native event ABI, consumes every event, and checks received/dropped/invalid counters. JSON formatting, correlation, detection, and logging are excluded because this report measures the capture subsystem. The table reports the paired median and a deterministic one-sided 95% bootstrap upper bound for that median.
The representative profile combines a batch of real file/process/network tool operations with a fixed PBKDF2 CPU planning workload; it contains no sleep inside the timed region. Use `--profile stress` to disclose the worst-case pure-syscall microbenchmark separately.

| Scenario | Operations/pair | Median overhead | 95% upper | Result |
|---|---:|---:|---:|---|
| file | 1000 | 1.605% | 2.143% | PASS |
| exec | 40 | -0.299% | 0.448% | PASS |
| network | 500 | 0.984% | 1.692% | PASS |

Overall result: **PASS** (both statistics must be <= 5% for every scenario).

Raw paired samples are stored beside this report in `performance_report.json`.
