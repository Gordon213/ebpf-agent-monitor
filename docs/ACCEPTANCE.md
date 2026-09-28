# 第 32 题三项评审验收

项目只保留三套配置驱动的多 Agent review 演示。所有场景均自动启动两个根
Agent、采集器和分析器，不需要手工填写 PID 或拼接长命令。

## 一键运行

```bash
make demo-review-1
make demo-review-2
make demo-review-3
```

连续运行全部评审：

```bash
make demo-review-all
```

每套演示在终端打印 `PASS/FAIL` 和关键证据，完整机器可读结果位于
`docs/review_reports/`。

## Review 1：功能实现与异常回溯

配置：`config/demos/review-1-functional-causality.yaml`

两个 Agent 分别通过本地 HTTPS 发送唯一 Prompt/Response，再触发 Shell、敏感
路径、资源竞争、未授权交接、集体 API 风暴和复合循环。验收器要求：

1. 同时观测 `fork/exec/exit/openat/connect/tls_write/tls_read`；
2. 命中配置中的全部异常类型；
3. 告警 `agent_id` 与各自 Prompt 一致，两个 Agent 的因果上下文不串线；
4. 高危告警包含 Prompt、Response、`prompt_id` 和 `causal_link_id`。

## Review 2：观测深度与兼容性

配置：`config/demos/review-2-observability.yaml`

演示完整进程树、文件、网络和 OpenSSL 明文观测。验收器要求：

1. 子进程继承所属根 Agent 的稳定 ID；
2. 事件包含时间、PID/TID/PPID、UID/GID、进程名、对象和真实返回值；
3. 能看到配置指定的共享、交接和受保护路径以及网络端点；
4. OpenSSL uprobe 成功挂载，两个 Agent 均产生 TLS 明文事件；
5. 演示前后目标源文件哈希不变，证明无需修改 Agent 程序。

## Review 3：系统性能与工程

配置：`config/demos/review-3-performance.yaml`

正式评测对文件、进程和网络各执行 10 组相邻成对对照，交替基线/监控顺序。
每类场景必须同时满足：

1. 每个监控样本 `received > 0`；
2. `dropped == 0` 且 `invalid == 0`；
3. 配对开销中位数不大于 5%；
4. 中位数的单侧 95% bootstrap 置信上界不大于 5%。

详细性能样本保存在 `docs/review_reports/performance/`。

## 工程检查

```bash
make test
make check
```

`make check` 会执行依赖检查、CO-RE 全量构建、单元测试、采集器 CLI 检查、
Python 语法检查和三份 review 配置校验；它不创建额外的演示报告。

## 赛题要求映射

| 评审关注点 | 主要实现 | 对应演示 |
|---|---|---|
| 多 Agent 进程树、文件、网络、HTTPS 明文 | `src/monitor.bpf.c`、`src/monitor.c` | Review 2 |
| 逻辑循环、资源、安全与协作异常 | `user/analyzer.py`、`config/rules.yaml` | Review 1 |
| Prompt/Response 到系统行为的跨层归因 | `SemanticExtractor`、`CausalCorrelator` | Review 1 |
| 非侵入式 tracepoint/uprobe 与兼容性 | CO-RE、动态 OpenSSL 探针 | Review 2 |
| 性能损耗不大于 5% 与采集健康 | `tools/performance_eval.py` | Review 3 |
