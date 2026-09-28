# AgentScope-eBPF：系统级多智能体异常监测

本项目完整对应操作系统大赛第 32 题，采用“eBPF 内核态采集 + 用户态关联与
检测”架构，在不修改内核和目标 Agent 程序的前提下，同时监测多个 AI Agent
及其进程树。系统可采集进程、文件、网络和 OpenSSL 明文事件，识别资源、
安全与多智能体异常，并把 Prompt/Response 与底层高危行为关联为可审计因果
证据链。

## 已实现能力

### 多层级数据捕获

- `sched_process_fork/exec/exit` 追踪完整进程生命周期，子进程自动继承根
  Agent 的稳定 `agent_id`；
- `openat`、`unlink`、`unlinkat`、`rmdir` 记录路径、目录 FD、标志位和返回值；
- `connect` 记录 IPv4/IPv6 目标 IP、端口和返回值；
- 一个采集器可用重复的 `--agent ID:PID` 同时注册最多 128 个根 Agent；
- 内核 BPF Map 先过滤非 Agent 进程，再通过 Ring Buffer 输出统一事件；
- OpenSSL `SSL_read`、`SSL_write`、`SSL_read_ex`、`SSL_write_ex` 的
  uprobe/uretprobe 非侵入式截获 HTTPS 明文；
- 所有事件包含 UTC 时间戳、单调时钟时间戳、Agent ID、PID/TID、PPID、
  UID/GID、进程名和操作对象；采集结束输出接收与丢弃计数。

### 异常检测

- 复合逻辑死循环：重复 Prompt、重复文件 I/O、高频相同网络端点、重复进程
  执行至少两类信号同时越阈值；
- 资源滥用：进程事件风暴和批量删除；
- 安全异常：非预期 Shell、敏感路径访问、工作区外成功删除、恶意 IP 和高危
  端口；
- 多智能体异常：同一资源并发写竞争、未授权文件式数据传递、多个 Agent 的
  集体 API 风暴；
- 所有窗口、阈值、Agent 工作区、允许协作对和共享目录均由 YAML 配置。

### 跨层归因

- 有界重组 TLS 明文中的 HTTP `Content-Length` 消息与 JSON 片段；
- 提取 OpenAI/Anthropic/Gemini 常见 `prompt`、`messages`、`input`、
  `choices`、`content`、`output` 等语义字段；
- 在进入日志前脱敏 Authorization、Bearer Token、API Key、Cookie；
- 使用同 Agent、有界时间窗口建立 `Prompt -> Response -> system event` 关联；
- 告警 JSONL 包含 PID/TID、对象、`prompt_id`、`causal_link_id`、脱敏 Prompt、
  Response 和证据类型；所有普通系统事件的语义关联另存为 correlations JSONL。

## 环境

- Linux Kernel 5.15+，需要 `/sys/kernel/btf/vmlinux`；
- 已支持 x86_64 与 ARM64 CO-RE 编译；
- clang、bpftool、libbpf、libelf、zlib、pkg-config、Python 3.10+、PyYAML；
- eBPF 加载通常需要 root 或等价 BPF 能力。

Ubuntu 22.04/24.04：

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
  linux-tools-common linux-tools-$(uname -r) make gcc pkg-config \
  python3 python3-yaml
```

## 构建与测试

```bash
make doctor
make
make test
make check
```

`make check` 会全量重编译、执行单元测试、检查采集器 CLI、Python 语法以及三份
review 配置。真实 BPF 加载、TLS 明文采集和性能门槛由下面三套 review 演示验证。

## 三个评审要点的一键演示

三个演示都由 `config/demos/` 下的 YAML 描述 Agent、Prompt、阈值、期望事件和
期望告警。评审时不需要手工拼接 PID 或长管道命令：

```bash
make demo-review-1   # 功能与回溯：双 Agent HTTPS Prompt/Response -> 底层高危行为
make demo-review-2   # 观测与兼容：进程树、文件、网络、OpenSSL 明文及非侵入性
make demo-review-3   # 性能与工程：10 组成对对照、5% 门槛、丢失/ABI 健康检查
```

一次运行全部：

```bash
make demo-review-all
```

脚本只会请求一次 sudo，自动生成临时证书、本地 HTTPS 服务、双 Agent、采集器
和分析器，最后直接打印 `PASS/FAIL` 与人类可读证据。完整机器可读结果保存在
`docs/review_reports/`。演示全程只访问本机 `127.0.0.1` 和 `/tmp` 下的无害文件。

## HTTPS 明文捕获

review 1 和 review 2 会从两个根 Agent 的 `/proc/PID/maps` 或系统标准路径定位
`libssl.so.3`，并自动挂载四组 OpenSSL 探针，全程无需手工填写 PID 或库路径。

明文按最多 256 字节的内核事件分片传输，用户态使用有界缓冲重组，因此不会
因为大请求扩大普通系统调用事件。当前探针适用于动态链接 OpenSSL；静态链接、
BoringSSL、rustls、应用层再次加密或 HTTP/3 需要相应库的独立探针。

## 配置要点

`config/rules.yaml` 包含：

- `agents`：名称与独立工作区；
- `unexpected_shells`、`sensitive_paths`、`malicious_ips`、
  `high_risk_ports`；
- `loop_detection`：四类循环信号阈值；
- `resource_limits`：进程风暴和删除风暴阈值；
- `multi_agent`：竞争窗口、集体连接阈值、允许协作对与共享路径；
- `semantic_capture`：语义关联窗口、历史条数和重组内存上限。

离线重放采集事件：

```bash
python3 -m user.analyzer \
  --config config/rules.yaml \
  --events-file events.jsonl \
  --no-persist
```

## 性能评估

正式工具使用文件、进程和网络三种真实采集链路，至少 10 组相邻配对样本，
交替执行“基线 -> 监控”和“监控 -> 基线”。采集评测模式完整保留 eBPF 字段
读取、Ring Buffer 导出、用户态 ABI 校验和逐事件消费，只关闭 JSON 格式化、
关联、检测和日志。它验证实收事件大于 0、Ring Buffer 零丢弃、无非法 ABI，
并报告配对开销中位数及其中位数单侧 95% bootstrap 置信上界；两项都不超过
5% 才判定通过。

默认 `representative` 模式把一批真实工具操作与固定轮数的 PBKDF2 本地规划
计算组合，计时区间内没有 `sleep`，并把工作负载和监控器绑定到不同 vCPU。
统一运行 `make demo-review-3`，结果写入
`docs/review_reports/performance/`。性能结果与 CPU、虚拟化和频率策略相关，提交
材料应使用最终部署机器重新生成，不能用其他环境的数字替代。

## 工程边界

- 相对路径由用户态及时读取 `/proc/PID/cwd` 或 `/proc/PID/fd/DIRFD`；若短命
  进程在消费前退出，会保留原始相对路径，避免伪造绝对路径；
- TLS 因果关系是“同 Agent + 时间窗口”的可解释证据，不声称仅凭时间邻近就
  证明严格因果；日志明确记录证据类型；
- `connect` 会保留失败尝试，网络风险规则关注尝试本身；删除和敏感文件规则
  只对成功系统调用告警；
- BPF 哈希表、语义历史、TLS 重组、循环窗口和多 Agent 资源状态均有固定容量
  或时间淘汰，防止监控系统自身无界增长。

完整架构、关键决策和验收映射见 [docs/DESIGN.md](docs/DESIGN.md) 与
[docs/ACCEPTANCE.md](docs/ACCEPTANCE.md)。

## 目录

```text
.
├── src/                  # eBPF 程序、共享 ABI、libbpf 加载器
├── user/analyzer.py      # 语义提取、关联、规则引擎与日志
├── config/rules.yaml     # Agent 与异常规则
├── config/demos/         # 三个评审要点的配置驱动场景
├── demo/                 # 三套 review 共用的双 Agent 与本地 HTTPS 负载
├── tests/                # 用户态确定性测试
├── tools/                # 验收、性能与配置驱动评审演示
├── docs/                 # 设计、验收与测量报告
└── Makefile
```
