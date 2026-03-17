# UDP ASSOCIATE 完整支持规划

## 1. 当前状态

- 已支持 `SOCKS5 CMD=0x03 (UDP ASSOCIATE)` 握手。
- 当前实现为 `drop mode`：分配 UDP relay 端口并接收报文，但不向目标转发。
- 目标：升级为**完整可用**的 UDP 中继能力，并与现有策略系统对齐。

## 2. 目标能力（Definition of Done）

- 支持 SOCKS5 UDP relay（RFC 1928）端到端转发：
  - 客户端 UDP 报文 -> 目标服务器。
  - 目标服务器响应 -> 客户端。
- 支持 `ATYP=IPv4/IPv6/DOMAIN`。
- 正确处理 SOCKS5 UDP 头：
  - `RSV(2)`、`FRAG(1)`、`ATYP`、`DST.ADDR`、`DST.PORT`、`DATA`。
- `FRAG!=0` 有明确策略（首版可拒绝并计数）。
- 同步接入策略引擎：
  - `PROTOCOL=UDP` 规则生效。
  - 域名匹配（含后缀/通配）可对 UDP 做 `REJECT`。
- 具备资源治理：
  - 会话超时回收、速率限制、并发上限。
- 具备可观测性：
  - 连接数、收发包数、丢包数、拒绝数、错误分类。

## 3. 分阶段实施

### M1: 协议与会话骨架（可转发最小闭环）

- 新增 UDP 会话结构：
  - 绑定 TCP 控制连接 + 客户端 UDP 源地址。
  - 生命周期与 TCP 关联（TCP 断开后回收）。
- 实现 UDP relay 主循环：
  - 解析客户端发来的 SOCKS5 UDP 请求头。
  - 构造到目标地址的裸 UDP 报文并发送。
  - 接收目标响应，封装回 SOCKS5 UDP 响应头返回客户端。
- 首版 `FRAG!=0`：
  - 直接丢弃并记日志/计数（不做分片重组）。

验收：
- `dig @8.8.8.8 google.com`（经 SOCKS5 UDP）可通。
- QUIC/HTTP3 客户端可建立 UDP 通路（不保证 MITM，只保证转发）。

### M2: 策略引擎接入（规则可控）

- 在 UDP 出站前引入策略判定：
  - 输入：`dst host/ip + port + protocol=UDP`。
- 实现/接入 `[Rule]` 中 UDP 相关匹配。
- 对命中 `REJECT` 的 UDP 请求：
  - 丢弃并记录命中规则。

验收：
- 配置 `DOMAIN-SUFFIX,googlevideo.com + PROTOCOL,UDP -> REJECT` 时，相关 UDP 请求被稳定拒绝。

### M3: 健壮性与性能

- 每会话/全局缓冲池（减少分配）。
- 可配置超时：
  - 会话空闲超时。
  - 上游读写超时。
- 限流与保护：
  - 最大并发会话数。
  - 每会话 PPS/BPS 限制（可选）。
- 错误分级：
  - 解析错误、网络错误、策略拒绝、超时回收。

验收：
- 压测下无 goroutine 泄漏、FD 泄漏。
- `go test -race ./...` 通过。

### M4: 可观测性与运维

- 暴露指标（建议）：
  - `udp_sessions_active`
  - `udp_packets_in_total`
  - `udp_packets_out_total`
  - `udp_packets_drop_total`
  - `udp_policy_reject_total`
  - `udp_parse_error_total`
- 管理 API 增加 UDP 会话视图（可选）。

验收：
- 可通过日志/指标快速定位“UDP 不生效”根因。

## 4. 协议实现要点

- 客户端到 relay 的 UDP payload 格式：
  - `RSV(2)=0x0000`
  - `FRAG(1)`
  - `ATYP(1)`
  - `DST.ADDR`
  - `DST.PORT(2)`
  - `DATA(...)`
- relay 返回客户端时也需按同格式封装。
- 客户端来源校验：
  - 仅接受与 UDP ASSOCIATE 对应客户端地址的报文（可配置是否放宽）。
- 域名 `ATYP=DOMAIN`：
  - 支持按需解析（缓存 TTL 可后续加入）。

## 5. 测试计划（TDD）

### 单元测试

- UDP 头编解码：
  - IPv4/IPv6/DOMAIN 正反向测试。
  - `FRAG!=0` 路径。
- 会话管理：
  - 创建、续期、超时回收。
- 策略判定：
  - UDP 命中/未命中/拒绝行为。

### 集成测试

- 本地 fake UDP echo server：
  - 经 SOCKS5 UDP relay 发包回包校验。
- 同时多会话并发：
  - 隔离性与正确性。
- TCP 控制连接断开后：
  - UDP 会话及时回收。

### 回归测试

- 现有 TCP CONNECT / MITM 行为不退化。
- `mitm-all` 与内置页面逻辑不受影响。

## 6. 风险与边界

- 不实现 UDP 分片重组（`FRAG>0`）是常见取舍，但需文档明确。
- UDP 无连接语义导致源地址伪造风险，需要客户端地址绑定策略。
- 大流量 UDP（如 QUIC 视频）可能带来高 CPU/内存压力，必须做限流与池化。

## 7. 里程碑与提交建议

- `M1`: `feat(server): implement socks5 udp relay basic forwarding`
- `M2`: `feat(policy): apply udp protocol/domain reject rules`
- `M3`: `perf(server): optimize udp relay buffers and timeouts`
- `M4`: `feat(observe): add udp relay metrics and diagnostics`

