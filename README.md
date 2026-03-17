# gomitm

开发规范：

- [GoMITM 开发规范（v1）](./docs/ARCHITECTURE.zh-CN.md)

## 当前能力（M1 + M2）

- SOCKS5 入口（`NO AUTH` + `CONNECT`）
- 非命中域名走 TCP 透传
- 命中域名（`--mitm-hosts`）走 HTTPS MITM（HTTP/1.1）
- 首次启动自动生成 Root CA
- 支持导出 CA 证书供客户端安装
- 支持加载 Surge-like 模块子集：
  - `[MITM] hostname`
  - `[URL Rewrite] ... - reject/reject-200`
- 支持 `[Script]` 子集（`type=http-request` / `type=http-response`）并执行 JS（goja）
- 支持 `binary-body-mode=true` 的响应体字节数组改写（`bodyBytes`）
- 支持 MITM 抓包并在退出时导出 HAR 文件
- 支持 Admin API（健康检查、抓包列表、实时 HAR 导出）

## 快速使用

```bash
gomitm ca init --ca-dir ~/.gomitm/ca
gomitm ca export --ca-dir ~/.gomitm/ca --out ./gomitm-ca.crt
gomitm serve --config ./config.example.yaml
gomitm serve --listen :1080 --mitm-hosts "*.googlevideo.com,youtubei.googleapis.com"
gomitm serve --listen :1080 --module-urls "https://raw.githubusercontent.com/iab0x00/ProxyRules/refs/heads/main/Rewrite/YouTubeNoAd.sgmodule"
gomitm serve --listen :1080 --module-urls "https://raw.githubusercontent.com/iab0x00/ProxyRules/refs/heads/main/Rewrite/YouTubeNoAd.sgmodule" --module-args "字幕翻译语言=ja,歌词翻译语言=ko,启用调试模式=true"
gomitm serve --listen :1080 --module-urls "https://raw.githubusercontent.com/iab0x00/ProxyRules/refs/heads/main/Rewrite/YouTubeNoAd.sgmodule" --capture-enabled --har-out ./tmp/session.har
gomitm serve --listen :1080 --admin-listen 127.0.0.1:19090 --capture-enabled
```

将客户端代理设置为 SOCKS5 `127.0.0.1:1080`，并安装 `gomitm-ca.crt` 为受信任根证书。

## 开发启动（Dev）

```bash
# 1) 拉依赖
go mod tidy

# 2) 运行测试
go test ./...

# 3) 直接开发态启动（无需先 build）
go run ./cmd/gomitm serve --listen :1080
```

常用开发命令：

```bash
# 带远程模块启动
go run ./cmd/gomitm serve --listen :1080 \
  --module-urls "https://raw.githubusercontent.com/iab0x00/ProxyRules/refs/heads/main/Rewrite/YouTubeNoAd.sgmodule"

# 带模块参数覆盖
go run ./cmd/gomitm serve --listen :1080 \
  --module-urls "https://raw.githubusercontent.com/iab0x00/ProxyRules/refs/heads/main/Rewrite/YouTubeNoAd.sgmodule" \
  --module-args "字幕翻译语言=ja,歌词翻译语言=ko,启用调试模式=true"

# 开启抓包并在退出时导出 HAR
go run ./cmd/gomitm serve --listen :1080 \
  --module-urls "https://raw.githubusercontent.com/iab0x00/ProxyRules/refs/heads/main/Rewrite/YouTubeNoAd.sgmodule" \
  --capture-enabled --har-out ./tmp/session.har

# 开启 Admin API（运行中查看抓包）
go run ./cmd/gomitm serve --listen :1080 --admin-listen 127.0.0.1:19090 --capture-enabled
# GET /healthz
# GET /api/captures?limit=100
# GET /api/captures.har

# 通过配置文件启动
go run ./cmd/gomitm serve --config ./config.example.yaml

# 配置文件 + 命令行覆盖（命令行优先）
go run ./cmd/gomitm serve --config ./config.example.yaml --listen :2080 --capture-enabled=false

# 构建二进制
go build -o ./gomitm ./cmd/gomitm
```

配置文件参考：

- [config.example.yaml](/Users/caiyagang/Downloads/gomitm/config.example.yaml)

## 压力测试

```bash
# 全量单测
go test ./...

# 基准测试（含内存分配）
go test -run '^$' -bench . -benchmem ./internal/capture ./internal/module ./internal/script ./internal/server

# 并发数据竞争检查
go test -race ./...
```

## CI / Release

- CI 文件：
  - `.gitea/workflows/ci.yml`
  - `.gitea/workflows/release.yml`
- 触发规则：
  - `push main` / `pull_request main`：自动执行 `go test ./...`，并做一次构建冒烟检查
  - `push tag v*`：自动交叉编译（`linux/darwin/windows` 的 `amd64/arm64`）并发布到 Gitea Release
  - 两个工作流都支持 `workflow_dispatch` 手动触发
- 需要在仓库 Secrets 中配置：
  - `TOKEN`：具备仓库 release 写权限的 token（用于上传发布资产）

## 说明

- MITM 目前仅在域名命中且端口为 `443` 时触发。
- 抓包当前仅覆盖 MITM 的 HTTP 事务，不含纯 TCP 透传流量。
