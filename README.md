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

## 快速使用

```bash
gomitm ca init --ca-dir ~/.gomitm/ca
gomitm ca export --ca-dir ~/.gomitm/ca --out ./gomitm-ca.crt
gomitm serve --listen :1080 --mitm-hosts "*.googlevideo.com,youtubei.googleapis.com"
gomitm serve --listen :1080 --module-urls "https://raw.githubusercontent.com/iab0x00/ProxyRules/refs/heads/main/Rewrite/YouTubeNoAd.sgmodule"
gomitm serve --listen :1080 --module-urls "https://raw.githubusercontent.com/iab0x00/ProxyRules/refs/heads/main/Rewrite/YouTubeNoAd.sgmodule" --module-args "字幕翻译语言=ja,歌词翻译语言=ko,启用调试模式=true"
gomitm serve --listen :1080 --module-urls "https://raw.githubusercontent.com/iab0x00/ProxyRules/refs/heads/main/Rewrite/YouTubeNoAd.sgmodule" --capture-enabled --har-out ./tmp/session.har
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

# 构建二进制
go build -o ./gomitm ./cmd/gomitm
```

## 说明

- MITM 目前仅在域名命中且端口为 `443` 时触发。
- 抓包当前仅覆盖 MITM 的 HTTP 事务，不含纯 TCP 透传流量。
