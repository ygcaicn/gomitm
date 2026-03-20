# GoMITM 运维手册（Runbook）

本文档面向运维与发布人员，给出部署、升级、回滚、排障的最小闭环流程。

## 1. 部署前检查

1. 系统为 Linux + systemd，具备 root 权限。
2. 已开放或规划好代理端口（默认 `127.0.0.1:1080`）与管理端口（默认 `127.0.0.1:19090`）。
3. 若服务监听非 loopback 地址：
   - 必须配置 `serve.socks_username` + `serve.socks_password`。
   - 若 Admin API 监听非 loopback，必须配置 `serve.admin_token`。
4. 客户端已准备好导入并信任 CA 的流程。

## 2. 安装与首次启动

```bash
sudo bash -c "$(curl -L https://github.com/ygcaicn/gomitm/raw/main/install-release.sh)" @ install
```

安装后检查：

```bash
systemctl status gomitm --no-pager
gomitm version
```

## 3. 配置变更

配置文件路径：`/etc/gomitm/config.yaml`

推荐最小安全配置（公网监听示例）：

```yaml
serve:
  listen: "0.0.0.0:1080"
  admin_listen: "127.0.0.1:19090"
  admin_token: "change-me"
  socks_username: "change-me"
  socks_password: "change-me"
  max_conns: 4096
```

应用配置：

```bash
sudo systemctl restart gomitm
sudo systemctl status gomitm --no-pager
```

## 4. 健康检查与监控

健康检查：

```bash
curl -sS http://127.0.0.1:19090/healthz
```

统计接口（若配置 token）：

```bash
curl -H "Authorization: Bearer <token>" -sS http://127.0.0.1:19090/api/stats
curl -H "Authorization: Bearer <token>" -sS http://127.0.0.1:19090/api/metrics
```

日志查看：

```bash
journalctl -u gomitm -n 200 --no-pager
journalctl -u gomitm -f
```

## 5. 升级流程

1. 评审新版本变更与风险。
2. 先在灰度节点升级并观察。
3. 逐批升级生产节点。

命令：

```bash
sudo bash -c "$(curl -L https://github.com/ygcaicn/gomitm/raw/main/install-release.sh)" @ install vX.Y.Z
```

升级后验证：

```bash
gomitm version
systemctl status gomitm --no-pager
```

## 6. 回滚流程

1. 明确回滚目标版本（例如 `v0.1.2`）。
2. 执行安装脚本安装旧版本。
3. 验证服务状态与核心功能。

```bash
sudo bash -c "$(curl -L https://github.com/ygcaicn/gomitm/raw/main/install-release.sh)" @ install v0.1.2
```

## 7. 常见问题排查

1. 代理可连通但 HTTPS 全失败：
   - 检查客户端是否导入并信任 GoMITM CA。
   - 访问内置页面 `http://8.8.9.9/` 重新下载证书。
2. Admin API 401：
   - 检查 `Authorization: Bearer <token>` 是否正确。
3. 服务无法启动：
   - 查看 `journalctl -u gomitm -n 200`。
   - 检查非 loopback 监听是否缺少 SOCKS 或 Admin 鉴权配置。
4. 模块加载失败：
   - 确认远程模块/脚本使用 `https://`。
   - 检查模块与脚本路径是否可访问。

## 8. 变更记录要求

每次发布必须记录：

1. 版本号、发布时间、发布人。
2. 变更摘要（功能/修复/风险）。
3. 回滚版本与回滚条件。
4. 发布后 24 小时观测结论（错误率、重启次数、关键告警）。
