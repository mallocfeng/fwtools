# fwtools

[中文](#中文) | [English](#english)

---

## 中文

独立的 3x-ui 用户/管理扩展服务。

本仓库**不包含** 3x-ui 源码，只通过 API 对接你服务器上已安装的 3x-ui 面板，因此可以做到：

- 3x-ui 单独升级
- fwtools 单独升级
- 互不影响

### 功能

- 用户注册 / 登录 / 用户后台
- 套餐购买（可选择目标节点）
- 订阅链接展示 + 二维码
- 管理员后台（启用/停用/删除/拉黑等）
- 与 3x-ui 同步（含删除节点/用户后的联动清理）

### 技术栈

- Go + Gin + GORM
- SQL Server
- 3x-ui HTTP API

### 前置条件

- Go 1.22+
- VPS 上已安装并运行 3x-ui
- SQL Server 可从 fwtools 服务访问

### 快速启动

```bash
cp .env.example .env
# 按实际环境修改 .env

set -a
source .env
set +a

go run .
```

访问地址：

- 用户端：`http://YOUR_SERVER_IP:8090/user/login`
- 管理端：`http://YOUR_SERVER_IP:8090/admin/login`

### 环境变量说明

参考 `.env.example`。

关键项：

- `PANEL_BASE_URL`：3x-ui 面板地址
- `PANEL_ADMIN_USER/PANEL_ADMIN_PASS`：3x-ui 管理账号密码
- `PANEL_SUB_BASE_URL`：用户可访问的订阅地址前缀

### systemd 部署（推荐）

示例 `/etc/systemd/system/fwtools.service`：

```ini
[Unit]
Description=fwtools service
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/fwtools
ExecStart=/opt/fwtools/fwtools
EnvironmentFile=/opt/fwtools/.env
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

构建并启动：

```bash
cd /opt/fwtools
go build -o fwtools .
sudo systemctl daemon-reload
sudo systemctl enable --now fwtools
sudo systemctl status fwtools
```

### 说明

- fwtools 是与 3x-ui 并行运行的扩展服务，不替代 3x-ui。
- 建议你继续使用原方式维护/升级 3x-ui。

---

## English

Independent user/admin extension service for **3x-ui**.

This repository does **not** include 3x-ui source code. It integrates with your existing 3x-ui installation via API, so you can upgrade 3x-ui and fwtools independently.

### Features

- User register / login / dashboard
- Plan purchase with selectable target node (inbound)
- Subscription link display + QR code
- Admin dashboard (enable/disable/delete/block actions)
- Sync with 3x-ui data (including cleanup after node/client deletion)

### Tech stack

- Go + Gin + GORM
- SQL Server
- 3x-ui HTTP API integration

### Prerequisites

- Go 1.22+
- Running 3x-ui panel on your VPS
- SQL Server reachable from fwtools

### Quick start

```bash
cp .env.example .env
# edit .env with your real values

set -a
source .env
set +a

go run .
```

Open:

- User: `http://YOUR_SERVER_IP:8090/user/login`
- Admin: `http://YOUR_SERVER_IP:8090/admin/login`

### Environment variables

See `.env.example`.

Important keys:

- `PANEL_BASE_URL`: your 3x-ui panel URL
- `PANEL_ADMIN_USER/PANEL_ADMIN_PASS`: 3x-ui admin credentials
- `PANEL_SUB_BASE_URL`: public subscription base URL for users

### Deploy with systemd (recommended)

Example `/etc/systemd/system/fwtools.service`:

```ini
[Unit]
Description=fwtools service
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/fwtools
ExecStart=/opt/fwtools/fwtools
EnvironmentFile=/opt/fwtools/.env
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Build and enable:

```bash
cd /opt/fwtools
go build -o fwtools .
sudo systemctl daemon-reload
sudo systemctl enable --now fwtools
sudo systemctl status fwtools
```

### Notes

- fwtools is designed to run **alongside** 3x-ui, not replace it.
- Keep 3x-ui managed/upgraded independently.
