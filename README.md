# fwtools

Independent user/admin extension service for **3x-ui**.

This repo does **not** include 3x-ui source code. It connects to an existing 3x-ui installation by API, so you can upgrade 3x-ui and fwtools independently.

## What it provides

- User register/login/dashboard
- Buy plan + choose target node (inbound) from dropdown
- Subscription link + QR code display
- Admin dashboard for service management
- User block/unblock
  - blocked user cannot buy/open new nodes
  - blocking also disables existing services for that user
- Sync with 3x-ui data (including deleted clients/nodes)

## Tech stack

- Go + Gin + GORM
- SQL Server
- 3x-ui HTTP API integration

## Prerequisites

- Go 1.22+
- Running 3x-ui panel on your VPS
- SQL Server reachable from your fwtools service

## Quick start

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

## Environment variables

See `.env.example`.

Important:

- `PANEL_BASE_URL` must point to your running 3x-ui panel
- `PANEL_ADMIN_USER/PANEL_ADMIN_PASS` must match 3x-ui admin credentials
- `PANEL_SUB_BASE_URL` should be the public subscription base users can access

## Deploy with systemd (recommended)

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

Build + enable:

```bash
cd /opt/fwtools
go build -o fwtools .
sudo systemctl daemon-reload
sudo systemctl enable --now fwtools
sudo systemctl status fwtools
```

## Notes

- This project is designed to run **alongside** 3x-ui, not replace it.
- Keep 3x-ui installed/managed separately.
