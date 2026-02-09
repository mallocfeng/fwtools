# fw-user-service

[中文](#中文说明) | [English](#english)

---

## 中文说明

独立业务服务，通过 HTTP API 对接 3x-ui，不修改 3x-ui 源码。

### 为什么这样做

- 3x-ui 上游保持原样，可单独升级。
- 你的业务系统可独立升级。
- 支持多面板隔离：同一个 SQL Server 下，通过 `PANEL_KEY` 区分不同 3x-ui 面板数据，互不冲突。

### 页面入口

- 用户注册：`GET /user/register`
- 用户登录：`GET /user/login`
- 用户后台：`GET /user/dashboard`
- 管理员登录：`GET /admin/login`
- 管理员后台：`GET /admin/dashboard`

### 运行方法

1. 复制环境变量文件

```bash
cp .env.example .env
```

2. 加载环境变量并运行

```bash
set -a
source .env
set +a

go run .
```

3. 访问地址

- 用户端：`http://127.0.0.1:8090/user/login`
- 管理端：`http://127.0.0.1:8090/admin/login`

### 多面板配置（重点）

- 每个 3x-ui 面板实例使用不同的 `PANEL_KEY`
- 示例：`PANEL_KEY=hk-prod-01`、`PANEL_KEY=sg-prod-01`
- 隔离范围：用户、套餐、订单、订阅记录

### 套餐数据

套餐存在 `plans` 表（程序启动会自动迁移建表）。

示例 SQL：

```sql
INSERT INTO plans (panel_key, name, inbound_id, traffic_gb, duration_days, price_cents, currency, status, created_at, updated_at)
VALUES
('default', '10G 30天', 1, 10, 30, 1000, 'CNY', 'ACTIVE', GETDATE(), GETDATE()),
('default', '20G 90天', 1, 20, 90, 1500, 'CNY', 'ACTIVE', GETDATE(), GETDATE()),
('default', '30G 365天', 1, 30, 365, 2000, 'CNY', 'ACTIVE', GETDATE(), GETDATE());
```

---

## English

Standalone business service integrating with 3x-ui via HTTP API, with no source modification to 3x-ui.

### Why this setup

- Keep 3x-ui upstream untouched and upgradable.
- Upgrade this business service independently.
- Multi-panel isolation via `PANEL_KEY` in one SQL Server database.

### Endpoints

- User register: `GET /user/register`
- User login: `GET /user/login`
- User dashboard: `GET /user/dashboard`
- Admin login: `GET /admin/login`
- Admin dashboard: `GET /admin/dashboard`

### Run

1. Copy env file

```bash
cp .env.example .env
```

2. Export env and run

```bash
set -a
source .env
set +a

go run .
```

3. Open

- User portal: `http://127.0.0.1:8090/user/login`
- Admin portal: `http://127.0.0.1:8090/admin/login`

### Multi-panel config

- Use a different `PANEL_KEY` per 3x-ui panel deployment.
- Example: `PANEL_KEY=hk-prod-01`, `PANEL_KEY=sg-prod-01`
- Isolation scope: users, plans, orders, subscriptions.

### Plan setup

Plans are stored in SQL Server table `plans` (auto-created by migration).

Example:

```sql
INSERT INTO plans (panel_key, name, inbound_id, traffic_gb, duration_days, price_cents, currency, status, created_at, updated_at)
VALUES
('default', '10G 30 days', 1, 10, 30, 1000, 'CNY', 'ACTIVE', GETDATE(), GETDATE()),
('default', '20G 90 days', 1, 20, 90, 1500, 'CNY', 'ACTIVE', GETDATE(), GETDATE()),
('default', '30G 365 days', 1, 30, 365, 2000, 'CNY', 'ACTIVE', GETDATE(), GETDATE());
```
