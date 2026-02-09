# fw-user-service

[中文](#中文说明) | [English](#english)

---

## 中文说明

这是一个独立业务服务，通过 HTTP 接口对接 3x-ui，不修改 3x-ui 源码。

### 为什么这样做

- 3x-ui 上游保持原样，可单独升级。
- 你的业务系统可独立升级。
- 支持多面板隔离：同一个数据库里，通过 `PANEL_KEY` 区分不同 3x-ui 面板数据，互不冲突。

### 页面入口

- 用户注册页：`GET /user/register`
- 用户登录页：`GET /user/login`
- 用户后台页：`GET /user/dashboard`
- 管理员登录页：`GET /admin/login`
- 管理员后台页：`GET /admin/dashboard`

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

### 数据表结构

#### 1) 用户表 `app_users`

- `id`：主键，自增
- `panel_key`：面板标识（同库多面板隔离）
- `email`：登录邮箱（同 `panel_key` 下唯一）
- `password_hash`：密码哈希
- `blocked`：是否拉黑
- `created_at`：创建时间
- `updated_at`：更新时间

#### 2) 套餐表 `plans`

- `id`：主键，自增
- `panel_key`：面板标识
- `name`：套餐名称
- `inbound_id`：3x-ui 入站 ID
- `traffic_gb`：流量（GB）
- `duration_days`：时长（天）
- `price_cents`：价格（分）
- `currency`：币种（如 CNY）
- `status`：状态（ACTIVE/INACTIVE）
- `created_at`：创建时间
- `updated_at`：更新时间

#### 3) 订单表 `orders`

- `id`：主键，自增
- `panel_key`：面板标识
- `order_no`：订单号（同 `panel_key` 下唯一）
- `user_id`：用户 ID
- `plan_id`：套餐 ID
- `inbound_id`：选择的入站 ID
- `amount_cents`：金额（分）
- `currency`：币种
- `status`：状态（PENDING/PAID）
- `paid_at`：支付时间
- `created_at`：创建时间
- `updated_at`：更新时间

#### 4) 服务记录表 `user_service_records`

- `id`：主键，自增
- `panel_key`：面板标识
- `user_id`：用户 ID
- `order_id`：订单 ID（同 `panel_key` 下唯一）
- `plan_id`：套餐 ID
- `inbound_id`：入站 ID
- `client_email`：客户端邮箱（同 `panel_key` 下唯一）
- `client_uuid`：客户端 UUID
- `client_password`：客户端密码
- `client_sub_id`：订阅 ID（同 `panel_key` 下唯一）
- `total_bytes`：总流量（字节）
- `expiry_time_ms`：到期时间（毫秒时间戳）
- `status`：状态（DONE/DISABLED 等）
- `created_at`：创建时间
- `updated_at`：更新时间

### 新建数据表 SQL（SQL Server）

```sql
IF OBJECT_ID('dbo.app_users', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.app_users (
        id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        panel_key NVARCHAR(100) NOT NULL CONSTRAINT DF_app_users_panel_key DEFAULT('default'),
        email NVARCHAR(255) NOT NULL,
        password_hash NVARCHAR(255) NOT NULL,
        blocked BIT NOT NULL CONSTRAINT DF_app_users_blocked DEFAULT(0),
        created_at DATETIME2 NOT NULL CONSTRAINT DF_app_users_created_at DEFAULT(SYSDATETIME()),
        updated_at DATETIME2 NOT NULL CONSTRAINT DF_app_users_updated_at DEFAULT(SYSDATETIME())
    );
END;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'uk_app_users_panel_email' AND object_id = OBJECT_ID('dbo.app_users'))
    CREATE UNIQUE INDEX uk_app_users_panel_email ON dbo.app_users(panel_key, email);
GO

IF OBJECT_ID('dbo.plans', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.plans (
        id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        panel_key NVARCHAR(100) NOT NULL CONSTRAINT DF_plans_panel_key DEFAULT('default'),
        name NVARCHAR(100) NOT NULL,
        inbound_id INT NOT NULL,
        traffic_gb INT NOT NULL,
        duration_days INT NOT NULL,
        price_cents BIGINT NOT NULL,
        currency NVARCHAR(8) NOT NULL CONSTRAINT DF_plans_currency DEFAULT('CNY'),
        status NVARCHAR(20) NOT NULL CONSTRAINT DF_plans_status DEFAULT('ACTIVE'),
        created_at DATETIME2 NOT NULL CONSTRAINT DF_plans_created_at DEFAULT(SYSDATETIME()),
        updated_at DATETIME2 NOT NULL CONSTRAINT DF_plans_updated_at DEFAULT(SYSDATETIME())
    );
END;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'uk_plans_panel_name_inbound' AND object_id = OBJECT_ID('dbo.plans'))
    CREATE UNIQUE INDEX uk_plans_panel_name_inbound ON dbo.plans(panel_key, name, inbound_id);
GO

IF OBJECT_ID('dbo.orders', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.orders (
        id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        panel_key NVARCHAR(100) NOT NULL CONSTRAINT DF_orders_panel_key DEFAULT('default'),
        order_no NVARCHAR(64) NOT NULL,
        user_id BIGINT NOT NULL,
        plan_id BIGINT NOT NULL,
        inbound_id INT NOT NULL CONSTRAINT DF_orders_inbound_id DEFAULT(1),
        amount_cents BIGINT NOT NULL,
        currency NVARCHAR(8) NOT NULL CONSTRAINT DF_orders_currency DEFAULT('CNY'),
        status NVARCHAR(20) NOT NULL CONSTRAINT DF_orders_status DEFAULT('PENDING'),
        paid_at DATETIME2 NULL,
        created_at DATETIME2 NOT NULL CONSTRAINT DF_orders_created_at DEFAULT(SYSDATETIME()),
        updated_at DATETIME2 NOT NULL CONSTRAINT DF_orders_updated_at DEFAULT(SYSDATETIME())
    );
END;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'uk_orders_panel_order_no' AND object_id = OBJECT_ID('dbo.orders'))
    CREATE UNIQUE INDEX uk_orders_panel_order_no ON dbo.orders(panel_key, order_no);
GO

IF OBJECT_ID('dbo.user_service_records', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.user_service_records (
        id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        panel_key NVARCHAR(100) NOT NULL CONSTRAINT DF_usr_panel_key DEFAULT('default'),
        user_id BIGINT NOT NULL,
        order_id BIGINT NOT NULL,
        plan_id BIGINT NOT NULL,
        inbound_id INT NOT NULL,
        client_email NVARCHAR(255) NOT NULL,
        client_uuid NVARCHAR(64) NULL,
        client_password NVARCHAR(128) NULL,
        client_sub_id NVARCHAR(64) NOT NULL,
        total_bytes BIGINT NOT NULL CONSTRAINT DF_usr_total_bytes DEFAULT(0),
        expiry_time_ms BIGINT NOT NULL CONSTRAINT DF_usr_expiry_time DEFAULT(0),
        status NVARCHAR(20) NOT NULL CONSTRAINT DF_usr_status DEFAULT('DONE'),
        created_at DATETIME2 NOT NULL CONSTRAINT DF_usr_created_at DEFAULT(SYSDATETIME()),
        updated_at DATETIME2 NOT NULL CONSTRAINT DF_usr_updated_at DEFAULT(SYSDATETIME())
    );
END;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'uk_sr_panel_client_email' AND object_id = OBJECT_ID('dbo.user_service_records'))
    CREATE UNIQUE INDEX uk_sr_panel_client_email ON dbo.user_service_records(panel_key, client_email);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'uk_sr_panel_client_sub' AND object_id = OBJECT_ID('dbo.user_service_records'))
    CREATE UNIQUE INDEX uk_sr_panel_client_sub ON dbo.user_service_records(panel_key, client_sub_id);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'uk_sr_panel_order' AND object_id = OBJECT_ID('dbo.user_service_records'))
    CREATE UNIQUE INDEX uk_sr_panel_order ON dbo.user_service_records(panel_key, order_id);
GO
```

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
