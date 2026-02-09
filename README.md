# fw-user-service (Standalone, no 3x-ui source modification)

This project is an independent service that integrates with 3x-ui through HTTP API.

## Why this setup

- 3x-ui remains upstream and untouched.
- You can upgrade 3x-ui independently.
- You can upgrade this service independently.
- Multi-panel isolation supported via `PANEL_KEY` (same DB, different 3x-ui servers, no data collision).

## Endpoints

- User register: `GET /user/register`
- User login: `GET /user/login`
- User dashboard: `GET /user/dashboard`
- Admin login (same credentials as 3x-ui): `GET /admin/login`
- Admin dashboard (all subscription records, enable/disable/delete): `GET /admin/dashboard`

## Run

1. Copy env

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

`PANEL_KEY` usage:

- Use a different `PANEL_KEY` value per 3x-ui server deployment.
- Example: `PANEL_KEY=hk-prod-01`, `PANEL_KEY=sg-prod-01`
- All users/plans/orders/subscriptions are isolated by this key.

3. Open

- User portal: `http://127.0.0.1:8090/user/login`
- Admin portal: `http://127.0.0.1:8090/admin/login`

## Plan setup

Plans are stored in SQL Server table `plans` (auto-created by migration).
You can insert plans manually; `inbound_id` should point to existing 3x-ui inbound ID.

Example:

```sql
INSERT INTO plans (name, inbound_id, traffic_gb, duration_days, price_cents, currency, status, created_at, updated_at)
VALUES
('10GB 30天', 1, 10, 30, 999, 'USD', 'ACTIVE', GETDATE(), GETDATE()),
('100GB 90天', 1, 100, 90, 4999, 'USD', 'ACTIVE', GETDATE(), GETDATE());
```

## Upgrade strategy

- Keep `/Volumes/MacMiniDisk/project/fwwebtool/3x-ui-upstream` as clean upstream source.
- Keep this project as your business extension service.
