# bughunter (HunterOps)

Autonomous bug bounty research framework for authorized targets only.

## System Requirements
- Ubuntu 22.04+ (recommended).
- Docker Engine 24+.
- Docker Compose v2 (`docker compose`).
- Linux host (Windows workflows were removed).
- Python 3.11+ (optional local runs/tests).
- Redis is provisioned as an internal service in `docker-compose.yml`.

## 3-Minute Deploy (Ubuntu + Docker)
1. Clone and enter the project:
   ```bash
   git clone <YOUR_REPO_URL> hunterops
   cd hunterops
   ```
2. Create runtime env file:
   ```bash
   cp .env.example .env
   ```
3. Edit `.env` with minimum required values:
   - `POSTGRES_USER`
   - `POSTGRES_PASSWORD`
   - `POSTGRES_DB`
   - `HUNTEROPS_POSTGRES_DSN` (must match db creds, default host is `db`)
4. Put in-scope targets in `data/targets/in_scope_hosts.txt` (one host per line).
5. Start stack:
   ```bash
   docker compose up -d --build
   ```
6. Confirm health:
   ```bash
   docker compose ps
   ```

## First-Run Configuration
- Targets file:
  - `data/targets/in_scope_hosts.txt`
  - Example:
    ```txt
    api.example.com
    app.example.com
    ```
- Main config:
  - `config/engine.yaml`
  - Review at least:
    - `runtime.rate_limit_per_sec`
    - `runtime.concurrency`
    - `runtime.recursion_max_depth`
    - `runtime.max_tasks_per_target`
    - `storage.postgres.enabled`
    - `modules.deep_js_intelligence`, `modules.parameter_intelligence`, `modules.auth_matrix_engine`
- Session profiles (for auth-matrix and differential checks):
  - `data/sessions.yaml` (tokens/cookies for `user`, `user_b`, optional `admin`).

## Kill Chain Flow
- `Recon/Surface` -> deep JS and route discovery.
- `Parameter Intelligence` -> endpoint/parameter typing and safe probes.
- `Business Logic Sniper` -> financial tampering, coupon abuse, currency/state-machine checks.
- `Race Turbo` -> 20+ parallel requests on high-value balance/update flows.
- `Differential/Auth Matrix` -> context comparison (`Auth A` vs `Auth B` vs unauth).
- `Entity Cross-Pollination` -> discovered IDs/entities reused across mapped endpoints.
- `PoC/Report` -> evidence bundling and markdown/json outputs.

## Operational Commands
- Start engine:
  ```bash
  docker compose up -d --build
  ```
- Follow app logs:
  ```bash
  docker logs -f hunterops-app
  ```
  or:
  ```bash
  docker compose logs -f app
  ```
- Follow monitor logs:
  ```bash
  docker compose logs -f monitor
  ```
- Stop stack:
  ```bash
  docker compose down
  ```

## Database Quick Check
Run a SQL query for verified findings:
```bash
docker compose exec db psql -U hunter -d hunterops -c \
"select severity, plugin, target, endpoint, confidence_score, created_at from verified_findings order by created_at desc limit 20;"
```

## Monitoring and Alerts
- Discord:
  - Set `HUNTEROPS_DISCORD_RECON_WEBHOOK` and `HUNTEROPS_DISCORD_FINDINGS_WEBHOOK` in `.env` for runtime findings routing.
  - For rich triage routing (`AlertRouter`), optionally set `HUNTEROPS_DISCORD_RESEARCH_WEBHOOK` and `HUNTEROPS_DISCORD_CRITICAL_WEBHOOK`.
  - Set `HUNTEROPS_CRITICAL_WEBHOOK` in `.env` for critical report synthesis alerts.
  - `MONITOR_DISCORD_WEBHOOK`/`DISCORD_WEBHOOK_URL` are used by `scripts/monitor_status.py`.
- Slack:
  - Set `HUNTEROPS_SLACK_RESEARCH_WEBHOOK` and `HUNTEROPS_SLACK_CRITICAL_WEBHOOK` in `.env` for Block Kit alerts.
- Telegram:
  - Set `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` in `.env`.
- Monitor loop sends periodic operational summaries via `scripts/monitor_status.py` (already wired in `docker-compose.yml`).

## Safety and Performance
- Keep scans non-disruptive:
  - Tune `runtime.rate_limit_per_sec` and `runtime.concurrency` in `config/engine.yaml`.
- Protect local usability:
  - Tune `.env` resource caps:
    - `APP_CPUS`, `APP_MEM_LIMIT`, `APP_MEM_RESERVATION`
    - `DB_CPUS`, `DB_MEM_LIMIT`, `DB_MEM_RESERVATION`
    - `MONITOR_CPUS`, `MONITOR_MEM_LIMIT`
- Recursion guardrails:
  - `runtime.recursion_max_depth`
  - `runtime.recursion_max_tasks`
  - `runtime.max_tasks_per_target`
- Only run against explicit in-scope assets.

## Optional Integrations
- HackerOne scope sync: configure `HACKERONE_API_USER` and `HACKERONE_API_TOKEN`, then enable in `config/engine.yaml`.
- OOB engine: configure `HUNTEROPS_OOB_CALLBACK_DOMAIN`, `HUNTEROPS_OOB_POLL_URL`, `HUNTEROPS_OOB_API_TOKEN`, then enable in `config/engine.yaml`.

## Local Test (without Docker)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export HUNTEROPS_HOME="$(pwd)"
python scripts/research_pipeline.py --config config/engine.yaml --out-dir data/reports/research
```

## Notes
- Default Linux root inside container is `/opt/hunterops`.
- Persistent data is stored in Docker volumes (`pgdata`, `hunterops-data`, `hunterops-reports`, `redis-data`).
- Use only authorized bug bounty scopes.
