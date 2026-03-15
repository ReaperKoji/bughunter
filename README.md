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
- Deadman alerts (no activity for X hours): set `MONITOR_DEADMAN_HOURS` in `.env`.
- Secrets can be provided via `*_FILE` (Docker secrets) or systemd `CREDENTIALS_DIRECTORY`.

## Nuclei Curation (Weekly)
- Run `scripts/nuclei_curation.py` + `scripts/nuclei_curation_apply.py` to generate `templates/nuclei-curated`.
- If you use systemd, enable the weekly timer in `ops/systemd/nuclei-curation.timer`.
- `nuclei_curation_apply.py --bootstrap-tags` can seed curated templates when no signals exist yet.

## Safety and Performance
- Keep scans non-disruptive:
  - Tune `runtime.rate_limit_per_sec` and `runtime.concurrency` in `config/engine.yaml`.
- Endpoint noise controls:
  - `runtime.endpoint_cache_enabled` and `runtime.endpoint_cache_ttl_hours` to avoid rescanning identical endpoints too frequently.
  - `runtime.endpoint_cache_max_entries` caps local endpoint cache size.
  - `runtime.endpoint_noise_patterns` to drop noisy paths (supports substring, glob `*`, or `re:` regex).
- ROI prioritization:
  - `runtime.priority_endpoint_patterns` and `runtime.priority_endpoint_boost` to push high-value paths to the front of the queue.
  - `runtime.roi_endpoint_patterns`, `runtime.roi_endpoint_boost`, and `runtime.roi_plugin_boosts` for higher-value workflows.
- Auto-mute:
  - `runtime.auto_mute_*` pauses targets that trigger repeated 403/429 spikes.
- Per-target burst control:
  - `runtime.per_target_inflight` and `runtime.per_target_jitter_ms` reduce spike bursts per host.
- Delta-first:
  - `runtime.delta_priority_min_score` forces new deltas to the front when meaningful.
- Memory cap:
  - `runtime.findings_flush_every` clears in-memory findings after N entries (set 0 to disable); findings remain in Postgres.
- Plugin performance logs:
  - `runtime.plugin_metrics_enabled` emits per-plugin call/error/latency summaries after each batch.
- Alert dedupe (persistent):
  - `modules.alert_router.dedupe_persist_*` keeps a rolling cache to avoid re-alerting the same issue across runs.
- Alert cooldown:
  - `modules.alert_router.cooldown_seconds` throttles per-target alerts (bypass critical by default).
  - `modules.alert_router.cooldown_scope` can be `target`, `target_category`, `target_severity`, or `program`.
- Discord finding dedupe (persistent):
  - `modules.discord_notifier.findings_dedupe_persist_*` prevents repeated confirmations across runs.
- Scheduler guardrails:
  - `RUN_MAX_SECONDS` caps each pipeline cycle runtime.
  - `RUN_JITTER_SECONDS` adds jitter between cycles to reduce sync bursts.
- ROE enforcement (recommended):
  - `HUNTEROPS_REQUIRE_PROGRAM_MATCH=1` to drop targets not covered by `config/programs.yaml`.
  - `HUNTEROPS_ENFORCE_ALLOWED_HOURS=1` to skip scans outside allowed windows.
  - `HUNTEROPS_REQUIRE_PROGRAM_HEADERS=1` to abort when mandatory headers are missing.
- Program-level plugin gating:
  - Use `allowed_plugins` / `blocked_plugins` per program in `config/programs.yaml` to restrict which plugins can run for each target.
  - `allowed_modules` / `blocked_modules` are also mapped by substring to plugin names (warns if no match).
- Protect local usability:
  - Tune `.env` resource caps:
    - `APP_CPUS`, `APP_MEM_LIMIT`, `APP_MEM_RESERVATION`
    - `DB_CPUS`, `DB_MEM_LIMIT`, `DB_MEM_RESERVATION`
    - `MONITOR_CPUS`, `MONITOR_MEM_LIMIT`
- Log rotation:
  - Install `ops/logrotate/hunterops-data-logs.conf` into `/etc/logrotate.d/` to rotate `data/logs/*.log`.
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

## Attack Chain Pipeline (Adaptive)
Run the standalone attack-chain pipeline (safe, modular, adaptive):
```bash
python3 scripts/attack_pipeline.py --config attack_pipeline.yaml
```

Example module body template (JSON POST):
```yaml
modules:
  idor:
    method: POST
    body_type: json
    body_template:
      from: \"{{acct}}\"
      to: \"x\"
      amount: 1
    placeholders:
      acct: \"acct_1\"
```

### Scope Authorization (Required)
Each run must pass an authorization gate:
- Option A (recommended): signed `config/scope.json`
- Option B: `AUTHORIZED_TARGETS` env list (comma-separated)
  - To force signed scopes only, set `HUNTEROPS_REQUIRE_SIGNED_SCOPE=1`.
  - To warn before expiry, set `HUNTEROPS_SCOPE_EXPIRY_WARN_DAYS` (e.g., `7`).

Example `config/scope.json` (unsigned template is in `examples/scope_unsigned.json`):
```json
{
  "targets": ["*.capital.com", "*.backend-capital.com"],
  "authorized_by": "Security Team",
  "valid_from": "2026-03-10T00:00:00Z",
  "valid_to": "2026-04-10T00:00:00Z",
  "rules_of_engagement": "Automated scanning is permitted under rate limits.",
  "signature_meta": {"algorithm": "hmac-sha256"},
  "signature": "<signature>"
}
```

If targets are not authorized, the run aborts with `preflight_failed`.

Sign/verify scope locally:
```bash
make sign-scope
make verify-scope
```

Gate execution (bash snippet):
```bash
python3 tools/verify_scope.py config/scope.json || { echo \"scope invalid\"; exit 1; }
export AUTHORIZED_TARGETS=\"*.example.com\" # fallback only when no signed scope is available
```

To generate an RSA keypair locally (public key only is stored in repo):
```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out config/signer.key
openssl rsa -in config/signer.key -pubout -out config/signer.pub
```

You can override scope path with:
```bash
export HUNTEROPS_SCOPE_PATH=/path/to/scope.json
```

### Go/No-Go Checklist
Before any run, a go/no-go report is generated at:
- `reports/go_no_go.json`
- `reports/go_no_go.md`

You can run the checklist manually:
```bash
python3 tools/go_no_go.py --config attack_pipeline.yaml
```

### Program Config Validation
Validate `config/programs.yaml`:
```bash
python3 tools/validate_program_config.py config/programs.yaml
```

### Sessions/Vault Templates
See:
- `data/sessions.example.yaml`
- `config/vault.example.yaml`

### Reporting Templates
Report templates are in:
- `config/report_templates.yaml`
- Example program config: `config/program_example.yaml`

### Observability
Start local observability:
```bash
make start-observability
```
Files:
- Prometheus config: `prometheus/prometheus.yml`
- Alert rules: `prometheus/alert_rules.yml`
- Grafana dashboard JSON: `grafana/dashboard.json`
- Metrics exporter: `observability/pipeline_metrics_client.py`

Run metrics exporter (local dev):
```bash
python3 observability/pipeline_metrics_client.py --events data/events/events.ndjson --summary data/metrics/attack_chain_summary.json --port 9108
```

### Runbook Actions (Auto/Safe)
Runtime controls (pause, reduce rate, temporary block) are stored in:
- `data/runtime/runbook_override.json`

Manual controls:
```bash
python3 tools/runbook_action.py pause --minutes 15 --reason "manual_pause"
python3 tools/runbook_action.py reduce-rate --multiplier 0.5 --minutes 20
python3 tools/runbook_action.py block-host example.com --minutes 15
python3 tools/runbook_action.py resume
```

### Threshold Calibration
Calibrate thresholds using labeled data:
```bash
python3 tools/calibrate_thresholds.py examples/labeled_scan_results.csv --report reports/threshold_recommendation.md
```

### Mock API (E2E)
Start the mockserver:
```bash
docker compose -f examples/mockserver/docker-compose.yml up -d
```
Run the E2E test:
```bash
make e2e
```

### Tests
Run unit tests:
```bash
pytest -q
```

### Make Targets
```bash
make sign-scope
make verify-scope
make test
make e2e
make start-observability
```
