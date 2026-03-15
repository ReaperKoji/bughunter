#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CLI_TARGETS_FILE="${1:-}"
CLI_OUT_DIR="${2:-}"
CLI_MAX_HOURS="${3:-}"

# Load local runtime env if available.
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

TARGETS_FILE="${CLI_TARGETS_FILE:-${TARGETS_FILE:-data/processed/capital_24h_targets.txt}}"
OUT_DIR="${CLI_OUT_DIR:-${OUT_DIR:-data/reports/research/capital_24h}}"
MAX_HOURS="${CLI_MAX_HOURS:-${MAX_HOURS:-24}}"

if [[ ! -f "$TARGETS_FILE" ]]; then
  echo "targets_file_not_found path=$TARGETS_FILE" >&2
  exit 2
fi

mkdir -p "$OUT_DIR" data/logs
LOG_FILE="data/logs/capital_24h_$(date -u +%Y%m%d_%H%M%S).log"
LOCK_FILE="/tmp/hunterops_capital_24h.lock"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "runner_already_active lock=$LOCK_FILE" >&2
  exit 3
fi

if [[ ! -x .venv/bin/python ]]; then
  echo "missing_virtualenv_python path=.venv/bin/python" >&2
  exit 4
fi

missing_env=0
for key in HUNTEROPS_POSTGRES_DSN INTIGRITI_API_TOKEN; do
  if [[ -z "${!key:-}" ]]; then
    echo "missing_required_env env=$key" >&2
    missing_env=1
  fi
done
if [[ "$missing_env" -ne 0 ]]; then
  exit 5
fi

END_TS=$(( $(date +%s) + (MAX_HOURS * 3600) ))
ITER=0

echo "capital_24h_runner_start targets=$TARGETS_FILE out_dir=$OUT_DIR log=$LOG_FILE max_hours=$MAX_HOURS" | tee -a "$LOG_FILE"

while [[ $(date +%s) -lt $END_TS ]]; do
  ITER=$((ITER + 1))
  RUN_ID="$(date -u +%Y%m%d_%H%M%S)_capital24h_${ITER}"
  echo "run_start run_id=$RUN_ID iteration=$ITER" | tee -a "$LOG_FILE"

  set +e
  timeout 55m .venv/bin/python scripts/research_pipeline.py \
    --config config/engine.yaml \
    --targets-file "$TARGETS_FILE" \
    --run-id "$RUN_ID" \
    --out-dir "$OUT_DIR" >>"$LOG_FILE" 2>&1
  RC=$?
  set -e

  echo "run_end run_id=$RUN_ID rc=$RC" | tee -a "$LOG_FILE"

  if [[ $(date +%s) -ge $END_TS ]]; then
    break
  fi

  sleep 60
done

echo "capital_24h_runner_done log=$LOG_FILE" | tee -a "$LOG_FILE"
