#!/usr/bin/env bash
set -euo pipefail

ROOT="${HUNTEROPS_HOME:-/opt/hunterops}"
APP_USER="${HUNTEROPS_APP_USER:-hunterops}"

mkdir -p "${ROOT}/data" "${ROOT}/data/evidence" "${ROOT}/data/processed" "${ROOT}/reports"
chmod 0755 "${ROOT}/data" "${ROOT}/data/evidence" "${ROOT}/data/processed" "${ROOT}/reports" || true

if [ "$(id -u)" -eq 0 ]; then
  chown -R "${APP_USER}:${APP_USER}" "${ROOT}/data" "${ROOT}/reports" || true
fi

for secret_file in \
  "${ROOT}/.env" \
  "${ROOT}/data/sessions.yaml" \
  "${HUNTEROPS_SESSIONS_FILE:-}" \
  "${HUNTEROPS_ENV_FILE:-}"; do
  if [ -n "${secret_file}" ] && [ -f "${secret_file}" ]; then
    chmod 0600 "${secret_file}" || true
  fi
done

for bin_name in subfinder httpx naabu nuclei interactsh-client amass hunterops_rust_analyzer; do
  if command -v "${bin_name}" >/dev/null 2>&1; then
    chmod 0755 "$(command -v "${bin_name}")" || true
  fi
done

if [ "${HUNTEROPS_SKIP_INFRA_CHECK:-0}" != "1" ] && [ -f "${ROOT}/scripts/check_infra.sh" ]; then
  bash "${ROOT}/scripts/check_infra.sh"
fi

if [ "$#" -eq 0 ]; then
  set -- python scripts/research_pipeline.py --config config/engine.yaml --targets-file "${TARGETS_FILE:-data/targets/in_scope_hosts.txt}"
fi

if [ "$(id -u)" -eq 0 ] && command -v gosu >/dev/null 2>&1; then
  exec gosu "${APP_USER}" "$@"
fi

exec "$@"
