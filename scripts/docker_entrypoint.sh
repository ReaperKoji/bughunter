#!/usr/bin/env bash
set -euo pipefail

ROOT="${HUNTEROPS_HOME:-/opt/hunterops}"
APP_USER="${HUNTEROPS_APP_USER:-hunterops}"
SESSIONS_FILE="${HUNTEROPS_SESSIONS_FILE:-${ROOT}/data/sessions.yaml}"

mkdir -p "${ROOT}/data" "${ROOT}/data/evidence" "${ROOT}/data/processed" "${ROOT}/reports"
chmod 0755 "${ROOT}/data" "${ROOT}/data/evidence" "${ROOT}/data/processed" "${ROOT}/reports" || true

# Seed a default sessions file inside the runtime data volume when missing/invalid.
# This keeps authenticated modules functional with env-based cookie/session secrets.
if [ ! -s "${SESSIONS_FILE}" ] || ! grep -q "cookie_env:" "${SESSIONS_FILE}" 2>/dev/null; then
  mkdir -p "$(dirname "${SESSIONS_FILE}")"
  cat > "${SESSIONS_FILE}" <<'YAML'
sessions:
  - name: user
    token_type: Bearer
    token_env: HUNTEROPS_USER_TOKEN
    cookie_env: HUNTEROPS_USER_COOKIE
    headers: {}
  - name: user_b
    token_type: Bearer
    token_env: HUNTEROPS_USER_B_TOKEN
    cookie_env: HUNTEROPS_USER_B_COOKIE
    headers: {}
  - name: admin
    token_type: Bearer
    token_env: HUNTEROPS_ADMIN_TOKEN
    cookie_env: HUNTEROPS_ADMIN_COOKIE
    headers: {}
YAML
fi

if [ "$(id -u)" -eq 0 ]; then
  chown -R "${APP_USER}:${APP_USER}" "${ROOT}/data" "${ROOT}/reports" || true
fi

for secret_file in \
  "${ROOT}/.env" \
  "${SESSIONS_FILE}" \
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

# Keep HackerOne env names in sync across modules.
if [ -z "${H1_API_TOKEN:-}" ] && [ -n "${HACKERONE_API_TOKEN:-}" ]; then
  export H1_API_TOKEN="${HACKERONE_API_TOKEN}"
fi
if [ -z "${HACKERONE_API_TOKEN:-}" ] && [ -n "${H1_API_TOKEN:-}" ]; then
  export HACKERONE_API_TOKEN="${H1_API_TOKEN}"
fi
if [ -z "${H1_API_IDENTIFIER:-}" ] && [ -n "${HACKERONE_API_USER:-}" ]; then
  export H1_API_IDENTIFIER="${HACKERONE_API_USER}"
fi
if [ -z "${HACKERONE_API_USER:-}" ] && [ -n "${H1_API_IDENTIFIER:-}" ]; then
  export HACKERONE_API_USER="${H1_API_IDENTIFIER}"
fi

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
