#!/usr/bin/env bash
set -euo pipefail

mode="${1:-web}"

python manage.py migrate --noinput

if [ "$mode" = "worker" ]; then
  exec celery -A config worker -l INFO -Q recon,scan,triage,notify
fi

exec python manage.py runserver 0.0.0.0:8000
