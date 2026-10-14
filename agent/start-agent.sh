#!/usr/bin/env bash
# AegisApex agent - start on macOS / Linux: ./start-agent.sh
# First run asks for your Supabase URL and service_role key and saves them to
# agent/.env (never committed). Later runs start straight away.
set -euo pipefail
cd "$(dirname "$0")"

PY=$(command -v python3 || command -v python || true)
if [ -z "$PY" ]; then
  echo "Python 3 is not installed. Install Python 3.12 from python.org, then run this again." >&2
  exit 1
fi

if [ ! -f .env ]; then
  echo "=== First-time setup === (Supabase: Project Settings > API)"
  while :; do
    read -r -p "Supabase Project URL (https://....supabase.co): " url
    [[ "$url" == https://* ]] && break
    echo "  That does not start with https:// - try again."
  done
  key=""
  while [ -z "$key" ]; do read -r -s -p "Supabase service_role key (hidden): " key; echo; done
  umask 077
  printf 'SUPABASE_URL=%s\nSUPABASE_SERVICE_ROLE_KEY=%s\n' "$url" "$key" > .env
  echo "  Saved to agent/.env"
fi

[ -x .venv/bin/python ] || "$PY" -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -q -r requirements.txt
echo "Starting the agent. Press Ctrl+C to stop."
exec .venv/bin/python worker.py
