#!/usr/bin/env bash
# Applies the migration twice to a scratch database built from the Supabase
# shim, then runs the RLS / queue assertions. Usage:
#   PGHOST=... PGPORT=... PGUSER=postgres supabase/tests/run.sh
set -euo pipefail
cd "$(dirname "$0")/.."
DB=aegis_migration_test
psql -q -c "drop database if exists $DB" -c "create database $DB" postgres
run() { PGOPTIONS='-c client_min_messages=warning' psql -q -v ON_ERROR_STOP=1 -d "$DB" -f "$1"; }
run tests/supabase_shim.sql
run migrations/20261014120000_aegisapex_upgrades.sql
run migrations/20261014120000_aegisapex_upgrades.sql
run tests/rls_check.sql
