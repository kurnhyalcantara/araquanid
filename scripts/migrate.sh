#!/usr/bin/env bash
# Run database migrations without a local `migrate` binary, using the
# migrate/migrate Docker image against the shared koer-network Postgres
# (see deployments/docker-compose.yml's `migrate` service — this mirrors
# its DSN formula since `docker compose run <args>` replaces its command).
#
# Usage: scripts/migrate.sh [up|down 1|version|...]
set -euo pipefail

cd "$(dirname "$0")/.."

set -a
[ -f .env ] && source .env
[ -f deployments/.env ] && source deployments/.env
set +a

DATABASE_URL="${ARAQUANID_MIGRATE_DATABASE_URL:-postgres://${ARAQUANID_POSTGRES__USER:-admin}:${ARAQUANID_POSTGRES__PASSWORD:?set ARAQUANID_POSTGRES__PASSWORD or ARAQUANID_MIGRATE_DATABASE_URL}@koer-postgres:${ARAQUANID_POSTGRES__PORT:-5432}/${ARAQUANID_POSTGRES__DATABASE:-araquanid}?sslmode=${ARAQUANID_POSTGRES__SSL_MODE:-disable}}"

docker compose -f deployments/docker-compose.yml run --rm migrate \
  -path=/migrations \
  -database="$DATABASE_URL" \
  "${@:-up}"
