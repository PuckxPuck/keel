#!/bin/sh
# Local development only: runs postgres-roles.sql with throwaway passwords. Never use these values anywhere shared.
set -eu

set -- -v owner_password="${KEEL_OWNER_PASSWORD:?}" -v app_password="${KEEL_APP_PASSWORD:?}"
# part:tenancy
set -- "$@" -v operator_password="${KEEL_OPERATOR_PASSWORD:?}"
# /part:tenancy
exec psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" "$@" -f /opt/keel/postgres-roles.sql
