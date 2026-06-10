#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DUMMY_BE_ENV="${DUMMY_BE_ENV:-$HOME/nexth-dummy-be/.env}"

# Load DB credentials — dummy-be .env is canonical, local .env overrides it
if [[ -f "$DUMMY_BE_ENV" ]]; then
    set -o allexport
    # shellcheck disable=SC1091
    source "$DUMMY_BE_ENV"
    set +o allexport
    echo "[start] Loaded $DUMMY_BE_ENV"
fi

if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -o allexport
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
    set +o allexport
    echo "[start] Loaded $SCRIPT_DIR/.env"
fi

# ── DB connection ──────────────────────────────────────────────────────────────
: "${DB_HOST:=127.0.0.1}"
: "${DB_PORT:=5432}"
: "${DB_NAME:=myapp_db}"
: "${DB_USER:=myapp_user}"

if [[ -z "${DB_PASS:-}" ]]; then
    echo "[start] ERROR: DB_PASS not found in $DUMMY_BE_ENV or environment." >&2
    exit 1
fi

export DB_HOST DB_PORT DB_NAME DB_USER DB_PASS

# ── Optional config file ───────────────────────────────────────────────────────
CONFIG_ARG=""
if [[ -n "${ANALYZER_CONFIG_FILE:-}" ]]; then
    CONFIG_ARG="--config $ANALYZER_CONFIG_FILE"
elif [[ -f "$SCRIPT_DIR/config.yaml" ]]; then
    CONFIG_ARG="--config $SCRIPT_DIR/config.yaml"
    echo "[start] Using config: $SCRIPT_DIR/config.yaml"
fi

# ── Python interpreter ─────────────────────────────────────────────────────────
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" &>/dev/null; then
    echo "[start] ERROR: Python interpreter '$PYTHON' not found." >&2
    exit 1
fi

echo "[start] DB=$DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
echo "[start] Starting agent-analyzer..."

cd "$SCRIPT_DIR"
exec "$PYTHON" "$SCRIPT_DIR" $CONFIG_ARG "$@"
