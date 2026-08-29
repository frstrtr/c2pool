#!/usr/bin/env bash
# HiveOS miner launcher for c2pool

cd "$(dirname "$0")"

# Source manifest for MINER_API_PORT etc.
. h-manifest.conf

# Generate config from flight sheet variables
. h-config.sh

# Read generated config
CONF=$(cat config.txt 2>/dev/null)

if [[ -z "$CONF" ]]; then
    echo "ERROR: No config generated. Check flight sheet settings."
    exit 1
fi

# Ensure log directory exists
mkdir -p /var/log/miner/c2pool

# Launch c2pool
# shellcheck disable=SC2086
exec ./c2pool $CONF 2>&1
