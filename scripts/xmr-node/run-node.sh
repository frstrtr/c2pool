#!/usr/bin/env bash
# run-node.sh [ENV_FILE] - start c2pool-v37-xmr with the flags from ENV_FILE
# (default: $C2POOL_XMR_DATA/node.env, else ./node.env). Used by the systemd
# unit and by hand. It also starts memguard.sh, which stops the node with
# SIGINT (a clean stop that saves the chain index) when the machine runs low
# on memory.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${1:-${C2POOL_XMR_DATA:+$C2POOL_XMR_DATA/node.env}}"
ENV_FILE="${ENV_FILE:-./node.env}"
[ -r "$ENV_FILE" ] || { echo "run-node: cannot read $ENV_FILE" >&2; exit 1; }

ARGS=""
# shellcheck disable=SC1090
. "$ENV_FILE"

BIN="${C2POOL_XMR_BIN:-$HERE/c2pool-v37-xmr}"
[ -x "$BIN" ] || { echo "run-node: no binary at $BIN" >&2; exit 1; }
[ -n "$ARGS" ] || { echo "run-node: ARGS is empty in $ENV_FILE" >&2; exit 1; }

# The dashboard files: default to the installed share/web-static.
case " $ARGS " in
    *" --dashboard-dir "*) ;;
    *) [ -d "$HERE/../share/web-static" ] && ARGS="$ARGS --dashboard-dir $HERE/../share/web-static" ;;
esac

if [ -n "${C2POOL_XMR_WORKDIR:-}" ]; then cd "$C2POOL_XMR_WORKDIR"; fi

# memguard watches THIS pid, which becomes the node's pid after exec.
if [ "${MEMGUARD:-on}" != "off" ]; then
    "$HERE/memguard.sh" "$$" "${MEMGUARD_MIN_MB:-1024}" &
fi

echo "run-node: $BIN $ARGS"
# shellcheck disable=SC2086
exec "$BIN" $ARGS
