#!/usr/bin/env bash
# W0 loopback simnet harness (Track A2, step W0).
#
# Launches N >= 8 c2pool-v37 node processes on one host over a loopback port
# ring (node i dials node (i+1) mod N), waits for the mesh to form and the
# processes to idle-then-exit, and asserts the W0 exit criteria:
#   * every node exits 0,
#   * every node logged ops_committed=1 (only the seeding AddLane ran —
#     nothing was exchanged),
#   * every node's lane-0 genesis digest is IDENTICAL (same seeded geometry).
#
# Usage: tools/v37_simnet.sh <path-to-c2pool-v37> [N] [base-port] [hold-ms]
set -u

BIN="${1:?usage: v37_simnet.sh <c2pool-v37 binary> [N] [base-port] [hold-ms]}"
N="${2:-8}"
BASE="${3:-39070}"
HOLD="${4:-600}"

if [ "$N" -lt 8 ]; then echo "N must be >= 8 (W0 exit criterion)"; exit 2; fi

TMP="$(mktemp -d)"
pids=()
for i in $(seq 0 $((N - 1))); do
    port=$((BASE + i))
    peer=$((BASE + ((i + 1) % N)))     # ring: each node dials its successor
    "$BIN" --node-id "$i" --listen "$port" --peers "$peer" --hold-ms "$HOLD" \
        > "$TMP/node_$i.log" 2>&1 &
    pids+=("$!")
done

rc=0
for i in $(seq 0 $((N - 1))); do
    if ! wait "${pids[$i]}"; then
        echo "node $i: exited NONZERO"; rc=1
    fi
done

digests=""
for i in $(seq 0 $((N - 1))); do
    log="$TMP/node_$i.log"
    if ! grep -q "ops_committed=1 " "$log"; then
        echo "node $i: MISSING ops_committed=1"; rc=1
    fi
    d=$(grep -o 'digest=[0-9a-f]*' "$log" | tail -1 | cut -d= -f2)
    digests="$digests $d"
done

uniq_d=$(echo "$digests" | tr ' ' '\n' | grep -v '^$' | sort -u | wc -l)
if [ "$uniq_d" -ne 1 ]; then
    echo "genesis digests DIFFER across nodes:$digests"; rc=1
else
    echo "genesis digest identical across all $N nodes:$(echo $digests | awk '{print $1}')"
fi

if [ "$rc" -eq 0 ]; then
    echo "SIMNET OK: $N nodes meshed, idled, exited 0, ops_committed=1 each"
else
    echo "SIMNET FAIL"; for i in $(seq 0 $((N-1))); do echo "--- node $i ---"; cat "$TMP/node_$i.log"; done
fi
rm -rf "$TMP"
exit "$rc"
