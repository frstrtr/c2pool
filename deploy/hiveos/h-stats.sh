#!/usr/bin/env bash
# HiveOS stats reporter for c2pool
#
# Must set two variables:
#   khs   — total hashrate in kilohashes/second
#   stats — JSON object with hs, temp, fan, uptime, ar, algo, ver
#
# Queries c2pool's REST API on MINER_API_PORT (default 8080).

cd "$(dirname "$0")"
. h-manifest.conf

API="http://127.0.0.1:${MINER_API_PORT}"

# Fetch stats from c2pool API (with timeout to avoid hanging)
local_stats=$(curl -s --max-time 5 "${API}/local_stats" 2>/dev/null)
stratum_stats=$(curl -s --max-time 5 "${API}/stratum_stats" 2>/dev/null)
uptime_val=$(curl -s --max-time 5 "${API}/uptime" 2>/dev/null)

if [[ -z "$local_stats" || "$local_stats" == "null" ]]; then
    # Miner not yet responding — report zero
    khs=0
    stats='{}'
    return 0 2>/dev/null || exit 0
fi

# Extract total hashrate (H/s) from all miners, convert to kH/s
# local_stats.miner_hash_rates is {address: hashrate_hs, ...}
total_hs=$(echo "$local_stats" | jq -r '
    [.miner_hash_rates // {} | to_entries[] | .value] | add // 0
')
khs=$(echo "$total_hs" | awk '{printf "%.2f", $1 / 1000}')

# Extract accepted/rejected from stratum_stats
# stratum_stats.workers is {worker_name: {accepted: N, rejected: N, ...}, ...}
accepted=$(echo "$stratum_stats" | jq -r '
    [.workers // {} | to_entries[] | .value.accepted // 0] | add // 0
')
rejected=$(echo "$stratum_stats" | jq -r '
    [.workers // {} | to_entries[] | .value.rejected // 0] | add // 0
')

# Per-worker hashrates for HiveOS hs[] array (in H/s)
hs_array=$(echo "$local_stats" | jq -c '
    [.miner_hash_rates // {} | to_entries[] | .value] // [0]
')

# Uptime in seconds
up=$(echo "$uptime_val" | jq -r '. // 0' 2>/dev/null)
[[ -z "$up" || "$up" == "null" ]] && up=0

# Pool efficiency
efficiency=$(echo "$local_stats" | jq -r '.efficiency // 0')

# Shares info
total_shares=$(echo "$local_stats" | jq -r '.shares.total // 0')
orphan_shares=$(echo "$local_stats" | jq -r '.shares.orphan // 0')
dead_shares=$(echo "$local_stats" | jq -r '.shares.dead // 0')

# Build stats JSON
# HiveOS expects: hs (array), hs_units, temp (array), fan (array),
#                 uptime, ar (array [accepted, rejected]), algo, ver
stats=$(jq -n \
    --argjson hs "$hs_array" \
    --arg hs_units "hs" \
    --argjson uptime "$up" \
    --argjson accepted "$accepted" \
    --argjson rejected "$rejected" \
    --arg ver "$MINER_LATEST_VER" \
    --argjson total_shares "$total_shares" \
    --argjson orphan_shares "$orphan_shares" \
    --argjson dead_shares "$dead_shares" \
    --argjson efficiency "$efficiency" \
    '{
        hs: $hs,
        hs_units: $hs_units,
        temp: [],
        fan: [],
        uptime: $uptime,
        ar: [$accepted, $rejected],
        algo: "scrypt",
        ver: $ver,
        "total_shares": $total_shares,
        "orphan_shares": $orphan_shares,
        "dead_shares": $dead_shares,
        "efficiency": $efficiency
    }')
