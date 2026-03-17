#!/usr/bin/env bash
# RaveOS stats collector for c2pool
# Outputs JSON to stdout in RaveOS-compatible format.

API="http://127.0.0.1:8080"

local_stats=$(curl -s --max-time 5 "${API}/local_stats" 2>/dev/null)
stratum_stats=$(curl -s --max-time 5 "${API}/stratum_stats" 2>/dev/null)
uptime_val=$(curl -s --max-time 5 "${API}/uptime" 2>/dev/null)

if [[ -z "$local_stats" || "$local_stats" == "null" ]]; then
    echo '{"hash_rate": 0, "shares": {"accepted": 0, "rejected": 0, "invalid": 0}}'
    exit 0
fi

# Total hashrate
total_hs=$(echo "$local_stats" | jq '[.miner_hash_rates // {} | to_entries[] | .value] | add // 0')

# Share counts
accepted=$(echo "$stratum_stats" | jq '[.workers // {} | to_entries[] | .value.accepted // 0] | add // 0')
rejected=$(echo "$stratum_stats" | jq '[.workers // {} | to_entries[] | .value.rejected // 0] | add // 0')

uptime=$(echo "$uptime_val" | jq '. // 0' 2>/dev/null)
[[ -z "$uptime" || "$uptime" == "null" ]] && uptime=0

jq -n \
    --argjson hash_rate "$total_hs" \
    --argjson accepted "$accepted" \
    --argjson rejected "$rejected" \
    --argjson uptime "$uptime" \
    '{
        hash_rate: $hash_rate,
        uptime: $uptime,
        algo: "scrypt",
        shares: {
            accepted: $accepted,
            rejected: $rejected,
            invalid: 0
        }
    }'
