#!/bin/bash
# GAP-2 rig helpers (sourced). daemons: d1 rpc 44901, d2 44911, d3 44921. relay 45000-45002. stratum 5790-5792.
R=~/gap2-rig
BIN=${BIN:-/home/ubuntu/wt-gap2/build/src/c2pool/c2pool-v37-xmr}
H()   { curl -s -m 5 127.0.0.1:${1:-44901}/get_info -d "{}" -H "Content-Type: application/json" | grep -oE "\"height\": *[0-9]+" | grep -oE "[0-9]+"; }
TOP() { curl -s -m 5 127.0.0.1:${1:-44901}/get_info -d "{}" -H "Content-Type: application/json" | grep -oE "\"top_block_hash\": *\"[0-9a-f]+" | grep -oE "[0-9a-f]{64}"; }
waitpast() { local port=$1 t=$2 n=0; until [ "$(H $port)" -ge "$t" ] 2>/dev/null || [ $n -ge 120 ]; do sleep 2; n=$((n+1)); done; }
