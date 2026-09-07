#!/usr/bin/env bash
# =============================================================================
# v37 canonical testnet — Phase A, single node, DASH REGTEST on VM100.
#
#   ssh vm100 → dashd -regtest (Dash Core v23.1.7, pinned) → generatetoaddress
#   → c2pool-v37-btc-dash on the DASH RPC backend → forced low share-diff CPU
#   miner → ONE accepted stratum-won block (A5) → FINALIZE (A6) → reorg drill
#   (A7) → restart with a PENDING block + F2 (A8) → oracle-down + fence (A9).
#
# RUN ON VM100 ONLY (`ssh vm100`, the isolated DASH regtest host). Every step is
# idempotent; run top to bottom, or `STOP_AFTER=A5 ./runbook_dash_regtest.sh`
# to stop after the first accepted block. Nothing here touches mainnet: the
# daemon is -regtest, the node refuses any chain != "regtest" and pins the
# regtest genesis (DashRpcCoinBackend::wait_ready), and refuses mainnet without
# --i-understand-mainnet (btc_node.hpp:105).
#
# FACTS PINNED TO SOURCE (Dash Core v23.1.7 unless noted; do not "fix" from memory):
#   regtest rpc port 19898, p2p 19899          src/chainparamsbase.cpp:48, src/chainparams.cpp:833
#   (19998 is TESTNET rpc — btc_node_config.hpp:87 is wrong for regtest, seam S-6)
#   regtest genesis 000008ca…3ef23d2e           src/chainparams.cpp:846 (pinned by the node; A1 verifies)
#   halving 150 (:765) / MN payments from 240 (:766) / budget 1000 (:771) / superblocks from 1500,
#   cycle 20 (:774, :776)                      src/chainparams.cpp CRegTestParams
#   DIP0003Height=432 (:788), DIP0003EnforcementHeight=500 (:790), V20Height=DIP0003Height (:798),
#   MN_RRHeight=V20Height (:799), WithdrawalsHeight=600 (:800)   src/chainparams.cpp
#   overrides applied at :840-842, THEN
#     assert(V20Height >= DIP0003Height)         src/chainparams.cpp:924
#     assert(MN_RRHeight >= V20Height)           src/chainparams.cpp:926
#   -testactivationheight=name@height names: bip147 bip34 dersig cltv csv brr dip0001
#     dip0008 dip0024 v19 v20 mn_rr             src/chainparams.cpp:1001-1041 (MaybeUpdateHeights)
#   -dip3params=<activation>:<enforcement>     src/chainparams.cpp:1106-1124
#   regtest pre-V20 subsidy 1111/(dDiff+1)^2 capped 500 DASH   src/validation.cpp GetBlockSubsidyHelper
#   Dash Core >= 19: no default wallet; createwallet is mandatory.
#   c2pool stratum: initial vardiff 1.0 (src/c2pool/hashrate/tracker.hpp:38, warm-up 4
#   shares :64); a "+N" username suffix forces the share difficulty
#   (src/core/stratum_server.cpp:643-656); StratumConfig::min_difficulty 0.0005.
#   DASH SubmitBlockFn height = TEMPLATE height (src/impl/dash/stratum/work_source.cpp:2698,
#   :2845) — the node derives H_b from the block instead (main_v37_btc_dash.cpp, D8).
# =============================================================================
set -euo pipefail

# ── A0. knobs ────────────────────────────────────────────────────────────────
export DASHCORE_VER="${DASHCORE_VER:-23.1.7}"
export DASHCORE_SHA256="${DASHCORE_SHA256:-4515634a76054a3adb5a2f3aaae150305737bc416c08568efb1b434050316213}"  # dashcore-23.1.7-x86_64-linux-gnu.tar.gz, from the release SHA256SUMS.asc
export DASHCORE_DIR="${DASHCORE_DIR:-$HOME/dashcore-$DASHCORE_VER}"
export DASH_DIR="${DASH_DIR:-$HOME/v37-regtest/dashd}"              # isolated datadir (never ~/.dashcore)
export DASH_RPC_PORT="${DASH_RPC_PORT:-19898}"
export DASH_P2P_PORT="${DASH_P2P_PORT:-19899}"
export DASH_RPC_USER="${DASH_RPC_USER:-v37regtest}"
export C2POOL_SRC="${C2POOL_SRC:-$HOME/Github/c2pool}"
export C2POOL_BRANCH="${C2POOL_BRANCH:-v37/dash-rpc-coin-backend}"   # PR-1 branch (on master 89325e91)
export C2POOL_BUILD="${C2POOL_BUILD:-$C2POOL_SRC/build-v37-dash}"
export V37_STRATUM="${V37_STRATUM:-127.0.0.1:3032}"
export V37_DCONF="${V37_DCONF:-6}"                                    # DRILL depth; production default 100 (btc_node_config.hpp:106-109)
export V37_STORE="${V37_STORE:-$HOME/v37-regtest/v37_settle_db}"
export V37_LOG="${V37_LOG:-$HOME/v37-regtest/c2pool-v37-btc-dash.log}"
export V37_AUTH="${V37_AUTH:-$HOME/v37-regtest/c2pool-dash-rpc.conf}"
export V37_BIN="${V37_BIN:-$C2POOL_BUILD/src/c2pool/c2pool-v37-btc-dash}"
export MINER_THREADS="${MINER_THREADS:-$(nproc)}"
export SHARE_DIFF="${SHARE_DIFF:-0.001}"                              # forced via the "+N" username suffix (see A5)
export STOP_AFTER="${STOP_AFTER:-A9}"
mkdir -p "$DASH_DIR" "$HOME/v37-regtest"
# the rpc password lives in dash.conf only (never on argv / in the log); reuse it across shells
if [ -f "$DASH_DIR/dash.conf" ] && grep -q '^rpcpassword=' "$DASH_DIR/dash.conf"; then
  export DASH_RPC_PASS="$(grep '^rpcpassword=' "$DASH_DIR/dash.conf" | head -1 | cut -d= -f2-)"
else
  export DASH_RPC_PASS="${DASH_RPC_PASS:-$(head -c 24 /dev/urandom | base64 | tr -d '/+=')}"
fi
DASHD="$DASHCORE_DIR/bin/dashd"; DASHCLI="$DASHCORE_DIR/bin/dash-cli"
cli() { "$DASHCLI" -regtest -datadir="$DASH_DIR" -rpcport="$DASH_RPC_PORT" -rpcuser="$DASH_RPC_USER" -rpcpassword="$DASH_RPC_PASS" "$@"; }
v37() { "$V37_BIN" --network regtest --daemon-rpc "127.0.0.1:$DASH_RPC_PORT" --coin-rpc-auth "$V37_AUTH" \
        --settle-db "${V37_STORE_OVERRIDE:-$V37_STORE}" --d-conf "$V37_DCONF" --poll-ms 500 "$@"; }
last_found() { grep '\[v37-dash\] FOUND' "$V37_LOG" | tail -1 | sed -E 's/.*FOUND ([0-9a-f]{64}).*/\1/'; }
wait_found() { local n="$1"; for i in $(seq 1 180); do [ "$(grep -c '\[v37-dash\] FOUND' "$V37_LOG" || true)" -ge "$n" ] && return 0; sleep 1; done; echo "TIMEOUT waiting for FOUND #$n"; return 1; }
stop_after() { [ "$STOP_AFTER" = "$1" ] && { echo "[stop] STOP_AFTER=$1"; exit 0; } || true; }
echo "[A0] VM100 $(hostname) dashcore=$DASHCORE_VER rpc=127.0.0.1:$DASH_RPC_PORT store=$V37_STORE d_conf=$V37_DCONF"

# ── A1. Dash Core v23.1.7 (pinned, checksummed) + dashd -regtest, isolated datadir ──
if [ ! -x "$DASHD" ]; then
  TGZ="dashcore-$DASHCORE_VER-x86_64-linux-gnu.tar.gz"
  curl -fsSL -o "/tmp/$TGZ" "https://github.com/dashpay/dash/releases/download/v$DASHCORE_VER/$TGZ"
  echo "$DASHCORE_SHA256  /tmp/$TGZ" | sha256sum -c -            # release SHA256SUMS.asc line for this asset
  mkdir -p "$DASHCORE_DIR" && tar -xzf "/tmp/$TGZ" -C "$DASHCORE_DIR" --strip-components=1
fi
"$DASHD" --version | head -1                                       # expect "Dash Core version v23.1.7"
# dash.conf — creds in a file, never on argv (rpc_conf.hpp:9-13). NO fork-activation overrides:
#   the drill never exceeds ~240 < DIP0003Height 432, so DIP3/V20/MN_RR never activate and the
#   coinbase regime (plain pre-DIP3, miner-only payout) is stable for the whole window anyway.
#   ★ verify-round fix 2: the earlier draft wrote `dip3params=5000:5000` + `testactivationheight=v20@5000`.
#   Both ABORT dashd at startup on v23.1.7: overrides are applied at chainparams.cpp:840-842, then
#   :924 assert(V20Height >= DIP0003Height) fires on the first line (V20 stays 432 < 5000) and
#   :926 assert(MN_RRHeight >= V20Height) fires on the second (MN_RR stays 432 < 5000).
#   The ONLY accepted way to push the forks out to a height N on this version is ALL THREE together:
#       dip3params=N:N
#       testactivationheight=v20@N
#       testactivationheight=mn_rr@N
#   (keys are the arg names without the dash, in the [regtest] section; there is no
#   testactivationheight name for dip0003 — it is dip3params). Not needed for this drill.
cat > "$DASH_DIR/dash.conf" <<EOF
regtest=1
[regtest]
server=1
listen=1
port=$DASH_P2P_PORT
rpcport=$DASH_RPC_PORT
rpcuser=$DASH_RPC_USER
rpcpassword=$DASH_RPC_PASS
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
txindex=1
fallbackfee=0.0001
EOF
chmod 600 "$DASH_DIR/dash.conf"
# c2pool reads rpcuser/rpcpassword/rpcport/rpcconnect from a dash.conf-style file (rpc_conf.hpp:63-82)
printf 'rpcuser=%s\nrpcpassword=%s\nrpcport=%s\nrpcconnect=127.0.0.1\n' "$DASH_RPC_USER" "$DASH_RPC_PASS" "$DASH_RPC_PORT" > "$V37_AUTH"
chmod 600 "$V37_AUTH"
if ! cli getblockchaininfo >/dev/null 2>&1; then
  "$DASHD" -regtest -datadir="$DASH_DIR" -daemon
  for i in $(seq 1 60); do cli getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
fi
cli getblockchaininfo >/dev/null || { echo "dashd did not come up — check $DASH_DIR/debug.log (a stray fork-activation override asserts at chainparams.cpp:924/926)"; exit 1; }
[ "$(cli getblockchaininfo | jq -r .chain)" = regtest ] || { echo "REFUSING: chain is not regtest"; exit 1; }
[ "$(cli getblockhash 0)" = "000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e" ] || { echo "REFUSING: regtest genesis differs from the v23.1.7 pin (kDashRegtestGenesisHex)"; exit 1; }
echo "[A1] dashd $(cli getnetworkinfo | jq -r .subversion) regtest up: height=$(cli getblockcount) rpc=127.0.0.1:$DASH_RPC_PORT genesis=pinned"
stop_after A1

# ── A2. wallet + mature chain (200 > coinbase maturity 100; a fresh-timestamp block clears IBD) ──
cli createwallet v37 >/dev/null 2>&1 || cli loadwallet v37 >/dev/null 2>&1 || true
MINER_ADDR="$(cli -rpcwallet=v37 getnewaddress v37miner)"          # 'y…' regtest P2PKH (testnet address bytes)
if [ "$(cli getblockcount)" -lt 200 ]; then
  cli -rpcwallet=v37 generatetoaddress $((200 - $(cli getblockcount))) "$MINER_ADDR" >/dev/null
fi
[ "$(cli getblockchaininfo | jq .initialblockdownload)" = false ] || { echo "IBD still true after 200 blocks"; exit 1; }
echo "[A2] height=$(cli getblockcount) ibd=false miner=$MINER_ADDR"
# the template pays the miner the whole coinbase (no MNs registered → masternode[] empty, no payload)
cli getblocktemplate | jq '{height, coinbasevalue, mn:(.masternode|length), sb:(.superblock|length), payload:(.coinbase_payload!=null)}'
# expect: coinbasevalue ≈ 500e8 declining 1/14 per 150 blocks; mn=0; sb=0; payload=false (DIP3 inactive until 432)
stop_after A2

# ── A3. build the heavy leg on VM100 (+ keep the Threads-only smoke green) ────
# The target lives in src/c2pool/CMakeLists.txt next to c2pool-v37-btc (which STAYS Threads-only, HARD
# SAFETY 6): add_executable(c2pool-v37-btc-dash v37/main_v37_btc_dash.cpp) on the DASH library set of
# c2pool-dash / dash_hdr_backfill_window_kat. It is on build.yml's linux-leg --target list (like
# c2pool-dash, not on the ASan leg) so CI compiles + links it; it registers no CTest, so the drift-guard
# (tools/ci/check_test_target_allowlist.py) audits nothing for it — this runbook IS its runtime gate.
# BtcFinalizeDriver::reseed_found (the one consumer-tree seam, +20 lines) is on the same branch.
cd "$C2POOL_SRC" && git fetch -q origin && git checkout -q "$C2POOL_BRANCH" && git log -1 --format='[A3] c2pool %h %s'
cmake -S "$C2POOL_SRC" -B "$C2POOL_BUILD" -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null
cmake --build "$C2POOL_BUILD" --target c2pool-v37-btc c2pool-v37-btc-dash -j"$(nproc)"   # heavy link ≈ c2pool-dash size; watch RAM
"$C2POOL_BUILD/src/c2pool/c2pool-v37-btc" --selftest                                     # Threads-only smoke must stay green (exit 0)
python3 "$C2POOL_SRC/tools/ci/check_test_target_allowlist.py"                            # both build.yml lists carry the new target
[ -x "$V37_BIN" ] || { echo "no $V37_BIN"; exit 1; }
# CPU miner: cpuminer-multi (tpruvot) with X11. Build once if absent.
if ! command -v minerd >/dev/null; then
  sudo apt-get install -y -q build-essential automake autoconf pkg-config libcurl4-openssl-dev libjansson-dev libssl-dev libgmp-dev zlib1g-dev git >/dev/null
  git clone -q https://github.com/tpruvot/cpuminer-multi.git "$HOME/cpuminer-multi" 2>/dev/null || true
  (cd "$HOME/cpuminer-multi" && ./build.sh >/dev/null && sudo install -m 755 cpuminer /usr/local/bin/minerd)
fi
minerd --version 2>&1 | head -1
echo "[A3] built"
stop_after A3

# ── A4. start the live node ──────────────────────────────────────────────────
pkill -INT -f "c2pool-v37-btc-dash .*--network regtest" 2>/dev/null || true; sleep 1
mkdir -p "$V37_STORE"
nohup "$V37_BIN" --network regtest --daemon-rpc "127.0.0.1:$DASH_RPC_PORT" --coin-rpc-auth "$V37_AUTH" --settle-db "${V37_STORE_OVERRIDE:-$V37_STORE}" --d-conf "$V37_DCONF" --poll-ms 500 --stratum-bind "$V37_STRATUM" > "$V37_LOG" 2>&1 &
for i in $(seq 1 30); do grep -q "stratum listening" "$V37_LOG" && break; sleep 1; done
grep -E "dashd ready|boot:|stratum listening|REFUSED|refused" "$V37_LOG"
grep -q "stratum listening" "$V37_LOG" || { echo "node did not start (exit codes: 3 mainnet 4 creds 5 dashd/fence 6 store 7 start 8 bind)"; exit 1; }
echo "[A4] node up; store=$V37_STORE d_conf=$V37_DCONF"
stop_after A4

# ── A5. CPU-mine THROUGH STRATUM and PROVE the block is ours (the fact that unblocks everything) ──
# The "+$SHARE_DIFF" username suffix forces the share difficulty (stratum_server.cpp:643-656). Without it the
# initial vardiff 1.0 ≈ 2^32 X11 hashes per submission ≈ hours on one core, and the block-solving hash
# (regtest bits 0x207fffff → a block every few seconds of CPU) never reaches the pool as a share.
pkill -f "minerd -a x11" 2>/dev/null || true
nohup minerd -a x11 -o "stratum+tcp://$V37_STRATUM" -u "$MINER_ADDR+$SHARE_DIFF" -p x -t "$MINER_THREADS" > "$HOME/v37-regtest/minerd.log" 2>&1 &
wait_found 1
WON="$(last_found)"
grep -E '\[v37-dash\] (FOUND|.*NOT accepted|UNREGISTERED|height race|register .* failed)' "$V37_LOG" | tail -4
cli getblock "$WON" 2 | jq '{hash, height, confirmations, cb_out:(.tx[0].vout|length), cb_value:([.tx[0].vout[].value]|add)}'
# PASS (all three): (1) getblock $WON answers with .hash == $WON and confirmations >= 1 — the block dashd holds is
# the one OUR log registered, not dashd's own generatetoaddress tip; (2) the log line
# `[v37-dash] FOUND <hash> h=<H> accepted=1` has H == getblock .height (no UNREGISTERED; any `height race`
# line agrees with dashd — D8); (3) no `NOT accepted` line (a bad-cb-* reject = coinbase/reward mismatch, D4).
[ "$(cli getblock "$WON" | jq -r .hash)" = "$WON" ] || { echo "FAIL: dashd does not hold $WON"; exit 1; }
[ "$(cli getblock "$WON" | jq .confirmations)" -ge 1 ] || { echo "FAIL: $WON not on the active chain"; exit 1; }
[ "$(grep "FOUND $WON" "$V37_LOG" | tail -1 | sed -E 's/.* h=([0-9]+).*/\1/')" = "$(cli getblock "$WON" | jq .height)" ] || { echo "FAIL: registered height != dashd height (D8)"; exit 1; }
echo "[A5] ACCEPTED stratum-won block $WON @$(cli getblock "$WON" | jq .height)"
stop_after A5

# ── A6. burial → FINALIZE (F1): mine D_conf more blocks with dashd itself ─────
cli -rpcwallet=v37 generatetoaddress "$((V37_DCONF + 1))" "$MINER_ADDR" >/dev/null; sleep 3
grep "FINALIZE $WON" "$V37_LOG"           # exactly one; bin = h + d_conf (btc_finalize_driver.hpp:156-157)
[ "$(grep -c "FINALIZE $WON" "$V37_LOG")" -eq 1 ] || { echo "FAIL: expected exactly one FINALIZE $WON"; exit 1; }
echo "[A6] finalized $WON"
stop_after A6

# ── A7. the reorg drill (the controlled falsifier, btc_node_config.hpp:20-21) ─
wait_found 2                                                      # a second stratum-won block, NOT yet buried
WON2="$(last_found)"; H2="$(cli getblockheader "$WON2" | jq .height)"
cli invalidateblock "$WON2"                                       # tip lowers → D11 re-check fires on the next poll
sleep 2; grep -E "reorg signal|ORPHAN" "$V37_LOG" | tail -2        # expect: "reorg signal (tip lowered) ... ORPHAN 1"
cli -rpcwallet=v37 generatetoaddress "$((V37_DCONF + 2))" "$MINER_ADDR" >/dev/null; sleep 3   # longer competing branch
cli getblockheader "$WON2" | jq '{height, confirmations}'          # confirmations == -1
[ "$(grep -c "FINALIZE $WON2" "$V37_LOG" || true)" -eq 0 ] || { echo "FAIL: orphaned $WON2 was FINALIZED"; exit 1; }
# D8 check: any `height race` line printed while minerd ran through the invalidateblock must carry the
# registered h == getblockheader(bid).height — a mismatch here is the false-orphan bug this PR fixes.
grep "height race" "$V37_LOG" | tail -2 || true
echo "[A7] reorg drill done: $WON2 @$H2 orphaned, never finalized"
stop_after A7

# ── A8. W6 restart recovery WITH A PENDING BLOCK (★ fix 3 / D10) + F2 fail-closed (D12) ──
wait_found 3                                                      # a third block, NOT yet buried
WON3="$(last_found)"; H3="$(cli getblockheader "$WON3" | jq .height)"
pkill -INT -f "c2pool-v37-btc-dash .*--network regtest"; sleep 2
STOP="$(grep '\[v37-dash\] stop:' "$V37_LOG" | tail -1 | sed -E 's/.*(ledger_seq=[0-9]+ pending=[0-9]+ owed_digest=[0-9a-f]+).*/\1/')"
nohup "$V37_BIN" --network regtest --daemon-rpc "127.0.0.1:$DASH_RPC_PORT" --coin-rpc-auth "$V37_AUTH" --settle-db "${V37_STORE_OVERRIDE:-$V37_STORE}" --d-conf "$V37_DCONF" --poll-ms 500 --stratum-bind "$V37_STRATUM" >> "$V37_LOG" 2>&1 &
sleep 5
BOOT="$(grep '\[v37-dash\] boot:' "$V37_LOG" | tail -1 | sed -E 's/.*(ledger_seq=[0-9]+ pending=[0-9]+ owed_digest=[0-9a-f]+).*/\1/')"
[ "$STOP" = "$BOOT" ] && echo "RECOVERY OK: $BOOT" || { echo "FAIL: RECOVERY MISMATCH stop=[$STOP] boot=[$BOOT]"; exit 1; }
grep "re-drove pending FOUND $WON3" "$V37_LOG" || { echo "FAIL: $WON3 was not re-driven at boot (D10)"; exit 1; }
cli -rpcwallet=v37 generatetoaddress "$((V37_DCONF + 1))" "$MINER_ADDR" >/dev/null; sleep 3
grep "FINALIZE $WON3" "$V37_LOG" || { echo "FAIL: the block found BEFORE the restart did not finalize AFTER it"; exit 1; }
[ "$(grep "FINALIZE $WON3" "$V37_LOG" | tail -1 | sed -E 's/.*bin=([0-9]+).*/\1/')" -eq $((H3 + V37_DCONF)) ] || { echo "FAIL: bin != H_b + d_conf"; exit 1; }
# F2: a torn image must be refused with exit 6 (constructor throw mapped in main, D12), not a SIGABRT
rm -rf "$V37_STORE.torn"; cp -r "$V37_STORE" "$V37_STORE.torn"; truncate -s 7 "$V37_STORE.torn/settle.img"
set +e; V37_STORE_OVERRIDE="$V37_STORE.torn" v37 --stratum-bind 127.0.0.1:3033 >/dev/null 2>&1; RC=$?; set -e
[ "$RC" -eq 6 ] && echo "F2 OK (exit 6)" || { echo "FAIL: torn store exit=$RC (expect 6)"; exit 1; }
echo "[A8] restart re-drove pending $WON3 @$H3 and finalized it; F2 exit 6"
stop_after A8

# ── A9. oracle-unavailable (defer, never guess) + the chain fence across a dashd restart ──
cli stop; sleep 3                                                 # dashd down while minerd keeps submitting
sleep 40; grep -c "ORACLE UNAVAILABLE\|height-watch deferred\|register .* failed\|UNREGISTERED" "$V37_LOG" || true   # >0; NO ORPHAN/FINALIZE lines meanwhile
"$DASHD" -regtest -datadir="$DASH_DIR" -daemon; sleep 5
cli -rpcwallet=v37 generatetoaddress 1 "$MINER_ADDR" >/dev/null; sleep 3; tail -3 "$V37_LOG"   # resumes from the persisted cursor
# fence: a dashd on a DIFFERENT chain behind the SAME rpcport → the node must exit 9 (FATAL chain mismatch), never follow it.
# The devnet gets its OWN datadir (regtest=1 in a conf + -devnet is an invalid combination); it self-creates its
# devnet genesis at start and reports chain "devnet-v37fence" (GetDevNetName, src/util/system.cpp:1135-1139) —
# anything but "regtest" trips DashRpcCoinBackend::try_best_tip's per-poll fence.
cli stop; sleep 3
FENCE_DIR="$HOME/v37-regtest/dashd-fence"; mkdir -p "$FENCE_DIR"
printf 'devnet=v37fence\n[devnet]\nserver=1\nlisten=0\nrpcport=%s\nrpcuser=%s\nrpcpassword=%s\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\n' \
  "$DASH_RPC_PORT" "$DASH_RPC_USER" "$DASH_RPC_PASS" > "$FENCE_DIR/dash.conf"; chmod 600 "$FENCE_DIR/dash.conf"
"$DASHD" -datadir="$FENCE_DIR" -daemon; sleep 8
"$DASHCLI" -datadir="$FENCE_DIR" getblockchaininfo | jq -r .chain           # devnet-v37fence
grep -c "FATAL chain mismatch" "$V37_LOG"
pgrep -f "c2pool-v37-btc-dash" >/dev/null && { echo "FAIL: node still running after a chain switch"; exit 1; } || echo "node exited on the fence (correct)"
"$DASHCLI" -datadir="$FENCE_DIR" stop 2>/dev/null || true; sleep 3
"$DASHD" -regtest -datadir="$DASH_DIR" -daemon
pkill -f "minerd -a x11" 2>/dev/null || true
echo "[A9] done. Phase-A exit for THIS node: A5 accepted + A6 FINALIZE + A7 orphan (no false-orphan on the height race)"
echo "     + A8 stop/boot triple equal AND the pre-restart pending block finalized + F2 exit 6 + A9 defer/resume + fence."
echo "     Stated limits: owed_digest is the EMPTY digest throughout (no W5 outputs in the coinbase until S-1);"
echo "     post-SETTLED reorgs (D_conf=$V37_DCONF < maturity 100) are not driven (S-9)."
