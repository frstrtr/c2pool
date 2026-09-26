#!/bin/bash
# node.sh A|B|C : one c2pool-v37-xmr node (BIN_<N> or BIN): native template, p2p-first, relay ON, settlement
# ON, D_conf DCONF (10). A is the relay hub; B dials A; C dials A and B.
N=$1; shift; source "$(dirname "$0")/common.sh"
case $N in
  A) I=1; PEERS="";                                                   B_=${BIN_A:-$BIN};;
  B) I=2; PEERS="--relay-peer 127.0.0.1:$(rel_of 1)";                  B_=${BIN_B:-$BIN};;
  C) I=3; PEERS="--relay-peer 127.0.0.1:$(rel_of 1) --relay-peer 127.0.0.1:$(rel_of 2)"; B_=${BIN_C:-$BIN};;
esac
exec stdbuf -oL -eL nice -n 15 "$B_" --network regtest --rpc-host 127.0.0.1 --rpc-port $(prx_of $I) --zmq-port $(( $(p2p_of $I) + 2 )) \
  --coinbase v37 --xmr-template-source native --arm-order p2p-first --native-force-synced \
  --native-connect 127.0.0.1:$(p2p_of 1) --native-connect 127.0.0.1:$(p2p_of 2) --native-connect 127.0.0.1:$(p2p_of 3) \
  --native-p2p-bind 127.0.0.$((SRC_IP_BASE + I)) --native-ready-timeout 900 \
  --stratum-bind-host 127.0.0.1 --stratum-port $(str_of $I) --payout-address "$(addr_of $N)" \
  --payee-spend-hex "$SPEND" --payee-view-hex "$VIEW" --residual-sink-spend-hex "$VIEW" --residual-sink-view-hex "$SPEND" \
  --share-diff ${SHAREDIFF:-8} --d-conf ${DCONF:-10} --poll-ms ${POLL:-400} --status-every ${STATUS:-5} --randomx \
  --data-dir $RIG/settle$N --lane-chain 7 --relay-rx-budget ${RXB:-200,800,600,4000} \
  --relay-listen 127.0.0.1:$(rel_of $I) $PEERS "$@"
