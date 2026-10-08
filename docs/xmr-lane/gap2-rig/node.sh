#!/bin/bash
# node.sh A|B|C [extra flags]. Node N follows daemon N; relay full mesh (B dials A; C dials A and B).
N=$1; shift
R=~/gap2-rig; source $R/common.sh
SPEND=a03ab8e2191c928bffa5c875c42834f793a356c12cd6d319310619055bcc7005
VIEW=099b5b60c9a497e55985b3843c3fda8da741814c39f0cda7fab35c0c4c1c023d
ADDR=$(cat $R/addr$N 2>/dev/null)
case $N in
  A) I=1; SP=5790; RL=45000; PEERS="";;
  B) I=2; SP=5791; RL=45001; PEERS="--relay-peer 127.0.0.1:45000";;
  C) I=3; SP=5792; RL=45002; PEERS="--relay-peer 127.0.0.1:45000 --relay-peer 127.0.0.1:45001";;
esac
RPC=$((44901 + (I-1)*10)); ZMQ=$((RPC+1))
exec stdbuf -oL -eL nice -n 15 "$BIN" --network regtest --rpc-host 127.0.0.1 --rpc-port $RPC --zmq-port $ZMQ \
  --stratum-bind-host 127.0.0.1 --stratum-port $SP --payout-address "$ADDR" \
  --payee-spend-hex "$SPEND" --payee-view-hex "$VIEW" \
  --coinbase v37 --residual-sink-spend-hex "$VIEW" --residual-sink-view-hex "$SPEND" \
  --share-diff ${SHAREDIFF:-2000} --d-conf 3 --poll-ms ${POLL:-400} --status-every ${STATUS:-5} --randomx \
  --data-dir $R/settle$N --lane-chain 7 \
  --relay-listen 127.0.0.1:$RL $PEERS ${RELAYX:-} "$@"
