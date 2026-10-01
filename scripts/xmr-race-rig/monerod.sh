#!/bin/bash
# monerod.sh I : regtest monerod I (1..3), fixed difficulty 1, wired ONLY to the rig's other monerods (a line
# 1 - 2 - 3), never to any public network. DATADIR/LOGD override the data/log dirs (gen_chain.sh).
I=${1:-1}; source "$(dirname "$0")/common.sh"
P2P=$(p2p_of $I); RPC=$((P2P+1)); ZMQ=$((P2P+2)); ZRPC=$((P2P+3))
DD=${DATADIR:-$RIG/mdata$I}; LOGD=${LOGD:-$RIG/logs}
case $I in 1) EXTRA="--add-exclusive-node 127.0.0.1:$(p2p_of 2)";; 2) EXTRA="--add-exclusive-node 127.0.0.1:$(p2p_of 1) --add-exclusive-node 127.0.0.1:$(p2p_of 3)";; 3) EXTRA="--add-exclusive-node 127.0.0.1:$(p2p_of 2)";; esac
exec nice -n 15 $MONEROD --regtest --fixed-difficulty 1 --no-igd --hide-my-port --non-interactive --allow-local-ip \
  --data-dir $DD --log-level ${MLOG:-0} --log-file $LOGD/monerod$I.log --max-log-file-size 200000000 \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port $RPC --p2p-bind-ip 127.0.0.1 --p2p-bind-port $P2P \
  --zmq-pub tcp://127.0.0.1:$ZMQ --zmq-rpc-bind-port $ZRPC --disable-rpc-ban --keep-fakechain --disable-dns-checkpoints \
  $EXTRA --out-peers 8 --in-peers 16 --detach --pidfile $RIG/monerod$I.pid
