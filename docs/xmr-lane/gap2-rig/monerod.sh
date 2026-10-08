#!/bin/bash
# regtest monerod I (1..3), P2P-joined in a line 1-2-3. rpc 449I1 p2p 449I0 zmq-pub 449I2 zmq-rpc 449I3
I=${1:-1}; R=~/gap2-rig
P2P=$((44900 + (I-1)*10)); RPC=$((P2P+1)); ZMQ=$((P2P+2)); ZRPC=$((P2P+3))
case $I in 1) EXTRA="--add-exclusive-node 127.0.0.1:44910";; 2) EXTRA="--add-exclusive-node 127.0.0.1:44900 --add-exclusive-node 127.0.0.1:44920";; 3) EXTRA="--add-exclusive-node 127.0.0.1:44910";; esac
exec ~/ic-verify/monero/monerod --regtest --fixed-difficulty ${DIFF:-50000} --no-igd --hide-my-port --non-interactive --allow-local-ip \
  --data-dir $R/mdata$I --log-level 0 --log-file $R/logs/monerod$I.log --max-log-file-size 50000000 \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port $RPC --p2p-bind-ip 127.0.0.1 --p2p-bind-port $P2P \
  --zmq-pub tcp://127.0.0.1:$ZMQ --zmq-rpc-bind-port $ZRPC --disable-rpc-ban --keep-fakechain $EXTRA --out-peers 8 --in-peers 8 \
  --detach --pidfile $R/monerod$I.pid
