#!/bin/bash
R=~/gap2-rig
exec ~/ic-verify/monero/monero-wallet-rpc --daemon-address 127.0.0.1:44901 --trusted-daemon \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port 44950 --disable-rpc-login --allow-mismatched-daemon-version \
  --wallet-dir $R/wallets --log-file $R/logs/wallet-rpc.log --log-level 0
