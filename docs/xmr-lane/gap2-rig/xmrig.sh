#!/bin/bash
# xmrig.sh PORT ADDR WORKER THREADS
exec nice -n 12 ~/cc15-poc/xmrig/xmrig -o 127.0.0.1:$1 -u "$2.$3" -p x -a rx/0 --threads ${4:-3} --no-huge-pages --no-color --print-time 60 --retries 100 --retry-pause 2
