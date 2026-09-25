# xmr-race-rig helpers (sourced). REGTEST ONLY: three monerods at --fixed-difficulty 1 wired only to each
# other (exclusive nodes on 127.0.0.1), never to any public network.
# Layout (override with env): RIG = runtime dir (data dirs, logs, runs-<label>/), MDIR = regtest monerod dir.
# Ports: monerod i p2p MON_BASE+(i-1)*10, rpc +1, zmq +2, zmq-rpc +3; rpc proxies PRX_BASE+i; stratum
# STR_BASE+i; receipt relay REL_BASE+i; native levin dials from source IP 127.0.0.(SRC_IP_BASE+i).
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RIG=${RIG:-$HOME/v37/v37-racediv-rig}
MDIR=${MDIR:-$HOME/v37/ic-verify/monero}
MONEROD=$MDIR/monerod
MON_BASE=${MON_BASE:-62000}; PRX_BASE=${PRX_BASE:-62050}; STR_BASE=${STR_BASE:-7230}; REL_BASE=${REL_BASE:-62100}
SRC_IP_BASE=${SRC_IP_BASE:-120}
p2p_of(){ echo $((MON_BASE + ($1-1)*10)); }
rpc_of(){ echo $((MON_BASE + 1 + ($1-1)*10)); }
prx_of(){ echo $((PRX_BASE + $1)); }
str_of(){ echo $((STR_BASE + $1)); }
rel_of(){ echo $((REL_BASE + $1)); }
mrpc(){ curl -s -m 120 127.0.0.1:$(rpc_of $1)/json_rpc -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"$2\",\"params\":$3}"; }
H()   { curl -s -m 5 127.0.0.1:$(rpc_of ${1:-1})/get_info -d "{}" -H "Content-Type: application/json" | grep -oE "\"height\": *[0-9]+" | grep -oE "[0-9]+"; }
say(){ echo "$(date -Is) $* | h=$(H 1)/$(H 2)/$(H 3) avail=$(free -g | awk "/Mem:/{print \$7}")G" | tee -a $RIG/logs/phase.log; }
pidof_(){ grep "^$1=" $RIG/logs/pids 2>/dev/null | tail -1 | cut -d= -f2; }
found_total(){ cat $RIG/logs/node[ABC].log 2>/dev/null | grep -c "\[submit\] FOUND"; }
# regtest-only payee keys + addresses (test vectors, no value)
SPEND=a03ab8e2191c928bffa5c875c42834f793a356c12cd6d319310619055bcc7005
VIEW=099b5b60c9a497e55985b3843c3fda8da741814c39f0cda7fab35c0c4c1c023d
ADDR_A=45Th3zoFRcFHqFUHB7g6VV7SwSrKacDUkA9yR95GSXCX7ZUAGBJh9FABDFpoyvffdQS2vUNSu21MoHoar58H5TA5CRSMGWK
ADDR_B=4Ajge92EmrC6dZeVa86XGnGvMQTBwm7eRg1EqhSD9FFchqocqy4tP7wT8fEjBw7HAyE3k3PpP5AKbEPiGUH78Y1w6Mo5cTk
ADDR_C=47d3CXw5Xpajbco4kYv5wZgXTJB4nuffDJ9Y5dfHh4Nbi24J9PmTQAHYguPEck3uKAM9BzsJw34TK3geRPhxeyt5HH91vMf
WADDR=441igT1yU6dRW228y46F96QQrzCXhXqaJFoE4xyEXisZEwh4nwphJWNACKJ3BSMGefMf5JFX5KXeb6MRqzUZ84YFD9MggpJ
addr_of(){ case $1 in A) echo $ADDR_A;; B) echo $ADDR_B;; C) echo $ADDR_C;; esac; }
MYPORTS(){ for i in 1 2 3; do echo -n "$(p2p_of $i) $(rpc_of $i) $(prx_of $i) $(str_of $i) $(rel_of $i) "; done; }
ports_busy(){ for p in $(MYPORTS); do ss -ltn | grep -q ":$p " && { echo "port $p busy"; return 0; }; done; return 1; }
