#include "messages.h"
#include "protocol.h"
using namespace c2pool::messages;

c2pool::messages::message *c2pool::messages::fromStr(string str) {
    if (str == "version") {
        return new message_version();
    }

    return new message_error();
}

message_version::message_version(int ver, int serv, c2pool::messages::address_type to, c2pool::messages::address_type from, long _nonce, string sub_ver, int _mode, long best_hash, string cmd) :message(cmd){
    version = ver;
    services = serv;
    addr_to = to;
    addr_from = from;
    nonce = _nonce;
    sub_version = sub_ver;
    mode = _mode;
    best_share_hash = best_hash;
}
