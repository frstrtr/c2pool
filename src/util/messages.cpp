#include "messages.h"
#include "protocol.h"

c2pool::messages::message *c2pool::messages::fromStr(string str) {
    if (str == "version") {
        return new message_version();
    }

    return new message_error();
}
