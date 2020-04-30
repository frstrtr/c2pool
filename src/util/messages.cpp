#include "messages.h"
#include "protocol.h"
#include <sstream>
#include <string>
using namespace c2pool::messages;

namespace c2pool::messages
{
    message::message(std::string cmd)
    {
        command = cmd;
    }

    void message::unpack(std::string item)
    {
        std::stringstream ss;
        ss << item;
        _unpack(ss);
    }

    string message::pack()
    {
        //TODO:
    }

    message *fromStr(string str)
    {
        if (str == "version")
        {
            return new message_version();
        }

        return new message_error();
    }

    message_error::message_error(const std::string cmd) : message(cmd)
    {

    }

    message_version::message_version(int ver, int serv, c2pool::messages::address_type to, c2pool::messages::address_type from, long _nonce, std::string sub_ver, int _mode, long best_hash, std::string cmd) : message(cmd)
    {
        version = ver;
        services = serv;
        addr_to = to;
        addr_from = from;
        nonce = _nonce;
        sub_version = sub_ver;
        mode = _mode;
        best_share_hash = best_hash;
    }

} // namespace c2pool::messages
