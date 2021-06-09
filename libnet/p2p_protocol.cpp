#include "p2p_protocol.h"
#include "p2p_socket.h"
#include "p2p_node.h"
#include "messages.h"
using namespace c2pool::libnet::messages;

#include "converter.h"
#include <devcore/logger.h>

#include <univalue.h>

#include <memory>
using std::shared_ptr, std::weak_ptr, std::make_shared;

namespace c2pool::libnet::p2p
{
    Protocol::Protocol(shared_ptr<c2pool::libnet::p2p::P2PSocket> _sct, shared_ptr<c2pool::Network> _network) : version(3301), _net(_network) //TODO: init version
    {
        LOG_TRACE << "Base protocol: "
                  << "start constuctor";
        _socket = _sct;
    }

    shared_ptr<P2PNode> Protocol::node(){
        return _socket->get_node();
    }

    void initialize_network_protocol::handle(shared_ptr<raw_message> RawMSG_version)
    {
        LOG_DEBUG << "called handle in initialize_network_protocol.";
        RawMSG_version->deserialize();

        UniValue json_value = RawMSG_version->value;
        LOG_TRACE << "initialize_network_protocol name_type: " << RawMSG_version->name_type;
        if (RawMSG_version->name_type == commands::cmd_version)
        {
            if (check_c2pool(json_value))
            {
                //c2pool
                //_socket->get_protocol_type<>
            }
            else
            {
                LOG_TRACE << "Set p2pool protocol in initialize_network_protocol";
                //p2pool
                _socket->set_protocol_type_and_version<p2pool_protocol>(_handle, RawMSG_version);
            }
        }
        else
        {
            LOG_WARNING << "initialize_network_protocol get not message_version";
        }
    }
}