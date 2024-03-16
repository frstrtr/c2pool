#pragma once

#include "coind_socket.h"
#include "coind_protocol.h"
#include "coind_node_data.h"

#include <libp2p/network_tree_node.h>
#include <libp2p/node.h>

class CoindNodeClient : public Client<BaseCoindSocket>
{
protected:
    CoindNodeData* node_data;
    CoindProtocol* protocol;

public:
    CoindNodeClient(CoindNodeData* node_data_) 
        : Client<BaseCoindSocket>(), node_data(node_data_)
    {
    }

	void connect(const NetAddress& addr)
	{
		interface->try_connect(addr);
	}

    void start() override
    {

    }

    void stop() override
    {
        interface->stop();

        if (protocol)
        {
            protocol->close();
            delete protocol;
            protocol = nullptr;
        }
    }

    void disconnect(const NetAddress& addr)
    {
        if (protocol)
        {
            protocol->close();
            delete protocol;
            protocol = nullptr;
        }
    }

protected:
    void error(const libp2p::error& err) override
    {
        LOG_ERROR << "Coind[client]: [" << err.errc << "/" << err.addr.to_string() << "]" << err.reason;
        throw libp2p::node_exception(err.reason, node_data);
    }

    void socket_handle(std::shared_ptr<BaseCoindSocket> socket) override
    {
        LOG_DEBUG_COIND << "CoindNode has been connected to: " << socket;

		protocol 
            = new CoindProtocol(
                node_data->context, 
                socket, 
                node_data->handler_manager,
                [&](const libp2p::error& err)
                {
                    error(err);
                }
            );
        socket->event_disconnect->subscribe([]()
        {
            LOG_INFO << "COIND DISCONNECTED";
        });

        // start accept messages
        socket->read();
        node_data->connected();
    }
};