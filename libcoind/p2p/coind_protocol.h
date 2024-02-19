#pragma once
#include <memory>

#include "coind_socket.h"
#include "coind_protocol_data.h"
#include "coind_messages.h"
#include <libp2p/protocol.h>
#include <libp2p/handler.h>
#include <libp2p/protocol_components.h>
#include <libdevcore/deferred.h>
#include <libdevcore/exceptions.h>

typedef BaseProtocol<BaseCoindSocket, Pinger> BaseCoindProtocol;

//https://en.bitcoin.it/wiki/Protocol_documentation
class CoindProtocol : public BaseCoindProtocol, public CoindProtocolData
{
public:
    CoindProtocol(boost::asio::io_context* context_, BaseCoindSocket* socket_, HandlerManagerPtr handler_manager_) 
		: BaseCoindProtocol(socket_, handler_manager_, context_, 20, 30)
    {
		send_version();
    }

	void write(std::shared_ptr<Message> msg) override
	{
		socket->write(msg);
	}

private:

	void send_version()
	{
        auto addr = socket->get_addr();
		address_type addr_to(1, addr.ip, addr.port);

		//TODO: get my global ip
		address_type addr_from(1, "192.168.0.1", 12024);

		auto msg = std::make_shared<coind::messages::message_version>(
				70017,
				1,
				c2pool::dev::timestamp(),
				addr_to,
				addr_from,
				c2pool::random::randomNonce(),
				"C2Pool", //TODO: generate sub_version
				0
		);
        LOG_TRACE << "CoindProtocol message_version:";
        LOG_TRACE << msg->timestamp.get() << " " << msg->version.get() << " " << msg->nonce.get() << " " << msg->services.get() << " " << msg->start_height.get();
        LOG_TRACE << "addrFrom: " << msg->addr_from.get().address << " " << msg->addr_from.get().port << " " << msg->addr_from.get().services;
        LOG_TRACE << "addrTo: " << msg->addr_to.get().address << " " << msg->addr_to.get().port << " " << msg->addr_to.get().services;
		write(msg);
	}

	void timeout() override 
	{
		throw make_except<coind_exception, NodeExcept>("out time ping");
	}

    void send_ping() override
	{
		auto ping_msg = std::make_shared<coind::messages::message_ping>(1234);
		socket->write(ping_msg);
	}
};