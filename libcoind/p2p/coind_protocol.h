//
//  CoindProtocol->init(...<events>...)
//
#pragma once
#include <memory>

#include "coind_protocol_data.h"
#include "coind_messages.h"
#include <libp2p/protocol.h>
#include <libp2p/handler.h>
#include <libp2p/protocol_events.h>
#include <libdevcore/deferred.h>

//https://en.bitcoin.it/wiki/Protocol_documentation
class CoindProtocol : public Protocol<CoindProtocol>, public CoindProtocolData, ProtocolPinger
{
public:
    std::shared_ptr<c2pool::deferred::ReplyMatcher<uint256, coind::data::types::BlockType, uint256>> get_block;
    std::shared_ptr<c2pool::deferred::ReplyMatcher<uint256, coind::data::BlockHeaderType, uint256>> get_block_header;

    CoindProtocol(std::shared_ptr<boost::asio::io_context> _context, std::shared_ptr<Socket> _socket,
                  HandlerManagerPtr<CoindProtocol> _handler_manager) : Protocol<CoindProtocol>(std::move(_socket), std::move(handler_manager)),
                                                                       ProtocolPinger(_context, 30, std::bind(&CoindProtocol::out_time_ping, this),
																					  [](){return 20; /*TODO: return  random.expovariate(1/100)*/}, [&](){ send_ping(); })
    {
		send_version();
    }

private:

	void send_version()
	{
		address_type addr_to(1, std::get<0>(socket->get_addr()), std::get<1>(socket->get_addr()));

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
		write(msg);
	}

	void send_ping()
	{
		auto ping_msg = std::make_shared<coind::messages::message_ping>(1234);
		socket->write(ping_msg);
	}

    void out_time_ping()
    {
        //TODO: out of ping timer;
        socket->disconnect();
    }
};