#pragma once

#include <memory>
#include <set>
#include <map>

#include <btclibs/uint256.h>

#include "pool_protocol_data.h"
#include "pool_messages.h"
#include <libp2p/protocol.h>
#include <libp2p/handler.h>
#include <libcoind/transaction.h>

#include <boost/asio/io_context.hpp>

class PoolProtocol : public Protocol<PoolProtocol>, public PoolProtocolData, ProtocolPinger
{
public:
	std::set<uint256> remote_tx_hashes;
	int32_t remote_remembered_txs_size = 0;

	std::map<uint256, coind::data::stream::TransactionType_stream> remembered_txs;
	int32_t remembered_txs_size;
	std::vector<std::map<uint256, coind::data::tx_type>> known_txs_cache;

public:
	PoolProtocol(std::shared_ptr<boost::asio::io_context> _context, std::shared_ptr<Socket> _socket,
                 HandlerManagerPtr<PoolProtocol> _handler_manager, std::shared_ptr<PoolProtocolData> _data) : Protocol<PoolProtocol>(_socket, _handler_manager), PoolProtocolData(*_data),
                                                                                                              ProtocolPinger(_context, 100, std::bind(&PoolProtocol::out_time_ping, this),
																															 [](){return 20; /*TODO: return  random.expovariate(1/100)*/}, [&](){ send_ping(); })
	{}

	void send_ping()
	{
		auto ping_msg = std::make_shared<pool::messages::message_ping>();
		socket->write(ping_msg);
	}

	void out_time_ping()
	{
		//TODO: out of ping timer;
		socket->disconnect();
	}

	void bad_peer_happened()
	{
		// TODO:
	}

};