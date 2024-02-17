#pragma once

#include <memory>
#include <set>
#include <map>

#include <btclibs/uint256.h>

#include "pool_protocol_data.h"
#include "pool_messages.h"
#include "pool_socket.h"
#include <libdevcore/exceptions.h>
#include <libp2p/protocol.h>
#include <libp2p/protocol_events.h>
#include <libp2p/handler.h>
#include <libcoind/transaction.h>

#include <boost/asio/io_context.hpp>

class PoolProtocol : public BaseProtocol<PoolSocket, Pinger>, public PoolProtocolData
{
public:
//	std::set<uint256> remote_tx_hashes;
//	int32_t remote_remembered_txs_size = 0;
//
//	std::map<uint256, coind::data::stream::TransactionType_stream> remembered_txs;
//	int32_t remembered_txs_size;
//	const int32_t max_remembered_txs_size = 25000000;
//	std::vector<std::map<uint256, coind::data::tx_type>> known_txs_cache;

public:
	PoolProtocol(boost::asio::io_context* context_, Socket* socket_, HandlerManagerPtr handler_manager_, PoolProtocolData* data_) 
		: BaseProtocol<PoolSocket, Pinger>(socket_, handler_manager_, 20, 100), PoolProtocolData(*data_)
	{
	}

	void timeout() override 
	{
		//TODO: out of ping timer;
        throw make_except<pool_exception, NetExcept>("out time ping", get_addr());
	}

    void send_ping() override
	{
		auto ping_msg = std::make_shared<pool::messages::message_ping>();
		socket->write(ping_msg);
	}
};