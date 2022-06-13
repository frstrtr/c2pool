#pragma once

#include <memory>
#include <set>
#include <map>

#include <btclibs/uint256.h>

#include "p2p_protocol_data.h"
#include <libp2p/protocol.h>
#include <libp2p/handler.h>
#include <libcoind/transaction.h>

#include <boost/asio/io_context.hpp>

class P2PProtocol : public Protocol<P2PProtocol>, public P2PProtocolData,  ProtocolPinger
{
public:
	std::set<uint256> remote_tx_hashes;
	int32_t remote_remembered_txs_size = 0;

	std::map<uint256, coind::data::stream::TransactionType_stream> remembered_txs;
	int32_t remembered_txs_size;
	std::vector<std::map<uint256, coind::data::tx_type>> known_txs_cache;

public:
	P2PProtocol(std::shared_ptr<boost::asio::io_context> _context, std::shared_ptr<Socket> _socket,
				HandlerManagerPtr<P2PProtocol> _handler_manager, std::shared_ptr<P2PProtocolData> _data) : Protocol<P2PProtocol>(_socket, _handler_manager), P2PProtocolData(*_data),
													  ProtocolPinger(_context, 100, std::bind(&P2PProtocol::out_time_ping, this))
	{}

	void out_time_ping()
	{
		//TODO: out of ping timer;
		socket->disconnect();
	}

};