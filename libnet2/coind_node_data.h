#pragma once

#include <memory>

#include "pool_node_data.h"
#include <libcoind/height_tracker.h>
#include <libcoind/p2p/coind_protocol.h>
#include <libcoind/jsonrpc/jsonrpc_coind.h>
#include <sharechains/tracker.h>
#include <networks/network.h>
#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = io::ip;

class CoindNodeData
{
public:
	std::shared_ptr<io::io_context> context;
	std::shared_ptr<coind::ParentNetwork> parent_net;
	std::shared_ptr<ShareTracker> tracker;
	std::shared_ptr<coind::JSONRPC_Coind> coind;
	std::shared_ptr<PoolNodeData> pool_node;

	HandlerManagerPtr<CoindProtocol> handler_manager;
public:
	coind::TXIDCache txidcache;
	Event<> stop;

	VariableDict<uint256, coind::data::tx_type> known_txs;
	VariableDict<uint256, coind::data::tx_type> mining_txs;
	VariableDict<uint256, coind::data::tx_type> mining2_txs;
	Variable<uint256> best_share;
	Variable<std::vector<std::tuple<std::tuple<std::string, std::string>, uint256>>> desired;

	Event<uint256> new_block;                           //block_hash
	Event<coind::data::tx_type> new_tx;                 //bitcoin_data.tx_type
	Event<std::vector<coind::data::types::BlockHeaderType>> new_headers; //bitcoin_data.block_header_type

	Variable<coind::getwork_result> coind_work;
	Variable<coind::data::BlockHeaderType> best_block_header;
	coind::HeightTracker get_height_rel_highest;

public:
	CoindNodeData(std::shared_ptr<io::io_context> _context) : context(std::move(_context)), get_height_rel_highest(coind, [&](){return coind_work.value().previous_block; })
	{
		handler_manager = std::make_shared<HandlerManager<CoindProtocol>>();
	}

	auto set_parent_net(std::shared_ptr<coind::ParentNetwork> _net)
	{
		parent_net = std::move(_net);
		return this;
	}

	auto set_coind(std::shared_ptr<coind::JSONRPC_Coind> _coind)
	{
		coind = std::move(_coind);
		return this;
	}

	auto set_tracker(std::shared_ptr<ShareTracker> _tracker)
	{
		tracker = std::move(_tracker);
		return this;
	}

	auto set_pool_node(std::shared_ptr<PoolNodeData> _pool_node)
	{
		pool_node = std::move(_pool_node);
		return this;
	}
public:
	void set_best_share();
	void clean_tracker();

	void handle_header(coind::data::BlockHeaderType new_header);
};