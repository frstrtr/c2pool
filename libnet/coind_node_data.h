#pragma once

#include <memory>

#include <libp2p/workflow_node.h>
#include <libcoind/height_tracker.h>
#include <libcoind/jsonrpc/coindrpc.h>
#include <sharechains/share_tracker.h>
#include <networks/network.h>
#include "pool_node_data.h"
#include "coind_protocol.h"

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = io::ip;

class CoindNodeData : public WorkflowNode
{
public:
	io::io_context* context;
	coind::ParentNetwork* parent_net;
	ShareTracker* tracker;
	CoindRPC* coind;
	PoolNodeData* pool_node;

    std::function<void(coind::data::types::BlockType)> send_block; //send block in p2p
	HandlerManagerPtr handler_manager;
public:
    uint64_t cur_share_version = 0;
	coind::TXIDCache txidcache;
	Event<> stop_event;

	VariableDict<uint256, coind::data::tx_type> known_txs;
	VariableDict<uint256, coind::data::tx_type> mining_txs;
	VariableDict<uint256, coind::data::tx_type> mining2_txs;
	Variable<uint256> best_share;
	Variable<std::vector<std::tuple<NetAddress, uint256>>> desired;

	Event<uint256> new_block;                           //block_hash
	Event<coind::data::tx_type> new_tx;                 //bitcoin_data.tx_type
	Event<std::vector<coind::data::types::BlockHeaderType>> new_headers; //bitcoin_data.block_header_type

	Variable<coind::getwork_result> coind_work;
	Variable<coind::data::BlockHeaderType> best_block_header;
	coind::HeightTracker get_height_rel_highest; // wanna for init get_block_height func!
public:
	CoindNodeData(io::io_context* context_) : context(context_)
	{
		handler_manager = std::make_shared<HandlerManager>();

        stop_event = make_event();

        known_txs = make_vardict<uint256, coind::data::tx_type>({});
        mining_txs = make_vardict<uint256, coind::data::tx_type>({});
        mining2_txs = make_vardict<uint256, coind::data::tx_type>({});
        best_share = make_variable<uint256>(uint256::ZERO);
        desired = make_variable<std::vector<std::tuple<NetAddress, uint256>>>();

        new_block = make_event<uint256>();
        new_tx = make_event<coind::data::tx_type>();
        new_headers = make_event<std::vector<coind::data::types::BlockHeaderType>>();

        coind_work = make_variable<coind::getwork_result>();
        best_block_header = make_variable<coind::data::BlockHeaderType>();
	}

	auto set_parent_net(coind::ParentNetwork* _net)
	{
		parent_net = _net;
		return this;
	}

	auto set_coind(CoindRPC* _coind)
	{
		coind = _coind;
        get_height_rel_highest.set_jsonrpc_coind(coind);
		return this;
	}

	auto set_tracker(ShareTracker* _tracker)
	{
		tracker = _tracker;
		return this;
	}

	auto set_pool_node(PoolNodeData* _pool_node)
	{
		pool_node = _pool_node;
		return this;
	}

    auto set_send_block(auto _function)
    {
        send_block = std::move(_function);
        return this;
    }
public:
	void set_best_share();
	void clean_tracker();

	void handle_header(coind::data::BlockHeaderType new_header);
    void submit_block(coind::data::types::BlockType &block, bool ignore_failure);
};