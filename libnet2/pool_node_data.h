#pragma once

#include <memory>
#include <set>
#include <map>
#include <utility>
#include <vector>
#include <tuple>
#include <functional>

#include "pool_protocol.h"
#include <networks/network.h>
#include <libdevcore/config.h>
#include <libdevcore/addr_store.h>
#include <sharechains/share.h>
#include <sharechains/share_tracker.h>
#include <web_interface/metrics.hpp>

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = io::ip;

class CoindNodeData;

class WebPoolNode
{
protected:
//    typedef MetricSum<shares_stale_count, 120> stale_counts_metric_type;
//    typedef MetricRateTime<shares_stale_count, 120> stale_rate_metric_type;
    typedef MetricGetter peers_metric_type;
    typedef MetricGetter current_payouts_metric_type;
//    typedef MetricValue attempts_to_share_metric_type;
protected:
    // Metrics
    peers_metric_type* peers_metric{};
    current_payouts_metric_type* current_payouts_metric{};
//    attempts_to_share* attempts_to_share_metric = nullptr;
//    stale_counts_metric_type* stale_counts_metric{};
//    stale_rate_metric_type* stale_rate_metric{};

public:
    virtual void init_web_metrics() = 0;
};

//used in handle_shares
struct HandleSharesData
{
    std::vector<ShareType> items;
    std::map<uint256, std::vector<coind::data::tx_type>> txs;

    void add(const ShareType& _share, std::vector<coind::data::tx_type> _txs)
    {
        items.push_back(_share);
        txs[_share->hash] = std::move(_txs);
    }
};

class PoolNodeData
{
public:
	std::shared_ptr<c2pool::dev::coind_config> config;
	std::shared_ptr<io::io_context> context;
	std::shared_ptr<c2pool::Network> net;
	std::shared_ptr<c2pool::dev::AddrStore> addr_store;
	std::shared_ptr<ShareTracker> tracker;
	std::shared_ptr<CoindNodeData> coind_node;
	HandlerManagerPtr<PoolProtocol> handler_manager;

    //From CoindNode
	VariableDict<uint256, coind::data::tx_type> known_txs;
	VariableDict<uint256, coind::data::tx_type> mining_txs;
	Variable<uint256> best_share;

	std::map<uint64_t, std::shared_ptr<PoolProtocol>> peers;
	std::set<uint256> shared_share_hashes;
public:
	PoolNodeData(std::shared_ptr<io::io_context> _context) : context(std::move(_context))
	{
		handler_manager = std::make_shared<HandlerManager<PoolProtocol>>();

//        known_txs = VariableDict<uint256, coind::data::tx_type>(true);
//        mining_txs = VariableDict<uint256, coind::data::tx_type>(true);
	}

	auto set_net(std::shared_ptr<c2pool::Network> _net)
	{
		net = std::move(_net);
		return this;
	}

	auto set_config(std::shared_ptr<c2pool::dev::coind_config> _config)
	{
		config = std::move(_config);
		return this;
	}

	auto set_addr_store(std::shared_ptr<c2pool::dev::AddrStore> _addr_store)
	{
		addr_store = std::move(_addr_store);
		return this;
	}

	auto set_tracker(std::shared_ptr<ShareTracker> _tracker)
	{
		tracker = std::move(_tracker);
		return this;
	}

    PoolNodeData* set_coind_node(std::shared_ptr<CoindNodeData> _coind_node);

public:
	void got_addr(std::tuple<std::string, std::string> _addr, uint64_t services, int64_t timestamp)
	{
		if (addr_store->Check(_addr)) {
			auto old = addr_store->Get(_addr);
			c2pool::dev::AddrValue new_addr(services, old.first_seen, std::max(old.last_seen, timestamp));
			addr_store->Add(_addr, new_addr);
		} else {
			if (addr_store->len() < 10000) {
				c2pool::dev::AddrValue new_addr(services, timestamp, timestamp);
				addr_store->Add(_addr, new_addr);
			}
		}
	}

	std::vector<ShareType> handle_get_shares(std::vector<uint256> hashes, uint64_t parents, std::vector<uint256> stops, addr_type peer_addr);
	void handle_shares(HandleSharesData shares, std::tuple<std::string, std::string> addr);
	void handle_share_hashes(std::vector<uint256> hashes, std::shared_ptr<PoolProtocolData> peer, std::tuple<std::string, std::string> addr);
	void handle_bestblock(coind::data::stream::BlockHeaderType_stream header);
	void broadcast_share(uint256 share_hash);

    virtual bool is_connected()
    {
        return !peers.empty();
    }

protected:
	void send_shares(std::shared_ptr<PoolProtocol> peer, std::vector<uint256> share_hashes, std::vector<uint256> include_txs_with = {});
};