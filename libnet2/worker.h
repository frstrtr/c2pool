#pragma once

#include <memory>
#include <string>

#include <sharechains/share_tracker.h>
#include <sharechains/share_types.h>
#include <networks/network.h>
#include <libdevcore/events.h>
#include <btclibs/uint256.h>
#include <web_interface/metrics.hpp>

using std::shared_ptr;

class CoindNodeData;
class PoolNodeData;

namespace coind
{
    class getwork_result;
}

class Work
{
public:
    // https://developer.bitcoin.org/reference/block_chain.html#block-headers
    uint64_t version;
    uint256 previous_block;
    int32_t bits;
    std::vector<unsigned char> coinbaseflags;
    int32_t height;
    int32_t timestamp;
    vector<coind::data::tx_type> transactions;
    vector<int32_t> transaction_fees;
    coind::data::MerkleLink merkle_link;
    uint64_t subsidy;
    int32_t last_update;

    static Work from_jsonrpc_data(const coind::getwork_result& data);

    bool operator==(const Work &value) const;

    bool operator!=(const Work &value) const;

    friend std::ostream &operator<<(std::ostream &stream, const Work& value)
    {
        stream << "(Work: ";
        stream << "version = " << value.version;
        stream << ", previous_block = " << value.previous_block;
        stream << ", bits = " << value.bits;
        stream << ", coinbaseflags = " << value.coinbaseflags;
        stream << ", height = " << value.height;
        stream << ", timestamp = " << value.timestamp;
        stream << ", transactions = " << value.transactions;
        stream << ", transaction_fees = " << value.transaction_fees;
        stream << ", merkle_link = " << value.merkle_link;
        stream << ", subsidy = " << value.subsidy;
        stream << ", last_update = " << value.last_update;
        stream << ")";

        return stream;
    }
};

struct NotifyData
{
    uint64_t version;
    uint256 previous_block;
    coind::data::MerkleLink merkle_link;
    std::vector<unsigned char> coinb1;
	std::vector<unsigned char> coinb2;
    int32_t timestamp;
    int32_t bits;
    uint256 share_target;

    friend std::ostream &operator<<(std::ostream& stream, NotifyData &data)
    {
        stream << "(NotifyData: ";
        stream << "version = " << data.version;
        stream << ", previous_block = " << data.previous_block;
        stream << ", merkle_link = " << data.merkle_link;
        stream << ", coinb1 = " << data.coinb1;
        stream << ", coinb2 = " << data.coinb2;
        stream << ", timestamp = " << data.timestamp;
        stream << ", bits = " << data.bits;
        stream << ", share_target = " << data.share_target;
        stream << ")";
        return stream;
    }
};

struct worker_get_work_result
{
    NotifyData ba;
    std::function<bool(coind::data::types::BlockHeaderType, std::string, IntType(64))> get_response;
};

struct local_rate_datum
{
    arith_uint288 work;
    bool dead;
    std::string user; // address
    uint256 share_target;
};

struct local_addr_rate_datum
{
    uint288 work;
    std::string address;
};

struct local_rates
{
    std::map<std::string, arith_uint288> miner_hash_rates;
    std::map<std::string, arith_uint288> miner_dead_hash_rates;
};

struct stale_counts
{
    std::tuple<int32_t, int32_t> orph_doa; //(orphans; doas)
    int32_t total;
    std::tuple<int32_t, int32_t> recorded_in_chain; // (orphans_recorded_in_chain, doas_recorded_in_chain)
};

struct user_details
{
    std::string user;
    std::string address;
    uint256 desired_share_target;
    uint256 desired_pseudoshare_target;
};

class DOAElement
{
public:
    int32_t my_count;
    int32_t my_doa_count;
    int32_t my_orphan_announce_count;
    int32_t my_dead_announce_count;
public:
    DOAElement() = default;

    DOAElement(int32_t count, int32_t doa_count, int32_t orphan_announce_count, int32_t dead_announce_count)
    {
        my_count = count;
        my_doa_count = doa_count;
        my_orphan_announce_count = orphan_announce_count;
        my_dead_announce_count = dead_announce_count;
    }

    DOAElement operator+(const DOAElement &el)
    {
        DOAElement res = *this;

        res.my_count += el.my_count;
        res.my_doa_count += el.my_doa_count;
        res.my_orphan_announce_count += el.my_orphan_announce_count;
        res.my_dead_announce_count += el.my_dead_announce_count;

        return res;
    }

    DOAElement operator-(const DOAElement &el)
    {
        DOAElement res = *this;

        res.my_count -= el.my_count;
        res.my_doa_count -= el.my_doa_count;
        res.my_orphan_announce_count -= el.my_orphan_announce_count;
        res.my_dead_announce_count -= el.my_dead_announce_count;

        return res;
    }

    DOAElement &operator+=(const DOAElement &el)
    {
        this->my_count += el.my_count;
        this->my_doa_count += el.my_doa_count;
        this->my_orphan_announce_count += el.my_orphan_announce_count;
        this->my_dead_announce_count += el.my_dead_announce_count;

        return *this;
    }

    DOAElement &operator-=(const DOAElement &el)
    {
        this->my_count -= el.my_count;
        this->my_doa_count -= el.my_doa_count;
        this->my_orphan_announce_count -= el.my_orphan_announce_count;
        this->my_dead_announce_count -= el.my_dead_announce_count;

        return *this;
    }
};

class WebWorker
{
protected:
    typedef MetricGetter shares_metric_type;
    typedef MetricGetter founded_blocks_metric_type;
    typedef MetricGetter local_rate_metric_type;
    typedef MetricGetter pool_rate_metric_type;
    typedef MetricValue payout_addr_metric_type;
    typedef MetricValue my_share_hashes_metric_type;
protected:
    shares_metric_type* shares_metric;
    founded_blocks_metric_type* founded_blocks_metric; //TODO: can be optimized; hash of the new block is immediately added to the metric.
    local_rate_metric_type* local_rate_metric;
    pool_rate_metric_type* pool_rate_metric;
    payout_addr_metric_type* payout_addr_metric;
    my_share_hashes_metric_type* my_share_hashes_metric;
protected:
    virtual void init_web_metrics() = 0;
};

class Worker : WebWorker
{
public:
	const int32_t COINBASE_NONCE_LENGTH = 8;
public:
    Worker(std::shared_ptr<c2pool::Network> net, std::shared_ptr<PoolNodeData> pool_node,
           std::shared_ptr<CoindNodeData> coind_node, std::shared_ptr<ShareTracker> tracker);

    worker_get_work_result
    get_work(std::string pubkey_hash, uint256 desired_share_target, uint256 desired_pseudoshare_target);

    local_rates get_local_rates();

    std::map<std::string, uint288> get_local_addr_rates();

    stale_counts get_stale_counts();

    user_details get_user_details(std::string username);

    user_details preprocess_request(std::string username);

private:
    void compute_work();

	arith_uint288 _estimate_local_hash_rate()
	{
		if (recent_shares_ts_work.size() == 50)
		{
			auto hash_rate = std::accumulate(recent_shares_ts_work.begin()+1, recent_shares_ts_work.end(),  arith_uint288(),
											 [&](const arith_uint288 &x, const std::tuple<int32_t, uint288> &y){
				return x + UintToArith288(std::get<1>(y));
			});
			hash_rate = hash_rate / (std::get<0>(recent_shares_ts_work.back()) - std::get<0>(recent_shares_ts_work.front()));
			if (!hash_rate.IsNull())
				return hash_rate;
		}
		return {};
	}
protected:
    void init_web_metrics() override;
public:
    std::shared_ptr<c2pool::Network> _net;
    std::shared_ptr<PoolNodeData> _pool_node;
    std::shared_ptr<CoindNodeData> _coind_node;
    std::shared_ptr<ShareTracker> _tracker;

    math::RateMonitor<local_rate_datum> local_rate_monitor;
    math::RateMonitor<local_addr_rate_datum> local_addr_rate_monitor;
public:
    Variable<Work> current_work;
    Event<> new_work;

    // for web static
    Event<> share_received;
    Event<> pseudoshare_received;

    std::set<uint256> my_share_hashes;
    std::vector<nlohmann::json> founded_blocks;
    std::set<uint256> my_doa_share_hashes;
    std::vector<std::tuple<int32_t, uint288>> recent_shares_ts_work;

    Variable<std::tuple<int32_t, int32_t, int32_t>> removed_unstales;
    Variable<int32_t> removed_doa_unstales;

    double donation_percentage; // TODO: init from args
    double worker_fee; //TODO: init from args
    uint160 my_pubkey_hash; //TODO: init from args
};