#pragma once

#include <univalue.h>
#include "shareTypes.h"
#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <coind/data.h>
#include <devcore/logger.h>
#include <libnet/nodeManager.h>
#include "prefsum_share.h"

#include <map>
#include <vector>
#include <string>
#include <memory>
#include <set>
#include <tuple>

#include <queue> //TODO: remove
using namespace std;

#include <boost/function.hpp>


namespace c2pool::shares
{
    class BaseShare;
} // namespace c2pool::shares

using namespace c2pool::shares;

#define LOOKBEHIND 200
//TODO: multi_index for more speed https://www.boost.org/doc/libs/1_76_0/libs/multi_index/doc/index.html
namespace c2pool::shares
{
    typedef boost::function<shared_ptr<BaseShare>(/*TODO: args*/)> get_share_method;

    struct GeneratedShare
    {
        ShareInfo share_info; //TODO: sharechain[v1]::ShareTypes.h::ShareInfoType
        //TODO: GENTX gentx;          //TODO: just tx
        vector<uint256> other_transaction_hashes;
        get_share_method get_share;
    };

    struct TrackerThinkResult
    {
        uint256 best_hash;
        std::vector<std::tuple<std::tuple<std::string, std::string>, uint256>> desired;
        std::vector<uint256> decorated_heads; //TODO: TYPE???
        std::set<std::tuple<std::string, std::string>> bad_peer_addresses;
    };

    class LookbehindDelta
    {
    private:
        queue<shared_ptr<BaseShare>> _queue;

        arith_uint256 work;
        arith_uint256 min_work;

    public:
        size_t size()
        {
            return _queue.size();
        }

        void push(shared_ptr<BaseShare> share);
    };

    class ShareTracker : public c2pool::libnet::INodeMember, public enable_shared_from_this<ShareTracker>
    {
    private:
        PrefsumShare shares;
        PrefsumVerifiedShare verified;

    public:
        ShareTracker(shared_ptr<c2pool::libnet::NodeManager> mng);

        shared_ptr<BaseShare> get(uint256 hash);
        void add(shared_ptr<BaseShare> share);

        bool attempt_verify(shared_ptr<BaseShare> share);

        TrackerThinkResult think();

        ///in p2pool - generate_transaction | segwit_data in other_data
        template <typename ShareType>
        GeneratedShare generate_share_transactions(ShareData share_data, uint256 block_target, int32_t desired_timestamp, uint256 desired_target, MerkleLink ref_merkle_link, vector<tuple<uint256, boost::optional<int32_t>>> desired_other_transaction_hashes_and_fees, map<uint256, UniValue> known_txs = map<uint256, UniValue>(), unsigned long long last_txout_nonce = 0, long long base_subsidy = 0, UniValue other_data = UniValue());

        
    };
} // namespace c2pool::shares
