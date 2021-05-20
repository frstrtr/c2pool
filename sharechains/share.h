#pragma once

#include <coind/data.h>
#include <btclibs/uint256.h>
#include <dbshell/dbObject.h>
#include <networks/network.h>
#include <devcore/addrStore.h>
using dbshell::DBObject;

#include <string>
#include <memory>
#include <tuple>
#include <vector>
#include <map>

using std::shared_ptr, std::string;
using std::vector, std::tuple, std::map;

#include "shareTypes.h"

namespace c2pool::shares::tracker{
    class ShareTracker;
}

#include "prefsum_share.h"

namespace c2pool::shares::share
{
    class BaseShare : public DBObject
    {
        const int SHARE_VERSION; //init in constructor

    public:
        SmallBlockHeaderType min_header;

        MerkleLink ref_merkle_link; //FOR?
        unsigned long long last_txout_nonce;
        HashLinkType hash_link;
        MerkleLink merkle_link;

    public:
        //============share_data=============
        uint256 previous_hash;
        string coinbase;
        unsigned int nonce;
        unsigned long long subsidy;
        unsigned short donation;
        StaleInfo stale_info;
        unsigned long long desired_version;
        //===================================

        vector<uint256> new_transaction_hashes;
        vector<tuple<unsigned long long, unsigned long long>> transaction_hash_refs; //TODO: check+test; # pairs of share_count, tx_count
        uint256 far_share_hash;
        uint256 max_target; //from max_bits;
        uint256 target;     //from bits;
        unsigned int timestamp;
        unsigned int absheight;
        uint128 abswork;
        //TODO: self.new_script = bitcoin_data.pubkey_hash_to_script2(self.share_data['pubkey_hash']) //FROM pubkey_hash;
        //TODO: gentx_hash
        //TODO: header
        uint256 pow_hash;
        uint256 hash; //=header_hash
        //TODO: remove? unsigned int time_seen;

        shared_ptr<c2pool::Network> net;
        addr peer_addr;
        UniValue contents;
    public:
        BaseShare(int VERSION, shared_ptr<Network> _net, addr _peer_addr, UniValue _contents);

        virtual string SerializeJSON() override;
        virtual void DeserializeJSON(std::string json) override;

        operator c2pool::shares::tracker::PrefixSumShareElement() const
        {
            c2pool::shares::tracker::PrefixSumShareElement prefsum_share = {hash, UintToArith256(coind::data::target_to_average_attempts(target)), UintToArith256(coind::data::target_to_average_attempts(max_target)), 1};
            return prefsum_share;
        }

        bool is_segwit_activated() const { return SHARE_VERSION >= net->SEGWIT_ACTIVATION_VERSION; }

        virtual void contents_load(UniValue contents);

        virtual void check(shared_ptr<c2pool::shares::tracker::ShareTracker> tracker /*, TODO: other_txs = None???*/);
    };

    class Share : public BaseShare
    {
    public:
        Share(shared_ptr<Network> _net, addr _peer_addr, UniValue _contents) : BaseShare(17, _net, _peer_addr, _contents) {}

        virtual void contents_load(UniValue contents) override;
    };


    class PreSegwitShare : public BaseShare
    {
    public:
        SegwitData segwit_data;

    public:
        PreSegwitShare(shared_ptr<Network> _net, addr _peer_addr, UniValue _contents) : BaseShare(32, _net, _peer_addr, _contents) {}

        virtual void contents_load(UniValue contents) override;
    };
} // namespace c2pool::shares::share