#pragma once

#include <boost/format.hpp>
#include <coind/data.h>
#include <btclibs/uint256.h>
#include <devcore/dbObject.h>
#include <networks/network.h>
#include <devcore/addrStore.h>
#include <devcore/types.h>
#include <devcore/stream.h>
#include <devcore/stream_types.h>
using dbshell::DBObject;

#include <string>
#include <memory>
#include <tuple>
#include <vector>
#include <map>

using std::shared_ptr, std::string, std::make_shared;
using std::vector, std::tuple, std::map;

#include "shareTypes.h"
#include "data.h"

namespace c2pool::shares
{
    class ShareTracker;
}

namespace c2pool::shares
{
    class BaseShare : public DBObject
    {
        const int SHARE_VERSION; //init in constructor
    public:
        static const int32_t gentx_size = 50000;

    public:
        SmallBlockHeaderType min_header;

        ShareInfo share_info;

        MerkleLink ref_merkle_link; //FOR?
        unsigned long long last_txout_nonce;
        HashLinkType hash_link;
        MerkleLink merkle_link;

    public:
        //============share_data=============
        uint256 previous_hash;
        string coinbase;
        unsigned int nonce;
        uint160 pubkey_hash;
        unsigned long long subsidy;
        unsigned short donation;
        StaleInfo stale_info;
        unsigned long long desired_version;
        //===================================

        vector<uint256> new_transaction_hashes;
        vector<tuple<int, int>> transaction_hash_refs; //TODO: check+test; # pairs of share_count, tx_count
        uint256 far_share_hash;
        uint256 max_target; //from max_bits;
        uint256 target;     //from bits;
        int32_t timestamp;
        int32_t absheight;
        uint128 abswork;
        char *new_script; //TODO: self.new_script = bitcoin_data.pubkey_hash_to_script2(self.share_data['pubkey_hash']) //FROM pubkey_hash;
        //TODO: gentx_hash
        BlockHeaderType header;
        uint256 pow_hash;
        uint256 hash; //=header_hash
        int32_t time_seen;

        shared_ptr<c2pool::Network> net;
        c2pool::libnet::addr peer_addr;
        UniValue contents;
        //TODO: segwit ???

    public:
        BaseShare(int VERSION, shared_ptr<Network> _net, c2pool::libnet::addr _peer_addr, UniValue _contents);

        virtual string SerializeJSON() override;
        virtual void DeserializeJSON(std::string json) override;

        bool is_segwit_activated() const
        {
            return c2pool::shares::is_segwit_activated(SHARE_VERSION, net);
        }

        virtual void contents_load(UniValue contents);

        virtual bool check(shared_ptr<c2pool::shares::ShareTracker> tracker /*, TODO: other_txs = None???*/);

        static PackStream get_ref_hash(shared_ptr<Network> _net, ShareInfo _share_info, MerkleLink _ref_merkle_link)
        {
            PackStream res;

            RefType ref_type_value(_net->IDENTIFIER, _share_info);
            PackStream ref_type_stream;
            ref_type_stream << ref_type_value;
            auto ref_type_hash = coind::data::hash256(ref_type_stream);

            auto unpacked_res = coind::data::check_merkle_link(ref_type_hash, std::make_tuple(_ref_merkle_link.branch, _ref_merkle_link.index));

            IntType(256) packed_res(unpacked_res);
            res << packed_res;

            return res;
        }
    };

    //17
    class Share : public BaseShare
    {
    public:
        Share(shared_ptr<Network> _net, c2pool::libnet::addr _peer_addr, UniValue _contents) : BaseShare(17, _net, _peer_addr, _contents) {}

        virtual void contents_load(UniValue contents) override;
    };

    //32
    class PreSegwitShare : public BaseShare
    {
    public:
        SegwitData segwit_data;

    public:
        PreSegwitShare(shared_ptr<Network> _net, c2pool::libnet::addr _peer_addr, UniValue _contents) : BaseShare(32, _net, _peer_addr, _contents)
        {
            if (merkle_link.branch.size() > 16 || (is_segwit_activated() && segwit_data.txid_merkle_link.branch.size() > 16))
            {
                throw std::runtime_error("merkle branch too long!");
            }
        }

        virtual void contents_load(UniValue contents) override;
    };

    shared_ptr<BaseShare> load_share(UniValue share, shared_ptr<Network> net, c2pool::libnet::addr peer_addr);
} // namespace c2pool::shares