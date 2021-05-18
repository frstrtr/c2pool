#pragma once

#include <coind/data.h>
#include <btclibs/uint256.h>
#include <dbshell/dbObject.h>
using dbshell::DBObject;

#include <string>
#include <memory>
#include <tuple>
#include <vector>
#include <map>

using std::shared_ptr, std::string;
using std::vector, std::tuple, std::map;

class c2pool::shares::tracker::ShareTracker;

#include "prefsum_share.h"

namespace c2pool::shares::share
{
    enum StaleInfo
    {
        None = 0,
        orphan = 253,
        doa = 254
    };

    class SmallBlockHeaderType
    {
    public:
        unsigned long long version;
        uint256 previous_block;
        unsigned int timestamp;
        unsigned int bits;
        unsigned int nonce;

        SmallBlockHeaderType(){};
        SmallBlockHeaderType(unsigned long long version, uint256 previous_block, unsigned int timeStamp, unsigned int bits, unsigned int nonce);

        friend bool operator==(const SmallBlockHeaderType &first, const SmallBlockHeaderType &second);
        friend bool operator!=(const SmallBlockHeaderType &first, const SmallBlockHeaderType &second);

        SmallBlockHeaderType &operator=(UniValue value)
        {
            version = value["version"].get_int64();
            previous_block.SetHex(value["previous_block"].get_str());
            timestamp = value["timestamp"].get_int64();
            bits = value["bits"].get_int64();
            nonce = value["nonce"].get_int64();

            return *this;
        }

        operator UniValue()
        {
            UniValue result(UniValue::VOBJ);

            result.pushKV("version", (uint64_t)version);
            result.pushKV("previous_block", previous_block.GetHex());
            result.pushKV("timestamp", (uint64_t)timestamp);
            result.pushKV("bits", (uint64_t)bits);
            result.pushKV("nonce", (uint64_t)nonce);

            return result;
        }
    };

    class MerkleLink
    {
    public:
        std::vector<uint256> branch;
        int index;

        MerkleLink()
        {
            index = 0;
        };
        MerkleLink(std::vector<uint256> branch, int index);

        friend bool operator==(const MerkleLink &first, const MerkleLink &second);
        friend bool operator!=(const MerkleLink &first, const MerkleLink &second);

        MerkleLink &operator=(UniValue value)
        {
            for (auto hex_str : value["branch"].get_array().getValues())
            {
                uint256 temp_uint256;
                temp_uint256.SetHex(hex_str.get_str());
                branch.push_back(temp_uint256);
            }
            index = value["index"].get_int();

            return *this;
        }

        operator UniValue()
        {
            UniValue result(UniValue::VOBJ);

            UniValue branch_list(UniValue::VARR);
            for (auto num : branch)
            {
                branch_list.push_back(num.GetHex());
            }

            result.pushKV("branch", branch_list);
            result.pushKV("index", index);

            return result;
        }
    };

    class HashLinkType
    {
    public:
        std::string state;         //TODO: pack.FixedStrType(32)
        std::string extra_data;    //TODO: pack.FixedStrType(0) # bit of a hack, but since the donation script is at the end, const_ending is long enough to always make this empty
        unsigned long long length; //pack.VarIntType()

        HashLinkType() {}
        HashLinkType(std::string state, std::string extra_data, unsigned long long length);

        friend bool operator==(const HashLinkType &first, const HashLinkType &second);
        friend bool operator!=(const HashLinkType &first, const HashLinkType &second);

        HashLinkType &operator=(UniValue value)
        {
            state = value["state"].get_str();
            extra_data = value["extra_data"].get_str();
            length = value["length"].get_int64();
            return *this;
        }

        operator UniValue()
        {
            UniValue result(UniValue::VOBJ);

            result.pushKV("state", state);
            result.pushKV("extra_data", extra_data);
            result.pushKV("length", (uint64_t)length);

            return result;
        }
    };

    class BaseShare : public DBObject
    {
        const int SHARE_VERSION; //TODO: init in constructor

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
        //TODO: пропущен segwit_data, который находится в SegwitShare.

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
    public:
        BaseShare(int VERSION) : SHARE_VERSION(VERSION) {}

        virtual string SerializeJSON() override;
        virtual void DeserializeJSON(std::string json) override;

        operator c2pool::shares::tracker::PrefixSumShareElement() const
        {
            c2pool::shares::tracker::PrefixSumShareElement prefsum_share = {hash, UintToArith256(coind::data::target_to_average_attempts(target)), UintToArith256(coind::data::target_to_average_attempts(max_target)), 1};
            return prefsum_share;
        }

        virtual void check(shared_ptr<c2pool::shares::tracker::ShareTracker> tracker /*, TODO: other_txs = None???*/);
    };

    class Share : public BaseShare
    {
    public:
        Share(int VERSION) : BaseShare(VERSION) {}
    };

    class SegwitData
    {
        //SEGWIT DATA, 94 data.py
    public:
        MerkleLink txid_merkle_link; //---------------
        uint256 wtxid_merkle_root;   //pack.IntType(256)

        //Init PossiblyNoneType
        SegwitData()
        {
            txid_merkle_link = MerkleLink();
            wtxid_merkle_root.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        };

        SegwitData(MerkleLink txid_merkle_link, uint256 wtxid_merkle_root);

        friend bool operator==(const SegwitData &first, const SegwitData &second);
        friend bool operator!=(const SegwitData &first, const SegwitData &second);

        SegwitData &operator=(UniValue value)
        {
            txid_merkle_link = value["txid_merkle_link"].get_obj();

            wtxid_merkle_root.SetHex(value["wtxid_merkle_root"].get_str());

            return *this;
        }

        operator UniValue()
        {
            UniValue result(UniValue::VOBJ);

            result.pushKV("txid_merkle_link", txid_merkle_link);
            result.pushKV("wtxid_merkle_root", wtxid_merkle_root.GetHex());

            return result;
        }
    };

    class SegwitShare : public BaseShare
    {
    public:
        SegwitData segwit_data;

    public:
        SegwitShare() : BaseShare(17) {}
    };
} // namespace c2pool::shares::share