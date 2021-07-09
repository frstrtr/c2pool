#pragma once

#include <btclibs/uint256.h>
#include <univalue.h>
#include <boost/optional.hpp>

#include <set>
#include <tuple>
#include <vector>

namespace c2pool::shares
{
    enum StaleInfo
    {
        unk = 0,
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

    class BlockHeaderType : public SmallBlockHeaderType
    {
    public:
        
    public:
        BlockHeaderType() : SmallBlockHeaderType(){};
        BlockHeaderType(SmallBlockHeaderType min_header, )
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

    struct ShareData
    {
    public:
        uint256 previous_share_hash; //none — pack.PossiblyNoneType(0, pack.IntType(256))
        std::string coinbase;
        unsigned int nonce;         //pack.IntType(32)
        uint160 pubkey_hash;        //pack.IntType(160)
        unsigned long long subsidy; //pack.IntType(64)
        unsigned short donation;    //pack.IntType(16)
        StaleInfo stale_info;
        unsigned long long desired_version; //pack.VarIntType()

        friend bool operator==(const ShareData &first, const ShareData &second);
        friend bool operator!=(const ShareData &first, const ShareData &second);

        ShareData &operator=(UniValue value)
        {
            previous_share_hash.SetHex(value["previous_share_hash"].get_str());
            coinbase = value["coinbase"].get_str();
            nonce = value["nonce"].get_int64();
            pubkey_hash.SetHex(value["pubkey_hash"].get_str());
            subsidy = value["subsidy"].get_int64();
            donation = value["donation"].get_int();
            stale_info = (StaleInfo)value["stale_info"].get_int();
            desired_version = value["desired_version"].get_int64();

            return *this;
        }

        operator UniValue()
        {
            UniValue result(UniValue::VOBJ);

            result.pushKV("previous_share_hash", previous_share_hash.GetHex());
            result.pushKV("coinbase", coinbase);
            result.pushKV("nonce", (uint64_t)nonce);
            result.pushKV("pubkey_hash", pubkey_hash.GetHex());
            result.pushKV("subsidy", (uint64_t)subsidy);
            result.pushKV("donation", donation);
            result.pushKV("stale_info", (int)stale_info);
            result.pushKV("desired_version", (uint64_t)desired_version);

            return result;
        }
    };

    struct ShareInfo
    {
    public:
        ShareData share_data;
        uint256 far_share_hash;                                  //none — pack.PossiblyNoneType(0, pack.IntType(256))
        unsigned int max_bits;                                   //bitcoin_data.FloatingIntegerType() max_bits;
        unsigned int bits;                                       //bitcoin_data.FloatingIntegerType() bits;
        unsigned int timestamp;                                  //pack.IntType(32)
        std::vector<uint256> new_transaction_hashes;             //pack.ListType(pack.IntType(256))
        std::vector<std::tuple<int, int>> transaction_hash_refs; //pack.ListType(pack.VarIntType(), 2)), # pairs of share_count, tx_count
        unsigned long absheigth;                                 //pack.IntType(32)
        uint128 abswork;                                         //pack.IntType(128)

        boost::optional<SegwitData> segwit_data;

    public:
        ShareInfo(){};
        ShareInfo(ShareData share_data, std::vector<uint256> new_transaction_hashes, std::vector<std::tuple<int, int>> transaction_hash_refs, uint256 far_share_hash, unsigned int max_bits, unsigned int bits, unsigned int timestamp, unsigned long absheigth, uint128 abswork, SegwitData segwit_data);

        friend bool operator==(const ShareInfo &first, const ShareInfo &second);
        friend bool operator!=(const ShareInfo &first, const ShareInfo &second);

        //TODO: remove or create just obj -> json;
        // ShareInfo &operator=(UniValue value)
        // {
        //     share_data = std::make_shared<ShareData>();
        //     *share_data = value["share_data"].get_obj();

        //     segwit_data = std::make_shared<SegwitData>();
        //     *segwit_data = value["segwit_data"].get_obj();

        //     for (auto hex_str : value["new_transaction_hashes"].get_array().getValues())
        //     {
        //         uint256 temp_uint256;
        //         temp_uint256.SetHex(hex_str.get_str());
        //         new_transaction_hashes.push_back(temp_uint256);
        //     }

        //     for (auto tx_hash_ref : value["transaction_hash_refs"].get_array().getValues())
        //     {
        //         TransactionHashRef temp_tx_hash_ref;
        //         temp_tx_hash_ref = tx_hash_ref.get_obj();
        //         transaction_hash_refs.push_back(temp_tx_hash_ref);
        //     }

        //     far_share_hash.SetHex(value["far_share_hash"].get_str());
        //     max_bits = value["max_bits"].get_int64();
        //     bits = value["bits"].get_int64();
        //     timestamp = value["timestamp"].get_int64();
        //     absheigth = value["absheigth"].get_int64();

        //     abswork.SetHex(value["abswork"].get_str());
        //     return *this;
        // }

        // operator UniValue()
        // {
        //     UniValue result(UniValue::VOBJ);

        //     result.pushKV("share_data", *share_data);
        //     result.pushKV("segwit_data", *segwit_data);

        //     UniValue new_transaction_hashes_array(UniValue::VARR);
        //     for (auto hash : new_transaction_hashes)
        //     {
        //         new_transaction_hashes_array.push_back(hash.GetHex());
        //     }
        //     result.pushKV("new_transaction_hashes", new_transaction_hashes_array);

        //     UniValue transaction_hash_refs_array(UniValue::VARR);
        //     for (auto tx_hash_ref : transaction_hash_refs)
        //     {
        //         transaction_hash_refs_array.push_back(tx_hash_ref);
        //     }
        //     result.pushKV("transaction_hash_refs", transaction_hash_refs_array);

        //     result.pushKV("far_share_hash", far_share_hash.GetHex());
        //     result.pushKV("max_bits", (uint64_t)max_bits);
        //     result.pushKV("bits", (uint64_t)bits);
        //     result.pushKV("timestamp", (uint64_t)timestamp);
        //     result.pushKV("absheigth", (uint64_t)absheigth);
        //     result.pushKV("abswork", abswork.GetHex());

        //     return result;
        // }
    };

}