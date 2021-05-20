#pragma once

#include <btclibs/uint256.h>
#include <univalue.h>

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
}