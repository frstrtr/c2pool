#pragma once

#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <btclibs/hash.h>
#include <btclibs/crypto/sha256.h>
#include <btclibs/crypto/ripemd160.h>
#include <btclibs/util/strencodings.h>
#include <btclibs/base58.h>
#include <btclibs/span.h>
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>
#include <univalue.h>
#include <networks/network.h>

#include <cstring>
#include <string>
#include <vector>
#include <tuple>
#include <iostream>
#include <memory>

using std::vector, std::tuple, std::string, std::shared_ptr;

namespace coind::data{
    class TransactionType;
}

namespace coind::data
{
    bool is_segwit_tx(UniValue tx);

    bool is_segwit_tx(shared_ptr<coind::data::TransactionType> tx);

    uint256 target_to_average_attempts(uint256 target);

    uint256 average_attempts_to_target(uint256 average_attempts);

    double target_to_difficulty(uint256 target);

    uint256 difficulty_to_target(uint256 difficulty);

	uint256 get_txid(shared_ptr<coind::data::TransactionType> tx);

	uint256 get_wtxid(shared_ptr<coind::data::TransactionType> tx, uint256 txid = uint256(), uint256 txhash = uint256());

} // namespace coind::data

// MerkleTree
namespace coind::data{

    class MerkleLink
    {
    public:
        std::vector<uint256> branch;
        int32_t index;

        MerkleLink()
        {
            index = 0;
        };

        MerkleLink(std::vector<uint256> _branch, int32_t _index = 0)//, int index)
        {
            branch = _branch;
            index = _index;
        }

        bool operator==(const MerkleLink &value)
        {
            return branch == value.branch;
            //return branch == value.branch && index == value.index;
        }

        bool operator!=(const MerkleLink &value)
        {
            return !(*this == value);
        }

//        MerkleLink &operator=(UniValue value)
//        {
//            for (auto hex_str: value["branch"].get_array().getValues())
//            {
//                uint256 temp_uint256;
//                temp_uint256.SetHex(hex_str.get_str());
//                branch.push_back(temp_uint256);
//            }
//            index = value["index"].get_int();
//
//            return *this;
//        }

//        operator UniValue()
//        {
//            UniValue result(UniValue::VOBJ);
//
//            UniValue branch_list(UniValue::VARR);
//            for (auto num: branch)
//            {
//                branch_list.push_back(num.GetHex());
//            }
//
//            result.pushKV("branch", branch_list);
//            result.pushKV("index", index);
//
//            return result;
//        }
    };

    struct merkle_record_type
    {
        IntType(256) left;
        IntType(256) right;

        merkle_record_type() = default;

        merkle_record_type(uint256 _left, uint256 _right)
        {
            left = _left;
            right = _right;
        }

        PackStream &write(PackStream &stream)
        {
            stream << left << right;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> left >> right;
            return stream;
        }
    };

    MerkleLink calculate_merkle_link(std::vector<uint256> hashes, int32_t index);

    //link = MerkleLink from shareTypes.h
    uint256 check_merkle_link(uint256 tip_hash, coind::data::MerkleLink link);

    uint256 merkle_hash(std::vector<uint256> hashes);

    // Для этого действия -- не нужна отдельная функция.
    uint256 get_witness_commitment_hash(uint256 witness_root_hash, uint256 witness_reserved_value);
};

namespace coind::data
{
    //TODO: want 4 optimization???
    uint256 hash256(std::string data);

    uint256 hash256(PackStream stream);

    uint256 hash256(uint256 data);

    uint160 hash160(string data);

    uint160 hash160(PackStream stream);

    uint160 hash160(uint160 data);

    //TODO: Check for data & buf valid '\0x0'
    //double hash
    uint256 hash256_from_hash_link(uint32_t* init, unsigned char* data, unsigned char* buf = nullptr, uint64_t length = 0);

    struct HumanAddressType
    {
        IntType(8) version;
        IntType(160) pubkey_hash;

        PackStream &write(PackStream &stream)
        {
            stream << version << pubkey_hash;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> version >> pubkey_hash;
            return stream;
        }
    };

    std::string pubkey_hash_to_address(auto pubkey_hash, shared_ptr<c2pool::Network> _net)
    {
        HumanAddressType human_addr{IntType(8)(_net->ADDRESS_VERSION), IntType(160)(pubkey_hash)};
        PackStream stream;
        stream << human_addr;
        Span<unsigned char> _span(stream.data);
        auto result = EncodeBase58(_span);
        return result;
    }

    auto pubkey_to_address(auto pubkey, shared_ptr<c2pool::Network> _net)
    {
        return pubkey_to_address(hash160(pubkey), _net);
    }

    auto address_to_pubkey_hash(auto address, shared_ptr<c2pool::Network> _net)
    {
        vector<unsigned char> decoded_addr;
        if (!DecodeBase58(address, decoded_addr, 64))
        {
            throw ("Error address in decode");
        }
        PackStream stream(decoded_addr.data(), decoded_addr.size());

        HumanAddressType human_addr;
        stream >> human_addr;

        if (human_addr.version.value != _net->ADDRESS_VERSION)
        {
            throw("address not for this net!");
        }

        return human_addr.pubkey_hash.value;
    }

    PackStream pubkey_hash_to_script2(uint160 pubkey_hash);
}