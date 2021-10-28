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

} // namespace coind::data

namespace coind::data
{
    //TODO: want 4 optimization???
    uint256 hash256(std::string data);

    uint256 hash256(PackStream stream);

    uint256 hash256(uint256 data);

    uint160 hash160(string data);

    uint160 hash160(PackStream stream);

    uint160 hash160(uint160 data);

    struct MerkleRecordType
    {
        uint256 left;
        uint256 right;

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

    //link = MerkleLink from shareTypes.h
    uint256 check_merkle_link(uint256 tip_hash, tuple<vector<uint256>, int32_t> link);

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
}