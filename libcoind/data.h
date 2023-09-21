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
#include "transaction.h"

#include <cstring>
#include <string>
#include <vector>
#include <tuple>
#include <iostream>
#include <memory>

using std::vector, std::tuple, std::string, std::shared_ptr;

//namespace coind::data{
//    class TransactionType;
//}

namespace coind::data
{
    bool is_segwit_tx(UniValue tx);

    inline bool is_segwit_tx(std::shared_ptr<coind::data::TransactionType> tx)
    {
        if (tx)
        {
            return tx->wdata.has_value() && tx->wdata->marker == 0 && tx->wdata->flag >= 1;
        }
        return false;
    }

    arith_uint288 target_to_average_attempts(uint256 target);

    uint256 average_attempts_to_target(arith_uint288 att);
    uint256 average_attempts_to_target(uint288 average_attempts);

    double target_to_difficulty(uint256 target);

    /// max_target/difficulty
    uint256 difficulty_to_target(uint256 difficulty);
    /// max_target/(1/difficulty) -> max_target * difficulty
    uint256 difficulty_to_target_1(uint256 difficulty);

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
            branch = std::vector<uint256>();
        };

        MerkleLink(std::vector<uint256> _branch, int32_t _index = 0)//, int index)
        {
            branch = _branch;
            index = _index;
        }

        bool operator==(const MerkleLink &value) const
        {
            return branch == value.branch;
            //return branch == value.branch && index == value.index;
        }

        bool operator!=(const MerkleLink &value) const
        {
            return !(*this == value);
        }

        friend std::ostream &operator<<(std::ostream &stream, const MerkleLink &_value)
        {
            stream << "(MerkleLink: ";
            stream << "branch = " << _value.branch;
            stream << ", index = " << _value.index;
            stream << ")";

            return stream;
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

    //link = MerkleLink from shareTypes.h; tip_hash -- hash256(data, true)!
    uint256 check_merkle_link(uint256 tip_hash, coind::data::MerkleLink link);

    uint256 merkle_hash(std::vector<uint256> hashes);

    // Для этого действия -- не нужна отдельная функция.
    uint256 get_witness_commitment_hash(uint256 witness_root_hash, uint256 witness_reserved_value);
};

namespace coind::data
{
    //TODO: want 4 optimization???
    uint256 hash256(std::string data, bool reverse = true);

    uint256 hash256(PackStream stream, bool reverse = true);

    uint256 hash256(uint256 data, bool reverse = true);

    uint160 hash160(string data, bool reverse = true);

    uint160 hash160(PackStream stream, bool reverse = true);

    uint160 hash160(uint160 data, bool reverse = true);

    //double hash
    uint256 hash256_from_hash_link(uint32_t init[8], vector<unsigned char> data, vector<unsigned char> buf, uint64_t length = 0);

    struct HumanAddressType
    {
        IntType(8) version;
        IntType(160) pubkey_hash;

        PackStream checksum_func(PackStream data)
        {
            auto _hash = hash256(std::move(data));
            std::vector<unsigned char> res(_hash.begin(), _hash.end());

            res.resize(4);
            return {res};
        }

        PackStream &write(PackStream &stream)
        {
            stream << version << pubkey_hash;
            auto checksum = checksum_func(stream);
            stream << checksum;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> version >> pubkey_hash;

            PackStream checksum_bytes;
            checksum_bytes << version << pubkey_hash;

            auto calculated_checksum = checksum_func(checksum_bytes);
            if (stream.size() < calculated_checksum.size())
                throw std::invalid_argument("invalid checksum#1");

            PackStream checksum(std::vector<unsigned char>(stream.begin(), stream.begin() + (int) calculated_checksum.size()));
            stream.data.erase(stream.begin(), stream.begin() + (int) calculated_checksum.size());

            if (checksum.data != calculated_checksum.data)
                throw std::invalid_argument("invalid checksum#2");

            return stream;
        }
    };

    std::string pubkey_hash_to_address(auto pubkey_hash, int32_t addr_ver, int32_t bech32_ver, shared_ptr<c2pool::Network> _net)
    {
        if (addr_ver == -1)
        {
            /*if hasattr(net, 'padding_bugfix') and net.padding_bugfix:
                thash = '{:040x}'.format(pubkey_hash)
            else:
                thash = '{:x}'.format(pubkey_hash)
                if len(thash) % 2 == 1:
                    thash = '0%s' % thash
            data = [int(x) for x in bytearray.fromhex(thash)]
            if net.SYMBOL.lower() in ['bch', 'tbch', 'bsv', 'tbsv']:
                return cash_addr.encode(net.HUMAN_READABLE_PART, bech32_ver, data)
            else:
                return segwit_addr.encode(net.HUMAN_READABLE_PART, bech32_ver, data)*/
            LOG_WARNING << "pubkey_hash_to_address TODO";
        }


        HumanAddressType human_addr{IntType(8)(addr_ver), IntType(160)(pubkey_hash)};
        PackStream stream;
        stream << human_addr;
        Span<unsigned char> _span(stream.data);
        auto result = EncodeBase58(_span);
        return result;
    }

    auto pubkey_to_address(auto pubkey, shared_ptr<c2pool::Network> _net)
    {
        return pubkey_hash_to_address(hash160(pubkey), _net->parent->ADDRESS_VERSION, -1, _net);
    }

    auto get_legacy_pubkey_hash(auto address, shared_ptr<c2pool::Network> _net)
    {
        // P2PKH or P2SH address
        vector<unsigned char> decoded_addr;
        if (!DecodeBase58(address, decoded_addr, 64))
        {
            throw ("Error address in decode");
        }
        PackStream stream(decoded_addr.data(), decoded_addr.size());

        HumanAddressType human_addr;
        stream >> human_addr;

        if (human_addr.version.value != _net->parent->ADDRESS_VERSION)
        {
            throw("address not for this net!");
        }

        return std::make_tuple(human_addr.pubkey_hash.value, human_addr.version.get(), -1);
    }

    auto address_to_pubkey_hash(auto address, shared_ptr<c2pool::Network> _net)
    {
        //TODO:
//        try
//        {
            return get_legacy_pubkey_hash(address, _net);
//        }

        /* TODO: for BCH/BSV
    if net.SYMBOL.lower() not in ['bch', 'tbch', 'bsv', 'tbsv']:
        try:
            return get_bech32_pubkey_hash(address, net)
        except AddrError:
            pass
    else:
        try:
            return get_cashaddr_pubkey_hash(address, net)
        except AddrError:
            pass
    raise ValueError('invalid addr')
         */
    }

    PackStream pubkey_hash_to_script2(uint160 pubkey_hash, int32_t version, int32_t bech32_ver, const shared_ptr<c2pool::Network>& _net);

    auto address_to_script2(auto address, shared_ptr<c2pool::Network> _net)
    {
        auto res = address_to_pubkey_hash(address, _net);
        return pubkey_hash_to_script2(std::get<0>(res), std::get<1>(res), std::get<2>(res), _net);
    }

    inline auto pubkey_to_script2(PackStream pubkey)
    {
        if (pubkey.size() > 75)
            throw invalid_argument("pubkey_to_script2: pubkey.size > 75");

        pubkey.data.insert(pubkey.begin(), (unsigned char)pubkey.size());
        pubkey.data.push_back('\xac');

        return pubkey;
    }

    inline std::string script2_to_pubkey_address(const PackStream& script2, const shared_ptr<c2pool::Network>& _net)
    {
        PackStream pubkey;

        try
        {
            pubkey = script2;
            pubkey.data.erase(pubkey.begin());
            pubkey.data.erase(pubkey.end()-1);

            auto script2_test = pubkey_to_script2(pubkey);
            if (script2_test != script2)
                throw std::invalid_argument("ValueError");
        } catch (...)
        {
            throw std::invalid_argument("AddrError");
        }

        return pubkey_to_address(pubkey, _net);
    }

    inline std::string script2_to_pubkey_hash_address(const PackStream& script2, int32_t addr_ver, int32_t bech32_ver, const shared_ptr<c2pool::Network>& _net)
    {
        //TODO: Check for BCH and BSV length, could be longer than 20 bytes
        uint160 pubkey_hash;

        try
        {
            PackStream pubkey = script2;
            pubkey.data.erase(pubkey.begin(), pubkey.begin()+3);
            pubkey.data.erase(pubkey.end()-2, pubkey.end());

            pubkey_hash = unpack<IntType(160)>(pubkey.data);
            auto script2_test = pubkey_hash_to_script2(pubkey_hash, addr_ver, bech32_ver, _net);

            if (script2_test != script2)
                throw std::invalid_argument("ValueError");
        } catch (...)
        {
            throw std::invalid_argument("AddrError");
        }

        return pubkey_hash_to_address(pubkey_hash, addr_ver, bech32_ver, _net);
    }

    inline std::string script2_to_cashaddress(const PackStream& script2, int32_t addr_ver, int32_t ca_ver, const shared_ptr<c2pool::Network>& _net)
    {
        //TODO: Check for BCH and BSV length, could be longer than 20 bytes
        uint160 pubkey_hash;

        try
        {
            PackStream sub_hash = script2;
            if (ca_ver == 0)
            {
                sub_hash.data.erase(sub_hash.begin(), sub_hash.begin() + 3);
                sub_hash.data.erase(sub_hash.end() - 2, sub_hash.end());
            } else if (ca_ver == 1)
            {
                sub_hash.data.erase(sub_hash.begin(), sub_hash.begin() + 2);
                sub_hash.data.erase(sub_hash.end() - 1, sub_hash.end());
            } else {
                throw std::invalid_argument("ValueError");
            }

            pubkey_hash = unpack<IntType(160)>(sub_hash.data);
            auto script2_test = pubkey_hash_to_script2(pubkey_hash, addr_ver, ca_ver, _net);

            if (script2_test != script2)
                throw std::invalid_argument("ValueError");
        } catch (...)
        {
            throw std::invalid_argument("AddrError");
        }

        return pubkey_hash_to_address(pubkey_hash, addr_ver, ca_ver, _net);
    }

    inline std::string script2_to_bech32_address(const PackStream& script2, int32_t addr_ver, int32_t bech32_ver, const shared_ptr<c2pool::Network>& _net)
    {
        //TODO: Check for BCH and BSV length, could be longer than 20 bytes
        uint160 pubkey_hash;

        try
        {
            PackStream pubkey = script2;
            pubkey.data.erase(pubkey.begin(), pubkey.begin()+2);

            pubkey_hash = unpack<IntType(160)>(pubkey.data);
            auto script2_test = pubkey_hash_to_script2(pubkey_hash, addr_ver, bech32_ver, _net);

            if (script2_test != script2)
                throw std::invalid_argument("ValueError");
        } catch (...)
        {
            throw std::invalid_argument("AddrError");
        }
        return pubkey_hash_to_address(pubkey_hash, addr_ver, bech32_ver, _net);
    }

    inline std::string script2_to_p2sh_address(const PackStream& script2, int32_t addr_ver, int32_t bech32_ver, const shared_ptr<c2pool::Network>& _net)
    {
        //TODO: Check for BCH and BSV length, could be longer than 20 bytes
        uint160 pubkey_hash;

        try
        {
            PackStream pubkey = script2;
            pubkey.data.erase(pubkey.begin(), pubkey.begin()+2);
            pubkey.data.erase(pubkey.end()-1, pubkey.end());

            pubkey_hash = unpack<IntType(160)>(pubkey.data);
            auto script2_test = pubkey_hash_to_script2(pubkey_hash, addr_ver, bech32_ver, _net);

            if (script2_test != script2)
                throw std::invalid_argument("ValueError");
        } catch (...)
        {
            throw std::invalid_argument("AddrError");
        }

        return pubkey_hash_to_address(pubkey_hash, addr_ver, bech32_ver, _net);
    }

    inline std::string script2_to_address(const PackStream& script2, int32_t addr_ver, int32_t bech32_ver, const shared_ptr<c2pool::Network>& _net)
    {
        //TODO: optimize (избавиться от перебора всех методов)
        try
        {
            return script2_to_pubkey_address(script2, _net);
        } catch (const std::invalid_argument& ec) {}


        // pubkey_hash_address
        try
        {
            return script2_to_pubkey_hash_address(script2, addr_ver, bech32_ver, _net);
        } catch (const std::invalid_argument& ec) {}

        // bech32_address
        try
        {
            return script2_to_bech32_address(script2, addr_ver, bech32_ver, _net);
        } catch (const std::invalid_argument& ec) {}

        // p2sh_address
        try
        {
            return script2_to_p2sh_address(script2, addr_ver, bech32_ver, _net);
        } catch (const std::invalid_argument& ec) {}

        // cashaddress
        try
        {
            return script2_to_cashaddress(script2, addr_ver, bech32_ver, _net);
        } catch (const std::invalid_argument& ec) {}

        throw std::invalid_argument((boost::format("Invalid script2 hash: %1%") % HexStr(script2.data)).str());
    }

    auto donation_script_to_address(shared_ptr<c2pool::Network> _net)
    {
        try
        {
            return script2_to_address(PackStream{_net->DONATION_SCRIPT}, _net->parent->ADDRESS_VERSION, -1, _net);
        } catch (const invalid_argument &ec)
        {
            return script2_to_address(PackStream{_net->DONATION_SCRIPT}, _net->parent->ADDRESS_P2SH_VERSION, -1, _net);
        }
    }
}