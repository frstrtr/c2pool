#include "data.h"

#include <sstream>

#include "transaction.h"
#include <btclibs/uint256.h>
#include <univalue.h>

namespace coind::data
{
    bool is_segwit_tx(UniValue tx)
    {
        if (tx.exists("marker") && tx.exists("flag"))
        {
            return tx["marker"].get_int() == 0 && tx["flag"].get_int() >= 1;
        }
        return false;
    }

    bool is_segwit_tx(std::shared_ptr<TransactionType> tx)
    {
        std::shared_ptr<WitnessTransactionType> cast_tx = std::dynamic_pointer_cast<WitnessTransactionType>(tx);
//        if (std::is_t)
        if (cast_tx)
        {
            return cast_tx->marker == 0 && cast_tx->flag >= 1;
        }
        return false;
    }

    uint256 target_to_average_attempts(uint256 target)
    {
        //TODO: return coind::data::python::PyBitcoindData::target_to_average_attempts(target);
    }

    uint256 average_attempts_to_target(uint256 average_attempts)
    {
        //TODO: return coind::data::python::PyBitcoindData::average_attempts_to_target(average_attempts);
    }

    double target_to_difficulty(uint256 target)
    {
        //TODO: return coind::data::python::PyBitcoindData::target_to_difficulty(target);
    }

    uint256 difficulty_to_target(uint256 difficulty)
    {
        //TODO: return coind::data::python::PyBitcoindData::difficulty_to_target(difficulty);
    }

    uint256 hash256(std::string data)
    {
        uint256 result;

        vector<unsigned char> out1;
        out1.resize(CSHA256::OUTPUT_SIZE);

        vector<unsigned char> out2;
        out2.resize(CSHA256::OUTPUT_SIZE);

        CSHA256().Write((unsigned char *)&data[0], data.length()).Finalize(&out1[0]);
        CSHA256().Write((unsigned char *)&out1[0], out1.size()).Finalize(&out2[0]);
        result.SetHex(HexStr(out2));

        return result;
    }

    uint256 hash256(PackStream stream)
    {
        auto _bytes = stream.bytes();
        string in(reinterpret_cast<char const *>(_bytes), stream.size());
        return hash256(in);
    }

    uint256 hash256(uint256 data)
    {
        string in = data.GetHex();
        return hash256(in);
    }

    uint160 hash160(string data)
    {
        uint160 result;

        vector<unsigned char> out1;
        out1.resize(CSHA256::OUTPUT_SIZE);

        vector<unsigned char> out2;
        out2.resize(CRIPEMD160::OUTPUT_SIZE);

        CSHA256().Write((unsigned char *)&data[0], data.length()).Finalize(&out1[0]);
        CRIPEMD160().Write((unsigned char *)&out1[0], out1.size()).Finalize(&out2[0]);
        result.SetHex(HexStr(out2));

        return result;
    }

    uint160 hash160(PackStream stream)
    {
        auto _bytes = stream.bytes();
        string in(reinterpret_cast<char const *>(_bytes), stream.size());
        return hash160(in);
    }

    uint160 hash160(uint160 data)
    {
        string in = data.GetHex();
        return hash160(in);
    }

    uint256 check_merkle_link(uint256 tip_hash, tuple<vector<uint256>, int32_t> link)
    {
        auto branch = std::get<0>(link);
        auto index = std::get<1>(link);

        if (index >= pow(2, branch.size()))
        {
            throw std::invalid_argument("index too large");
        }

        auto cur = tip_hash;

        int i = 0;
        for (auto h : branch)
        {
            if ((index >> i) & 1)
            {
                auto merkle_rec = MerkleRecordType{h, cur};
                PackStream ps;
                ps << merkle_rec;
                cur = hash256(ps);
            }
            else
            {
                auto merkle_rec = MerkleRecordType{cur, h};
                PackStream ps;
                ps << merkle_rec;
                cur = hash256(ps);
            }
        }

        return cur;
    }

    PackStream pubkey_hash_to_script2(uint160 pubkey_hash)
    {
        auto packed_pubkey_hash = IntType(160)(pubkey_hash);

        PackStream result;
        result << vector<unsigned char>({0x76, 0xa9, 0x14}) << packed_pubkey_hash << vector<unsigned char>({0x88, 0xac});

        return result;
    }
}