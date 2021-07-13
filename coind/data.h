#pragma once

#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <btclibs/hash.h>
#include <btclibs/crypto/sha256.h>
#include <btclibs/util/strencodings.h>
#include <devcore/py_base.h>
#include <util/pack.h>
#include <univalue.h>

#include <cstring>
#include <string>
#include <vector>
#include <tuple>
#include <iostream>

using std::vector, std::tuple, std::string;

namespace coind::data::python
{
    class PyBitcoindData : c2pool::python::PythonBase
    {
    protected:
        static const char *filepath;

    public:
        static uint256 target_to_average_attempts(uint256 target);

        static uint256 average_attempts_to_target(uint256 average_attempts);

        //TODO: using uint256.SetCompact | https://bitcoin.stackexchange.com/questions/30467/what-are-the-equations-to-convert-between-bits-and-difficulty
        static double target_to_difficulty(uint256 target);

        static uint256 difficulty_to_target(uint256 difficulty);
    };
} // namespace coind::data::python

namespace coind::data
{

    bool is_segwit_tx(UniValue tx);

    uint256 target_to_average_attempts(uint256 target);

    uint256 average_attempts_to_target(uint256 average_attempts);

    double target_to_difficulty(uint256 target);

    uint256 difficulty_to_target(uint256 difficulty);

    class PreviousOutput
    {
    public:
        uint256 hash;
        unsigned long index;

        PreviousOutput()
        {
            hash.SetNull();
            index = 4294967295;
        }

        PreviousOutput(uint256 _hash, unsigned long _index)
        {
            hash = _hash;
            index = _index;
        }
    };

    class tx_in_type
    {
    public:
        PreviousOutput previous_output;
        char *script;
        unsigned long sequence;

        tx_in_type()
        {
            sequence = 4294967295;
        }

        tx_in_type(PreviousOutput _previous_output, char *_script, unsigned long _sequence)
        {
            previous_output = _previous_output;
            script = _script;
            sequence = _sequence;
        }
    };

    class tx_out_type
    {
    public:
        unsigned long long value;
        char *script;

        tx_out_type(unsigned long long _value, char *_script)
        {
            value = _value;
            script = _script;
        }
    };

    class tx_id_type
    {
    public:
        unsigned long version;
        vector<tx_in_type> tx_ins;
        vector<tx_out_type> tx_outs;
        unsigned long lock_time;
    };

    class TransactionType
    {
    public:
        int version;
        int marker;
        int flag;
        vector<tx_in_type> tx_ins;
        vector<tx_out_type> tx_outs;
    };
} // namespace coind::data

namespace coind::data
{
    //TODO: want 4 optimization???
    uint256 hash256(string data)
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

    uint256 hash256(c2pool::SerializedData data)
    {
        string in(reinterpret_cast<char const *>(data.data), data.length);
        return hash256(in);
    }

    uint256 hash256(uint256 data)
    {
        string in = data.GetHex();
        return hash256(in);
    }

    struct MerkleRecordType
    {
        uint256 left;
        uint256 right;
    };

    //link = MerkleLink from shareTypes.h
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
                cur = hash256(c2pool::SerializedData::pack(merkle_rec));
            }
            else
            {
                auto merkle_rec = MerkleRecordType{cur, h};
                cur = hash256(c2pool::SerializedData::pack(merkle_rec));
            }
        }

        return cur;
    }
}