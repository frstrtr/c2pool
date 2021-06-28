#pragma once

#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <devcore/py_base.h>
#include <univalue.h>

#include <cstring>
#include <vector>
#include <iostream>


using std::vector;

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