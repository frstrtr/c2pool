#ifndef BITCOIND_DATA_H
#define BITCOIND_DATA_H

#include "uint256.h"
#include "arith_uint256.h"
#include "py_base.h"

#include <cstring>
#include <vector>
#include <iostream>


using std::vector;

namespace bitcoind::data::python
{
    class PyBitcoindData : c2pool::python::PythonBase
    {
    protected:
        static const char *filepath;

    public:
    
        static uint256 target_to_average_attempts(uint256 target);

        static uint256 average_attempts_to_target(uint256 average_attempts);

        static double target_to_difficulty(uint256 target);

        static uint256 difficulty_to_target(uint256 difficulty);
    };
} // namespace bitcoind::data::python

namespace bitcoind::data
{

    uint256 target_to_average_attempts(uint256 target)
    {
        return bitcoind::data::python::PyBitcoindData::target_to_average_attempts(target);
    }

    uint256 average_attempts_to_target(uint256 average_attempts)
    {
        return bitcoind::data::python::PyBitcoindData::average_attempts_to_target(average_attempts);
    }

    double target_to_difficulty(uint256 target)
    {
        return bitcoind::data::python::PyBitcoindData::target_to_difficulty(target);
    }

    uint256 difficulty_to_target(uint256 difficulty)
    {
        return bitcoind::data::python::PyBitcoindData::difficulty_to_target(difficulty);
    }

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
} // namespace bitcoind::data

#endif //BITCOIND_DATA_H