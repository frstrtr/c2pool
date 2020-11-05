#ifndef BITCOIND_DATA_H
#define BITCOIND_DATA_H

#include <cstring>
#include <vector>
#include <uint256.h>

using std::vector;

namespace bitcoind::data
{

    // uint256 target_to_average_attempts(uint256 target)
    // {
    //     //TODO:
    // }

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