#ifndef BITCOIN_DATA_H
#define BITCOIN_DATA_H

#include <cstring>
#include <vector>
#include <uint256.h>

using std::vector;

namespace bitcoin::data
{

    class PreviousOutput
    {
        uint256 hash;
        unsigned long index;

        PreviousOutput(){
            hash.SetNull();
            index = 4294967295;
        }

        PreviousOutput(uint256 _hash, unsigned long _index){
            hash = _hash;
            index = _index;
        }
    };

    class tx_in_type{
        PreviousOutput previous_output;
        char* script;
        unsigned long sequence;

        tx_in_type(){
            sequence = 4294967295;  
        }

        tx_in_type(PreviousOutput _previous_output, char* _script, unsigned long _sequence){
            previous_output = _previous_output;
            memcpy(script, _script, /*TODO: Script len*/);
            sequence = _sequence;
        }
    }

    class tx_out_type{
        unsigned long long value;
        char* script;

        tx_out_type(unsigned long long _value, char* _script){
            value = _value;
            script = _script;
        }
    }

    class tx_id_type{
        unsigned long version;
        vector<tx_in_type> tx_ins;
        vector<tx_out_type> tx_outs;
        unsigned long lock_time;
    }

    class TransactionType
    {
    public:
        int version;
        int marker;
        int flag;
        vector<tx_in_type> tx_ins;
        vector<tx_out_type> tx_outs;
    };
} // namespace bitcoin::data

#endif //BITCOIN_DATA_H