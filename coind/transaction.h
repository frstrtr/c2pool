#pragma once

#include <vector>
#include <memory>
#include <string>

#include "univalue.h"
#include <util/stream.h>
#include <util/stream_types.h>
#include <btclibs/uint256.h>

using std::vector, std::string;

namespace coind::data
{
    class TransactionType;
    class WitnessTransactionType;
}

namespace coind::data::stream
{
    struct PreviousOutput_stream
    {
        IntType(256) hash;
        IntType(32) index;

        PackStream &write(PackStream &stream)
        {
            stream << hash << index;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> hash >> index;
            return stream;
        }
    };

    struct TxInType_stream
    {
        PossibleNoneType<PreviousOutput_stream> previous_output;
        StrType script;
        PossibleNoneType<IntType(32)> sequence;

        PackStream &write(PackStream &stream)
        {
            stream << previous_output << script << sequence;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> previous_output >> script >> sequence;
            return stream;
        }
    };

    struct TxOutType_stream
    {
        IntType(64) value;
        StrType script;

        PackStream &write(PackStream &stream)
        {
            stream << value << script;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> value >> script;
            return stream;
        }
    };

    struct TxIDType_stream
    {
        IntType(32) version;
        ListType<TxInType_stream> tx_ins;
        ListType<TxOutType_stream> tx_outs;
        IntType(32) lock_time;

        TxIDType_stream() {}
        TxIDType_stream(int32_t _version, vector<TxInType> _tx_ins, vector<TxOutType> _tx_outs, int32_t _locktime)
        {
            version = _version;

            tx_ins = ListType<TxInType_stream>(ListType<TxInType_stream>::make_list_type(_tx_ins));
            tx_outs = ListType<TxOutType_stream>(ListType<TxOutType_stream>::make_list_type(_tx_outs));
            
            lock_time = _locktime;
        }

        PackStream &write(PackStream &stream)
        {
            stream << version << tx_ins << tx_outs << lock_time;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> version >> tx_ins >> tx_outs >> lock_time;
            return stream;
        }
    };

    struct WTXType
    {
        IntType(8) flag;
        ListType<TxInType_stream> tx_ins;
        ListType<TxOutType_stream> tx_outs;

        PackStream &write(PackStream &stream)
        {
            stream << flag << tx_ins << tx_outs;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> flag >> tx_ins >> tx_outs;
            return stream;
        }
    };

    struct NTXType
    {
        ListType<TxOutType_stream> tx_outs;
        IntType(32) lock_time;

        PackStream &write(PackStream &stream)
        {
            stream << tx_outs << lock_time;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> tx_outs >> lock_time;
            return stream;
        }
    };

    struct TxWriteType{
        IntType(32) version;
        IntType(8) marker;
        IntType(8) flag;
        ListType<TxInType_stream> tx_ins;
        ListType<TxOutType_stream> tx_outs;

        TxWriteType() {}
        TxWriteType(shared_ptr<WitnessTransactionType> tx);

        PackStream &write(PackStream &stream){
            stream << version << marker << flag << tx_ins << tx_outs;
            return stream;
        }

        PackStream &read(PackStream &stream){
            stream >> version >> marker >> flag >> tx_ins >> tx_outs;
            return stream;
        }
    };

#define WitnessType ListType<StrType>

    struct TransactionType_stream
    {
        std::shared_ptr<coind::data::TransactionType> tx;

        PackStream &write(PackStream &stream);

        PackStream &read(PackStream &stream)
        {
            IntType(32) version;
            stream >> version;

            VarIntType marker;
            stream >> marker;

            if (marker.value == 0)
            {
                WTXType next;
                stream >> next;

                vector<WitnessType> witness;
                for (int i = 0; i < next.tx_ins.l.size(); i++)
                {
                    WitnessType _wit;
                    stream >> _wit;
                    witness.push_back(_wit);
                }

                IntType(32) locktime;
                stream >> locktime;

                tx = std::make_shared<coind::data::WitnessTransactionType>(version.get(), marker.value, next.flag.value, next.tx_ins.l, next.tx_outs.l, witness, locktime.value);
            }
            else
            {
                vector<TxInType_stream> tx_ins;
                for (int i = 0; i < marker.value; i++)
                {
                    TxInType_stream tx_in;
                    stream >> tx_in;

                    tx_ins.push_back(tx_in);
                }

                NTXType next;
                stream >> next;
                tx = std::make_shared<coind::data::TransactionType>(version.get(), tx_ins, next.tx_outs.l, next.lock_time.value);
            }

            return stream;
        }
    };

#undef WitnessType
}

namespace coind::data
{
    struct PreviousOutput
    {
        uint256 hash;
        int32_t index;

        PreviousOutput()
        {
        }

        PreviousOutput(uint256 _hash, int32_t _index)
        {
            hash = _hash;
            index = _index;
        }

        PreviousOutput(stream::PreviousOutput_stream obj)
        {
            hash = obj.hash.value;
            index = obj.index.value;
        }
    };

    struct TxInType
    {
        PreviousOutput previous_output;
        string script;
        int32_t sequence;

        TxInType()
        {
            previous_output.hash.SetNull();
            previous_output.index = 4294967295;
            sequence = 4294967295;
        }

        TxInType(PreviousOutput _previous_output, char *_script, unsigned long _sequence)
        {
            previous_output = _previous_output;
            script = _script;
            sequence = _sequence;
        }

        TxInType(stream::TxInType_stream obj)
        {
            previous_output = PreviousOutput(obj.previous_output.get());
            script = obj.script.get();
            sequence = obj.sequence.get().value;
        }
    };

    struct TxOutType
    {
        int64_t value;
        string script;

        TxOutType()
        {
        }

        TxOutType(int64_t _value, string _script)
        {
            value = _value;
            script = _script;
        }

        TxOutType(stream::TxOutType_stream obj)
        {
            value = obj.value.value;
            script = obj.script.get();
        }
    };

    struct TxIDType
    {
        int32_t version;
        vector<TxInType> tx_ins;
        vector<TxOutType> tx_outs;
        int32_t lock_time;

        TxIDType() {}

        TxIDType(int32_t _version, vector<TxInType> _tx_ins, vector<TxOutType> _tx_outs, int32_t _locktime)
        {
            version = _version;
            tx_ins = _tx_ins;
            tx_outs = _tx_outs;
            lock_time = _locktime;
        }

        TxIDType(stream::TxIDType_stream obj)
        {
            version = obj.version.value;

            for (auto v : obj.tx_ins.l)
            {
                TxInType tx_in(v);
                tx_ins.push_back(tx_in);
            }

            for (auto v : obj.tx_outs.l)
            {
                TxOutType tx_out(v);
                tx_outs.push_back(tx_out);
            }

            lock_time = obj.lock_time.get();
        }
    };

    struct TransactionType
    {
        int32_t version;
        vector<TxInType> tx_ins;
        vector<TxOutType> tx_outs;
        int32_t lock_time;

        TransactionType() {}

        TransactionType(int32_t _version, vector<stream::TxInType_stream> _tx_ins, vector<stream::TxOutType_stream> _tx_outs, int32_t _locktime)
        {
            version = _version;

            for (auto v : _tx_ins)
            {
                TxInType tx_in(v);
                tx_ins.push_back(tx_in);
            }

            for (auto v : _tx_outs)
            {
                TxOutType tx_out(v);
                tx_outs.push_back(tx_out);
            }

            lock_time = _locktime;
        }
    };

    struct WitnessTransactionType : TransactionType
    {
        int8_t marker;
        int8_t flag;
        vector<vector<string>> witness;

        WitnessTransactionType() : TransactionType() {}

        WitnessTransactionType(int32_t _version, int8_t _marker, int8_t _flag, vector<stream::TxInType_stream> _tx_ins, vector<stream::TxOutType_stream> _tx_outs, vector<vector<StrType>> _witness, int32_t _locktime) : TransactionType(_version, _tx_ins, _tx_outs, _locktime)
        {
            marker = _marker;
            flag = _flag;

            for (auto v_list : _witness)
            {
                vector<string> _wit_tx;
                for (auto _v : v_list)
                {
                    _wit_tx.push_back(_v.get());
                }
                witness.push_back(_wit_tx);
            }
        }
    };
}
