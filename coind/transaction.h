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
    struct TxInType;
    struct TxOutType;
    struct TxIDType;
}
namespace coind::data::stream
{
    struct PreviousOutput_stream;
    struct TxInType_stream;
    struct TxOutType_stream;
    struct TxIDType_stream;
    struct WTXType;
    struct NTXType;
    struct TxWriteType;
    struct TransactionType_stream;
}
//
//
//
//
//
//
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

        PreviousOutput(stream::PreviousOutput_stream obj);
    };

    struct TxInType
    {
        PreviousOutput previous_output;
        string script;
        int32_t sequence;

        TxInType();

        TxInType(PreviousOutput _previous_output, char *_script, unsigned long _sequence);

        TxInType(stream::TxInType_stream obj);
    };

    struct TxOutType
    {
        int64_t value;
        string script;

        TxOutType() = default;

        TxOutType(int64_t _value, string _script);

        TxOutType(stream::TxOutType_stream obj);
    };

    struct TxIDType
    {
        int32_t version;
        vector<TxInType> tx_ins;
        vector<TxOutType> tx_outs;
        int32_t lock_time;

        TxIDType() = default;

        TxIDType(int32_t _version, vector<TxInType> _tx_ins, vector<TxOutType> _tx_outs, int32_t _locktime);

        TxIDType(stream::TxIDType_stream obj);
    };

    struct TransactionType
    {
        uint32_t version;
        vector<TxInType> tx_ins;
        vector<TxOutType> tx_outs;
        uint32_t lock_time;

        TransactionType() = default;

        TransactionType(uint32_t _version, vector<stream::TxInType_stream> _tx_ins, vector<stream::TxOutType_stream> _tx_outs, uint32_t _locktime);
    };

    struct WitnessTransactionType : TransactionType
    {

        uint64_t marker{};
        //TODO:?
        // int8_t marker{};
        uint8_t flag{};
        vector<vector<string>> witness;

        WitnessTransactionType() : TransactionType() {}

        WitnessTransactionType(uint32_t _version, uint64_t _marker, uint8_t _flag, vector<stream::TxInType_stream> _tx_ins, vector<stream::TxOutType_stream> _tx_outs, vector<ListType<StrType>> _witness, uint32_t _locktime);
    };

    typedef shared_ptr<TransactionType> tx_type;
}

namespace coind::data::stream
{
    using namespace coind::data;

    struct PreviousOutput_stream : public Maker<PreviousOutput_stream, PreviousOutput>
    {
        IntType(256) hash;
        IntType(32) index;

        PreviousOutput_stream() = default;
        PreviousOutput_stream(PreviousOutput val)
        {
            hash = IntType(256)::make_type(val.hash);
            index = IntType(32)::make_type(val.index);
        }

        PackStream &write(PackStream &stream);
        PackStream &read(PackStream &stream);
    };

    struct TxInType_stream : public Maker<TxInType_stream, TxInType>
    {
        PossibleNoneType<PreviousOutput_stream> previous_output;
        StrType script;
        PossibleNoneType<IntType(32)> sequence;

        TxInType_stream() = default;
        TxInType_stream(TxInType val)
        {
            previous_output = PossibleNoneType<PreviousOutput_stream>(PreviousOutput_stream::make_type(val.previous_output));
            script = StrType::make_type(val.script);
            sequence = sequence.make_type(val.sequence);
        }

        PackStream &write(PackStream &stream);
        PackStream &read(PackStream &stream);
    };

    struct TxOutType_stream : public Maker<TxOutType_stream, TxOutType>
    {
        IntType(64) value;
        StrType script;

        TxOutType_stream() = default;
        TxOutType_stream(TxOutType val)
        {
            value = IntType(64)::make_type(val.value);
            script = StrType::make_type(val.script);
        }

        PackStream &write(PackStream &stream);
        PackStream &read(PackStream &stream);
    };

    struct TxIDType_stream : public Maker<TxIDType_stream, TxIDType>
    {
        IntType(32) version;
        ListType<TxInType_stream> tx_ins;
        ListType<TxOutType_stream> tx_outs;
        IntType(32) lock_time;

        TxIDType_stream() = default;
        TxIDType_stream(int32_t _version, vector<TxInType> _tx_ins, vector<TxOutType> _tx_outs, int32_t _locktime);
        TxIDType_stream(TxIDType val)
        {
            version = IntType(32)::make_type(val.version);
            tx_ins = tx_ins.make_type(val.tx_ins);
            tx_outs = tx_outs.make_type(val.tx_outs);
            lock_time = IntType(32)::make_type(val.lock_time);
        }

        PackStream &write(PackStream &stream);

        PackStream &read(PackStream &stream);
    };

    struct WTXType
    {
        IntType(8) flag;
        ListType<TxInType_stream> tx_ins;
        ListType<TxOutType_stream> tx_outs;

        PackStream &write(PackStream &stream);

        PackStream &read(PackStream &stream);
    };

    struct NTXType
    {
        ListType<TxOutType_stream> tx_outs;
        IntType(32) lock_time;

        PackStream &write(PackStream &stream);

        PackStream &read(PackStream &stream);
    };

    struct TxWriteType
    {
        IntType(32) version;
        IntType(8) marker;
        IntType(8) flag;
        ListType<TxInType_stream> tx_ins;
        ListType<TxOutType_stream> tx_outs;

        TxWriteType() {}
        TxWriteType(shared_ptr<WitnessTransactionType> tx);

        PackStream &write(PackStream &stream);

        PackStream &read(PackStream &stream);
    };

#define WitnessType ListType<StrType>

    struct TransactionType_stream // : public Maker<TransactionType_stream, TransactionType>
    {
        std::shared_ptr<coind::data::TransactionType> tx;

        TransactionType_stream() = default;
        //TODO:
        // TransactionType_stream(TransactionType val){
        //     tx = std::make_shared
        // }

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

                vector<WitnessType> _witness;
                for (int i = 0; i < next.tx_ins.l.size(); i++)
                {
                    WitnessType _wit;
                    stream >> _wit;
                    _witness.push_back(_wit);
                }

                IntType(32) locktime;
                stream >> locktime;

                //coind::data::TransactionType* test_tx = new coind::data::TransactionType(version.get(), marker.value, next.flag.value, next.tx_ins.l, next.tx_outs.l, witness, locktime.value);

                tx = std::make_shared<coind::data::WitnessTransactionType>(version.get(), marker.value, next.flag.value, next.tx_ins.l, next.tx_outs.l, _witness, locktime.value);
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
