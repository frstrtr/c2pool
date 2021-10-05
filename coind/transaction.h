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
}

namespace coind::data::stream
{
    using namespace coind::data;

    struct PreviousOutput_stream
    {
        IntType(256) hash;
        IntType(32) index;

        PackStream &write(PackStream &stream);

        PackStream &read(PackStream &stream);
    };

    struct TxInType_stream
    {
        PossibleNoneType<PreviousOutput_stream> previous_output;
        StrType script;
        PossibleNoneType<IntType(32)> sequence;

        PackStream &write(PackStream &stream);

        PackStream &read(PackStream &stream);
    };

    struct TxOutType_stream
    {
        IntType(64) value;
        StrType script;

        PackStream &write(PackStream &stream);

        PackStream &read(PackStream &stream);
    };

    struct TxIDType_stream
    {
        IntType(32) version;
        ListType<TxInType_stream> tx_ins;
        ListType<TxOutType_stream> tx_outs;
        IntType(32) lock_time;

        TxIDType_stream() {}
        TxIDType_stream(int32_t _version, vector<TxInType> _tx_ins, vector<TxOutType> _tx_outs, int32_t _locktime);

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

    struct TxWriteType{
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

    struct TransactionType_stream
    {
        std::shared_ptr<coind::data::TransactionType> tx;

        PackStream &write(PackStream &stream);

        PackStream &read(PackStream &stream);
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
        int32_t version;
        vector<TxInType> tx_ins;
        vector<TxOutType> tx_outs;
        int32_t lock_time;

        TransactionType() = default;

        TransactionType(int32_t _version, vector<stream::TxInType_stream> _tx_ins, vector<stream::TxOutType_stream> _tx_outs, int32_t _locktime);
    };

    struct WitnessTransactionType : TransactionType
    {
        int8_t marker{};
        int8_t flag{};
        vector<vector<string>> witness;

        WitnessTransactionType() : TransactionType() {}

        WitnessTransactionType(int32_t _version, int8_t _marker, int8_t _flag, vector<stream::TxInType_stream> _tx_ins, vector<stream::TxOutType_stream> _tx_outs, vector<vector<StrType>> _witness, int32_t _locktime);
    };

    typedef shared_ptr<TransactionType> tx_type;
}
