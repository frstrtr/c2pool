#include "transaction.h"
#include "data.h"

namespace coind::data::stream
{
#define WitnessType ListType<StrType>
    PackStream &TransactionType_stream::write(PackStream &stream)
    {
        if (is_segwit_tx(tx))
        {
            auto _tx = std::static_pointer_cast<WitnessTransactionType>(tx);

            assert(_tx->tx_ins.size() == _tx->witness.size());
            TxWriteType write_tx(_tx);
            stream << write_tx;

            for (auto v : _tx->witness)
            {
                WitnessType _witness;
                _witness = WitnessType::make_type(v);
                stream << _witness;
            }

            IntType(32) _locktime(_tx->lock_time);
            stream << _locktime;
            return stream;
        }
        TxIDType_stream tx_id(tx->version, tx->tx_ins, tx->tx_outs, tx->lock_time);
        stream << tx_id;
        return stream;
    }

    PackStream &TransactionType_stream::read(PackStream &stream)
    {
        IntType(32) version;
        stream >> version;

        VarIntType marker;
        stream >> marker;

        if (marker.value == 0)
        {
            WTXType next;
            stream >> next;

            //vector<WitnessType> _witness;
            vector<vector<StrType>>
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

#undef WitnessType

    PackStream &PreviousOutput_stream::write(PackStream &stream)
    {
        stream << hash << index;
        return stream;
    }

    PackStream &PreviousOutput_stream::read(PackStream &stream)
    {
        stream >> hash >> index;
        return stream;
    }

    PackStream &TxInType_stream::write(PackStream &stream)
    {
        stream << previous_output << script << sequence;
        return stream;
    }

    PackStream &TxInType_stream::read(PackStream &stream)
    {
        stream >> previous_output >> script >> sequence;
        return stream;
    }

    PackStream &TxOutType_stream::write(PackStream &stream)
    {
        stream << value << script;
        return stream;
    }

    PackStream &TxOutType_stream::read(PackStream &stream)
    {
        stream >> value >> script;
        return stream;
    }

    TxIDType_stream::TxIDType_stream(int32_t _version, vector<TxInType> _tx_ins, vector<TxOutType> _tx_outs,
                                     int32_t _locktime)
    {
        version = _version;

        tx_ins = ListType<TxInType_stream>(ListType<TxInType_stream>::make_type(_tx_ins));
        tx_outs = ListType<TxOutType_stream>(ListType<TxOutType_stream>::make_type(_tx_outs));

        lock_time = _locktime;
    }

    PackStream &TxIDType_stream::write(PackStream &stream)
    {
        stream << version << tx_ins << tx_outs << lock_time;
        return stream;
    }

    PackStream &TxIDType_stream::read(PackStream &stream)
    {
        stream >> version >> tx_ins >> tx_outs >> lock_time;
        return stream;
    }

    PackStream &WTXType::write(PackStream &stream)
    {
        stream << flag << tx_ins << tx_outs;
        return stream;
    }

    PackStream &WTXType::read(PackStream &stream)
    {
        stream >> flag >> tx_ins >> tx_outs;
        return stream;
    }

    PackStream &NTXType::write(PackStream &stream)
    {
        stream << tx_outs << lock_time;
        return stream;
    }

    PackStream &NTXType::read(PackStream &stream)
    {
        stream >> tx_outs >> lock_time;
        return stream;
    }

    TxWriteType::TxWriteType(std::shared_ptr<WitnessTransactionType> tx)
    {
        version.set(tx->version);
        marker.set(tx->marker);
        flag.set(tx->flag);
        tx_ins = ListType<TxInType_stream>::make_type(tx->tx_ins);
        tx_outs = ListType<TxOutType_stream>::make_type(tx->tx_outs);
    }

    PackStream &TxWriteType::write(PackStream &stream)
    {
        stream << version << marker << flag << tx_ins << tx_outs;
        return stream;
    }

    PackStream &TxWriteType::read(PackStream &stream)
    {
        stream >> version >> marker >> flag >> tx_ins >> tx_outs;
        return stream;
    }
}

coind::data::WitnessTransactionType::WitnessTransactionType(uint32_t _version, uint64_t _marker, uint8_t _flag, vector<stream::TxInType_stream> _tx_ins, vector<stream::TxOutType_stream> _tx_outs, vector<vector<StrType>> _witness, uint32_t _locktime) : TransactionType(_version, _tx_ins, _tx_outs, _locktime)
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

coind::data::TransactionType::TransactionType(uint32_t _version, vector<stream::TxInType_stream> _tx_ins, vector<stream::TxOutType_stream> _tx_outs, uint32_t _locktime)
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

coind::data::TxIDType::TxIDType(int32_t _version, vector<TxInType> _tx_ins, vector<TxOutType> _tx_outs,
                                int32_t _locktime)
{
    version = _version;
    tx_ins = _tx_ins;
    tx_outs = _tx_outs;
    lock_time = _locktime;
}

coind::data::TxIDType::TxIDType(coind::data::stream::TxIDType_stream obj)
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

coind::data::TxOutType::TxOutType(int64_t _value, string _script)
{
    value = _value;
    script = _script;
}

coind::data::TxOutType::TxOutType(coind::data::stream::TxOutType_stream obj)
{
    value = obj.value.value;
    script = obj.script.get();
}

coind::data::TxInType::TxInType()
{
    previous_output.hash.SetNull();
    previous_output.index = 4294967295;
    sequence = 4294967295;
}

coind::data::TxInType::TxInType(coind::data::PreviousOutput _previous_output, char *_script, unsigned long _sequence)
{
    previous_output = _previous_output;
    script = _script;
    sequence = _sequence;
}

coind::data::TxInType::TxInType(coind::data::stream::TxInType_stream obj)
{
    previous_output = PreviousOutput(obj.previous_output.get());
    script = obj.script.get();
    sequence = obj.sequence.get().value;
}

coind::data::PreviousOutput::PreviousOutput(coind::data::stream::PreviousOutput_stream obj)
{
    hash = obj.hash.value;
    index = obj.index.value;
}
