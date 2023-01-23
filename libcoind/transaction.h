#pragma once

#include <vector>
#include <memory>
#include <string>

#include "univalue.h"
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>
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

namespace coind::data
{
    struct PreviousOutput
    {
        uint256 hash;
        uint32_t index;

        PreviousOutput()
        {
            hash.SetHex("0");
            index = 4294967295;
        }

        PreviousOutput(uint256 _hash, int32_t _index)
        {
            hash = _hash;
            index = _index;
        }

        PreviousOutput(stream::PreviousOutput_stream obj);

        friend std::ostream &operator<<(std::ostream &stream, PreviousOutput &value)
        {
            stream << "(PreviousOutput: ";
            stream << "hash = " << value.hash;
            stream << ", index = " << value.index;
            stream << ")";

            return stream;
        }
    };

    struct TxInType
    {
        PreviousOutput previous_output;
		std::vector<unsigned char> script;
        uint32_t sequence;

        TxInType();

        TxInType(PreviousOutput _previous_output, std::vector<unsigned char> _script, unsigned long _sequence);

        TxInType(std::shared_ptr<stream::TxInType_stream> obj);

        friend std::ostream &operator<<(std::ostream &stream, TxInType &value)
        {
            stream << "(TxInType: ";
            stream << "previous_output = " << value.previous_output;
            stream << ", script = " << value.script;
            stream << ", sequence = " << value.sequence;
            stream << ")";

            return stream;
        }
    };

    struct TxOutType
    {
        int64_t value;
        std::vector<unsigned char> script;

        TxOutType() = default;

        TxOutType(int64_t _value, std::vector<unsigned char> _script);

        TxOutType(std::shared_ptr<stream::TxOutType_stream> obj);

        friend std::ostream &operator<<(std::ostream &stream, TxOutType &_value)
        {
            stream << "(TxOutType: ";
            stream << "value = " << _value.value;
            stream << ", script = " << _value.script;
            stream << ")";

            return stream;
        }
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

    struct WitnessTransactionData
    {
        uint64_t marker;
        uint8_t flag;
        vector<vector<std::string>> witness;

        WitnessTransactionData() {}

        WitnessTransactionData(uint64_t _marker, uint8_t _flag, vector<vector<string>> _witness)
        {
            marker = _marker;
            flag = _flag;
            witness = _witness;
        }

        WitnessTransactionData(uint64_t _marker, uint8_t _flag, vector<ListType<StrType>> _witness)
        {
            marker = _marker;
            flag = _flag;

            for (auto v_list : _witness)
            {
                vector<string> _wit_tx;
                for (auto _v : v_list.value)
                {
                    _wit_tx.push_back(_v.get());
                }
                witness.push_back(_wit_tx);
            }
        }

        friend std::ostream &operator<<(std::ostream &stream, WitnessTransactionData &value)
        {
            stream << "(WitnessTransactionData: ";
            stream << "marker = " << value.marker;
            stream << ", flag = " << value.flag;
            stream << ", flag = " << value.flag;
            stream << ", witness = " << value.witness;
            stream << ")";

            return stream;
        }
    };

    struct TransactionType
    {
        uint32_t version{};
        vector<TxInType> tx_ins;
        vector<TxOutType> tx_outs;
        uint32_t lock_time{};
        std::optional<WitnessTransactionData> wdata;

        TransactionType() = default;

        virtual ~TransactionType() {}

        TransactionType(uint32_t _version, vector<TxInType> _tx_ins, vector<TxOutType> _tx_outs, uint32_t _locktime, std::optional<WitnessTransactionData> _wdata = std::nullopt)
        {
            version = _version;
            tx_ins = _tx_ins;
            tx_outs = _tx_outs;
            lock_time = _locktime;
            wdata = _wdata;
        }

        friend std::ostream &operator<<(std::ostream &stream, const std::shared_ptr<TransactionType>& _tx)
        {
            stream << "(TxType: ";

            if (!_tx)
            {
                stream << "null)";
                return stream;
            }

            stream << "version = " << _tx->version;
            stream << ", tx_ins = " << _tx->tx_ins;
            stream << ", tx_outs = " << _tx->tx_outs;
            stream << ", lock_time = " << _tx->lock_time;
            if (_tx->wdata.has_value())
            {
                stream << ", wdata = " << _tx->wdata.value();
            } else {
                stream << ", wdata = null";
            }
            stream << ")";

            return stream;
        }
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

    struct TxInType_stream : public Maker<TxInType_stream, TxInType>
    {
        PossibleNoneType<PreviousOutput_stream> previous_output;
        StrType script;
        PossibleNoneType<IntType(32)> sequence;

        TxInType_stream() : previous_output(PreviousOutput_stream(PreviousOutput())), sequence(IntType(32)(4294967295)) {

        }
        TxInType_stream(TxInType val) : TxInType_stream() {
            previous_output = PossibleNoneType<PreviousOutput_stream>(PreviousOutput_stream::make_type(val.previous_output));
            script = StrType::make_type(val.script);
            sequence = sequence.make_type(val.sequence);
        }

        PackStream &write(PackStream &stream)
        {
            stream << previous_output << script << sequence;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> previous_output;
			stream >> script;
			stream >> sequence;
            return stream;
        }
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

        PackStream &write(PackStream &stream)
        {
            stream << flag << tx_ins << tx_outs;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
			//bug here
			stream >> flag;
			stream >> tx_ins;
			stream >> tx_outs;
//            stream >> flag >> tx_ins >> tx_outs;
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

    struct TxWriteType
    {
        IntType(32) version;
        IntType(8) marker;
        IntType(8) flag;
        ListType<TxInType_stream> tx_ins;
        ListType<TxOutType_stream> tx_outs;

        TxWriteType() {}
        TxWriteType(shared_ptr<TransactionType> tx);

        PackStream &write(PackStream &stream);

        PackStream &read(PackStream &stream);
    };

#define WitnessType ListType<StrType>

    struct TransactionType_stream : CustomGetter<std::shared_ptr<TransactionType>>, public Maker<TransactionType_stream, tx_type>
    {
        std::shared_ptr<coind::data::TransactionType> tx;

        TransactionType_stream() = default;

        TransactionType_stream(coind::data::tx_type val)
        {
            tx = val;
        }

        std::shared_ptr<TransactionType> get() const override
        {
            return tx;
        }

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
                for (int i = 0; i < next.tx_ins.value.size(); i++)
                {
                    WitnessType _wit;
                    stream >> _wit;
                    _witness.push_back(_wit);
                }

                IntType(32) locktime;
                stream >> locktime;

                vector<TxInType> tx_ins;
                for (auto tx_in_stream : next.tx_ins.value)
                {
                    auto ptr_tx_in = make_shared<coind::data::stream::TxInType_stream>(tx_in_stream);
                    TxInType tx_in(ptr_tx_in);
                    tx_ins.push_back(tx_in);
                }

                vector<TxOutType> tx_outs;
                for (auto tx_out_stream : next.tx_outs.value)
                {
                    auto ptr_tx_out = make_shared<coind::data::stream::TxOutType_stream>(tx_out_stream);
                    TxOutType tx_out(ptr_tx_out);
                    tx_outs.push_back(tx_out);
                }

                tx = std::make_shared<coind::data::TransactionType>(version.get(), tx_ins, tx_outs, locktime.value, std::make_optional<WitnessTransactionData>(marker.value, next.flag.value, _witness));
            }
            else
            {
                vector<TxInType> tx_ins;
                for (int i = 0; i < marker.value; i++)
                {
                    TxInType_stream tx_in_stream;
                    stream >> tx_in_stream;

                    auto ptr_tx_in = make_shared<coind::data::stream::TxInType_stream>(tx_in_stream);
                    TxInType tx_in(ptr_tx_in);
                    tx_ins.push_back(tx_in);
                }

                NTXType next;
                stream >> next;

                vector<TxOutType> tx_outs;
                for (auto tx_out_stream : next.tx_outs.value)
                {
                    auto ptr_tx_out = make_shared<coind::data::stream::TxOutType_stream>(tx_out_stream);
                    TxOutType tx_out(ptr_tx_out);
                    tx_outs.push_back(tx_out);
                }

                tx = std::make_shared<coind::data::TransactionType>(version.get(), tx_ins, tx_outs, next.lock_time.value);
            }

            return stream;
        }
    };

#undef WitnessType
}
