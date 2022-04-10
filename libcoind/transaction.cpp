#include "transaction.h"
#include "data.h"

namespace coind::data::stream
{
#define WitnessType ListType<StrType>
    PackStream &TransactionType_stream::write(PackStream &stream)
    {
        if (is_segwit_tx(tx))
        {
            assert(tx->tx_ins.size() == tx->wdata->witness.size());
            TxWriteType write_tx(tx);
            stream << write_tx;

            for (auto v : tx->wdata->witness)
            {
                WitnessType _witness;
                _witness = WitnessType::make_type(v);
                stream << _witness;
            }

            IntType(32) _locktime(tx->lock_time);
            stream << _locktime;
            return stream;
        }
        TxIDType_stream tx_id(tx->version, tx->tx_ins, tx->tx_outs, tx->lock_time);
        stream << tx_id;
        return stream;
    }

#undef WitnessType

    TxIDType_stream::TxIDType_stream(int32_t _version, vector<TxInType> _tx_ins, vector<TxOutType> _tx_outs,
                                     int32_t _locktime)
    {
        version = _version;

        tx_ins = ListType<TxInType_stream>(ListType<TxInType_stream>::make_type(_tx_ins));
        std::cout << "TXIDType_stream.script: ";
        for (auto v : tx_ins.value[0].script.value){
            std::cout << (unsigned int) v << " ";
        }
        std::cout << std::endl;

        tx_outs = ListType<TxOutType_stream>(ListType<TxOutType_stream>::make_type(_tx_outs));

        lock_time = _locktime;
    }

    PackStream &TxIDType_stream::write(PackStream &stream)
    {
        stream << version << tx_ins << tx_outs << lock_time;

        //======================================================
//        stream << version;
//        std::cout << "TXIDType_stream.write.stream[version]: ";
//        for (auto v : stream.data){
//            std::cout << (unsigned int) v << " ";
//        }
//        std::cout << std::endl;

//        stream << tx_ins.l[0].script;
//        std::cout << "TXIDType_stream.write.stream[tx_ins.script]:  ";
//        for (auto v : stream.data){
//            std::cout << (unsigned int) v << " ";
//        }
//        std::cout << std::endl;
//
//        std::cout << "TXIDType_stream.write.stream[tx_ins.script.value]:  ";
//        for (auto v : tx_ins.l[0].script.value){
//            std::cout << (unsigned int) v << " ";
//        }
//        std::cout << std::endl;
//
//
//        stream << tx_outs;
//        std::cout << "TXIDType_stream.write.stream[tx_outs]: ";
//        for (auto v : stream.data){
//            std::cout << (unsigned int) v << " ";
//        }
//        std::cout << std::endl;
//
//        stream << lock_time;
//        std::cout << "TXIDType_stream.write.stream[lock_time]: ";
//        for (auto v : stream.data){
//            std::cout << (unsigned int) v << " ";
//        }
//        std::cout << std::endl;

        return stream;
    }

    PackStream &TxIDType_stream::read(PackStream &stream)
    {
        stream >> version >> tx_ins >> tx_outs >> lock_time;
        return stream;
    }

    TxWriteType::TxWriteType(std::shared_ptr<TransactionType> tx)
    {
        version.set(tx->version);
        marker.set(tx->wdata->marker);
        flag.set(tx->wdata->flag);
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

// #define WitnessType ListType<StrType>
//     PackStream &TransactionType_stream::read(PackStream &stream)
//     {
//         IntType(32) version;
//         stream >> version;

//         VarIntType marker;
//         stream >> marker;

//         if (marker.value == 0)
//         {
//             WTXType next;
//             stream >> next;

//             vector<WitnessType> _witness;
//             for (int i = 0; i < next.tx_ins.l.size(); i++)
//             {
//                 WitnessType _wit;
//                 stream >> _wit;
//                 _witness.push_back(_wit);
//             }

//             IntType(32) locktime;
//             stream >> locktime;

//             vector<TxInType> tx_ins;
//             for (auto tx_in_stream : next.tx_ins.l)
//             {
//                 auto ptr_tx_in = make_shared<coind::data::stream::TxInType_stream>(tx_in_stream);
//                 TxInType tx_in(ptr_tx_in);
//                 tx_ins.push_back(tx_in);
//             }

//             vector<TxOutType> tx_outs;
//             for (auto tx_out_stream : next.tx_outs.l)
//             {
//                 auto ptr_tx_out = make_shared<coind::data::stream::TxOutType_stream>(tx_out_stream);
//                 TxOutType tx_out(ptr_tx_out);
//                 tx_outs.push_back(tx_out);
//             }

//             tx = std::make_shared<coind::data::WitnessTransactionType>(version.get(), marker.value, next.flag.value, tx_ins, tx_outs, _witness, locktime.value);
//         }
//         else
//         {
//             vector<TxInType> tx_ins;
//             for (int i = 0; i < marker.value; i++)
//             {
//                 TxInType_stream tx_in_stream;
//                 stream >> tx_in_stream;

//                 auto ptr_tx_in = make_shared<coind::data::stream::TxInType_stream>(tx_in_stream);
//                 TxInType tx_in(ptr_tx_in);
//                 tx_ins.push_back(tx_in);
//             }

//             NTXType next;
//             stream >> next;

//             vector<TxOutType> tx_outs;
//             for (auto tx_out_stream : next.tx_outs.l)
//             {
//                 auto ptr_tx_out = make_shared<coind::data::stream::TxOutType_stream>(tx_out_stream);
//                 TxOutType tx_out(ptr_tx_out);
//                 tx_outs.push_back(tx_out);
//             }

//             tx = std::make_shared<coind::data::TransactionType>(version.get(), tx_ins, tx_outs, next.lock_time.value);
//         }

//         return stream;
//     }
// #undef WitnessType
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

    for (auto v : obj.tx_ins.value)
    {
        auto ptr_tx_in = make_shared<coind::data::stream::TxInType_stream>(v);
        TxInType tx_in(ptr_tx_in);
        tx_ins.push_back(tx_in);
    }

    for (auto v : obj.tx_outs.value)
    {
        auto ptr_tx_out = make_shared<coind::data::stream::TxOutType_stream>(v);
        TxOutType tx_out(ptr_tx_out);
        tx_outs.push_back(tx_out);
    }

    lock_time = obj.lock_time.get();
}

coind::data::TxOutType::TxOutType(int64_t _value, std::vector<unsigned char> _script)
{
    value = _value;
//    script = std::vector<unsigned char>(_script, _script + (strlen((char*)_script))-1);
    script = _script;
}

coind::data::TxOutType::TxOutType(std::shared_ptr<stream::TxOutType_stream> obj)
{
    value = obj->value.value;
    script = obj->script.value;
}

coind::data::TxInType::TxInType()
{
    previous_output.hash.SetNull();
    previous_output.index = 4294967295;
    sequence = 4294967295;
}

coind::data::TxInType::TxInType(coind::data::PreviousOutput _previous_output, std::vector<unsigned char> _script, unsigned long _sequence)
{
    previous_output = _previous_output;
    //script = std::vector<unsigned char>(_script, _script + (strlen((char*)_script))-1);
    script = _script;
    sequence = _sequence;
}

coind::data::TxInType::TxInType(std::shared_ptr<coind::data::stream::TxInType_stream> obj)
{
    previous_output = PreviousOutput(obj->previous_output.get());
    script = obj->script.value;
    sequence = obj->sequence.get();
}

coind::data::PreviousOutput::PreviousOutput(coind::data::stream::PreviousOutput_stream obj)
{
    hash = obj.hash.value;
    index = obj.index.value;
}
