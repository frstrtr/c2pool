#include "transaction.h"
#include "data.h"

namespace coind::data::stream
{
    TxWriteType::TxWriteType(std::shared_ptr<WitnessTransactionType> tx)
    {
        version.set(tx->version);
        marker.set(tx->marker);
        flag.set(tx->flag);
        tx_ins = ListType<TxInType_stream>::make_list_type(tx->tx_ins);
        tx_outs = ListType<TxOutType_stream>::make_list_type(tx->tx_outs);
    }

#define WitnessType ListType<StrType>
    PackStream &TransactionType_stream::write(PackStream &stream)
    {
        if (is_segwit_tx(tx))
        {
            auto _tx = std::dynamic_pointer_cast<WitnessTransactionType>(tx);

            assert(_tx->tx_ins.size() == _tx->witness.size());
            TxWriteType write_tx(_tx);
            stream << write_tx;

            for (auto v : _tx->witness)
            {
                WitnessType _witness;
                _witness = WitnessType::make_list_type(v);
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

#undef WitnessType
}