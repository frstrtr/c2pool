#include "transaction.hpp"

// bch::coin transaction ctors -- ported from src/impl/btc/coin/transaction.cpp.
// BCH has no SegWit, so there is no ComputeHasWitness()/m_has_witness (M1 §4.1).

namespace bch
{

namespace coin
{

Transaction::Transaction(const MutableTransaction& tx)
    : vin(tx.vin), vout(tx.vout), version(tx.version), locktime(tx.locktime) {}
Transaction::Transaction(MutableTransaction&& tx)
    : vin(std::move(tx.vin)), vout(std::move(tx.vout)), version(tx.version), locktime(tx.locktime) {}

MutableTransaction::MutableTransaction()
    : version(Transaction::CURRENT_VERSION), locktime(0) {}
MutableTransaction::MutableTransaction(const Transaction& tx)
    : vin(tx.vin), vout(tx.vout), version(tx.version), locktime(tx.locktime) {}

} // namespace coin

} // namespace bch
