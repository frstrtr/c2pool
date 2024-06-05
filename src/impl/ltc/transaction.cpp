#include "transaction.hpp"

namespace ltc
{

MutableTransaction::MutableTransaction() : version(Transaction::CURRENT_VERSION), locktime(0) {}
MutableTransaction::MutableTransaction(const Transaction& tx) : version(tx.version), vin(tx.vin), vout(tx.vout), locktime(tx.locktime) {}

// Transaction::Transaction(const MutableTransaction& tx) : vin(tx.vin), vout(tx.vout), version(tx.version), locktime(tx.locktime), m_has_witness{true} { } //, m_has_witness{ComputeHasWitness()}, hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
// Transaction(MutableTransaction&& tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), nVersion(tx.version), nLockTime(tx.locktime), m_has_witness{true} { }//m_has_witness{ComputeHasWitness()}, hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

} // namespace ltc