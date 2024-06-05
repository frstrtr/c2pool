#include "transaction.hpp"

namespace ltc
{

Transaction::Transaction(const MutableTransaction& tx) : vin(tx.vin), vout(tx.vout), version(tx.version), locktime(tx.locktime), m_has_witness{ComputeHasWitness()} {} //, hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
Transaction::Transaction(MutableTransaction&& tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), version(tx.version), locktime(tx.locktime), m_has_witness{ComputeHasWitness()} {} // , hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

bool Transaction::ComputeHasWitness() const
{
    return std::any_of(vin.begin(), vin.end(), [](const auto& input) {
        return !input.scriptWitness.IsNull();
    });
}

MutableTransaction::MutableTransaction() : version(Transaction::CURRENT_VERSION), locktime(0) {}
MutableTransaction::MutableTransaction(const Transaction& tx) : version(tx.version), vin(tx.vin), vout(tx.vout), locktime(tx.locktime) {}

} // namespace ltc