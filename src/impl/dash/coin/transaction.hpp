#pragma once

// Dash transaction types: standard Bitcoin transactions + DIP3/DIP4 CBTX support.
// No MWEB, no HogEx. Has extra_payload for coinbase special transactions (type=5).

#include <impl/bitcoin_family/coin/base_transaction.hpp>

#include <core/pack.hpp>
#include <core/opscript.hpp>
#include <core/uint256.hpp>

#include <optional>
#include <vector>

namespace dash
{
namespace coin
{

// Import generic tx primitives from bitcoin_family
using bitcoin_family::coin::TxParams;
using bitcoin_family::coin::TX_WITH_WITNESS;
using bitcoin_family::coin::TX_NO_WITNESS;
using bitcoin_family::coin::TxPrevOut;
using bitcoin_family::coin::TxIn;
using bitcoin_family::coin::TxOut;

// Dash transaction type field (nType in serialization)
// type=0: standard, type=5: CBTX (coinbase with DIP3/DIP4 payload)
struct MutableTransaction
{
    std::vector<TxIn> vin;
    std::vector<TxOut> vout;
    int32_t version{1};
    uint16_t type{0};           // Dash-specific: transaction type
    uint32_t locktime{0};
    std::vector<unsigned char> extra_payload; // DIP3/DIP4 payload (for type=5 CBTX)

    MutableTransaction() = default;

    bool HasWitness() const { return false; } // Dash has no segwit

    template <typename StreamType>
    void Serialize(StreamType& s) const
    {
        // Dash uses version | (type << 16) in the version field
        int32_t version_with_type = version | (static_cast<int32_t>(type) << 16);
        s << version_with_type;
        s << vin;
        s << vout;
        s << locktime;
        // Extra payload for special transactions (CBTX type=5)
        if (type != 0 && !extra_payload.empty()) {
            BaseScript ep;
            ep.m_data = extra_payload;
            s << ep;
        }
    }

    template <typename StreamType>
    void Unserialize(StreamType& s)
    {
        int32_t version_with_type;
        s >> version_with_type;
        version = version_with_type & 0xFFFF;
        type = static_cast<uint16_t>((version_with_type >> 16) & 0xFFFF);
        s >> vin;
        s >> vout;
        s >> locktime;
        // Read extra payload for special transactions
        extra_payload.clear();
        if (type != 0) {
            BaseScript ep;
            s >> ep;
            extra_payload = std::move(ep.m_data);
        }
    }
};

// Immutable transaction (for txid computation — non-witness serialization)
class Transaction
{
public:
    static const int32_t CURRENT_VERSION = 1;

    std::vector<TxIn> vin;
    std::vector<TxOut> vout;
    int32_t version{1};
    uint16_t type{0};
    uint32_t locktime{0};
    std::vector<unsigned char> extra_payload;

    explicit Transaction(const MutableTransaction& tx)
        : vin(tx.vin), vout(tx.vout), version(tx.version),
          type(tx.type), locktime(tx.locktime), extra_payload(tx.extra_payload) {}

    bool HasWitness() const { return false; }
};

} // namespace coin
} // namespace dash
