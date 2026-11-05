// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// LTC transaction types: import generic primitives from bitcoin_family,
// extend Transaction/MutableTransaction with MWEB (serialization flag 0x08:
// a HogEx, or a tx carrying an mw::Transaction).

#include <impl/bitcoin_family/coin/base_transaction.hpp>
#include "mweb_tx_wire.hpp"

#include <core/pack.hpp>
#include <core/opscript.hpp>
#include <core/uint256.hpp>

namespace ltc
{

namespace coin
{

// Import generic transaction primitives from bitcoin_family
using bitcoin_family::coin::TxParams;
using bitcoin_family::coin::TX_WITH_WITNESS;
using bitcoin_family::coin::TX_NO_WITNESS;
using bitcoin_family::coin::TxPrevOut;
using bitcoin_family::coin::TxIn;
using bitcoin_family::coin::TxOut;

// Serialization modes (litecoind SERIALIZE_TRANSACTION_NO_WITNESS and
// SERIALIZE_NO_MWEB are independent bits; MWEB data is written only together
// with witnesses here):
//   TX_WITH_WITNESS  witness + MWEB  -- P2P, block bodies, template "data"
//   TX_NO_WITNESS    neither         -- txid
//   TX_WTXID         witness only    -- wtxid
constexpr static TxParams TX_WTXID {.allow_witness = true, .allow_mweb = false};

struct MutableTransaction;

class Transaction
{
public:
    // Default transaction version.
    static const int32_t CURRENT_VERSION = 2;

    std::vector<TxIn> vin;
    std::vector<TxOut> vout;
    int32_t version;
    uint32_t locktime;
    bool m_hogEx{false};  // MWEB HogEx indicator (memory-only, not in txid)
    // The serialized mw::Transaction this tx carries (litecoind mweb_tx);
    // empty = none. Relayed txs only: block transactions never carry one.
    std::vector<unsigned char> mweb_tx_raw;

private:
    bool m_has_witness;

    bool ComputeHasWitness() const;

public:
    /** Convert a MutableTransaction into a Transaction. */
    explicit Transaction(const MutableTransaction& tx) ;
    explicit Transaction(MutableTransaction&& tx);

    template <typename StreamType>
    inline void Serialize(StreamType& os) const
    {
        SerializeTransaction(*this, os, os.GetParams());
    }

    bool HasWitness() const { return m_has_witness; }
    bool HasMWEBTx() const { return !mweb_tx_raw.empty(); }
    /// MWEB-to-MWEB only: an MWEB part and no canonical inputs or outputs.
    bool IsMWEBOnly() const { return HasMWEBTx() && vin.empty() && vout.empty(); }
};

/** A mutable version of Transaction. */
struct MutableTransaction
{
    std::vector<TxIn> vin;
    std::vector<TxOut> vout;
    int32_t version;
    uint32_t locktime;
    bool m_hogEx{false};  // MWEB HogEx indicator (memory-only, not in txid)
    // The serialized mw::Transaction this tx carries (litecoind mweb_tx);
    // empty = none. Relayed txs only: block transactions never carry one.
    std::vector<unsigned char> mweb_tx_raw;

    explicit MutableTransaction();
    explicit MutableTransaction(const Transaction& tx);

    template <typename StreamType>
    inline void Serialize(StreamType& os) const
    {
        SerializeTransaction(*this, os, os.GetParams());
    }

    template <typename StreamType>
    inline void Unserialize(StreamType& os)
    {
        UnserializeTransaction(*this, os, os.GetParams());
    }

    bool HasWitness() const
    {
        for (size_t i = 0; i < vin.size(); i++)
        {
            if (!vin[i].scriptWitness.IsNull())
                return true;
        }
        return false;
    }

    bool HasMWEBTx() const { return !mweb_tx_raw.empty(); }
    /// MWEB-to-MWEB only: an MWEB part and no canonical inputs or outputs.
    bool IsMWEBOnly() const { return HasMWEBTx() && vin.empty() && vout.empty(); }
};

/**
 * Basic transaction serialization format:
 * - int32_t version
 * - std::vector<TxIn> vin
 * - std::vector<TxOut> vout
 * - uint32_t locktime
 *
 * Extended transaction serialization format:
 * - int32_t version
 * - unsigned char dummy = 0x00
 * - unsigned char flags (!= 0)
 * - std::vector<TxIn> vin
 * - std::vector<TxOut> vout
 * - if (flags & 1):
 *   - OPScriptWitness scriptWitness; (deserialized into TxIn)
 * - if (flags & 8):
 *   - uint8_t presence; 1 = an mw::Transaction follows, else none (HogEx)
 * - uint32_t locktime
 */
template<typename StreamType, typename TxType>
void UnserializeTransaction(TxType& tx, StreamType& s, const TxParams& params)
{
    const bool fAllowWitness = params.allow_witness;
    const bool fAllowMWEB = params.allow_witness && params.allow_mweb;

    s >> tx.version;
    unsigned char flags = 0;
    tx.vin.clear();
    tx.vout.clear();
    tx.mweb_tx_raw.clear();
    tx.m_hogEx = false;
    /* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
    s >> tx.vin;
    if (tx.vin.size() == 0 && fAllowWitness) 
    {
        /* We read a dummy or an empty vin. */
        s >> flags;
        if (flags != 0) 
        {
            s >> tx.vin;
            s >> tx.vout;
        }
    } else 
    {
        /* We read a non-empty vin. Assume a normal vout follows. */
        s >> tx.vout;
    }
    if ((flags & 1) && fAllowWitness) 
    {
        /* The witness flag is present, and we support witnesses. */
        flags ^= 1;
        for (size_t i = 0; i < tx.vin.size(); i++) 
        {
            s >> tx.vin[i].scriptWitness.stack;
        }
        if (!tx.HasWitness()) 
        {
            /* It's illegal to encode witnesses when all witness stacks are empty. */
            throw std::ios_base::failure("Superfluous witness record");
        }
    }

    if ((flags & 8) && fAllowMWEB)
    {
        /* The MWEB flag is present, and we support MWEB. */
        flags ^= 8;

        // MWEB::Tx is an OptionalPtr: the mw::Transaction follows only when
        // the presence byte is 1; any other value leaves it null
        // (serialize.h OptionalPtr::Unserialize), which makes a HogEx.
        unsigned char mweb_presence = 0;
        s >> mweb_presence;
        if (mweb_presence == 0x01) {
            // No length prefix anywhere: walk the grammar to its end, so the
            // locktime is read from the right offset, and keep the bytes.
            tx.mweb_tx_raw = mweb_wire::read_mw_transaction(s).raw;
        } else {
            if (tx.vout.empty()) {
                /* It's illegal to include a HogEx with no outputs. */
                throw std::ios_base::failure("Missing HogEx output");
            }
            tx.m_hogEx = true;
        }
    }

    if (flags) 
    {
        /* Unknown flag in the serialization */
        throw std::ios_base::failure("Unknown transaction optional data");
    }
    s >> tx.locktime;
}

template<typename StreamType, typename TxType>
void SerializeTransaction(const TxType& tx, StreamType& s, const TxParams& params)
{
    const bool fAllowWitness = params.allow_witness;
    const bool fAllowMWEB = params.allow_witness && params.allow_mweb;

    s << tx.version;
    unsigned char flags = 0;
    // Consistency check
    if (fAllowWitness)
    {
        /* Check whether witnesses need to be serialized. */
        if (tx.HasWitness())
        {
            flags |= 1;
        }
    }
    if (fAllowMWEB)
    {
        /* Check whether the MWEB flag needs to be serialized (HogEx or MWEB tx). */
        if (tx.m_hogEx || tx.HasMWEBTx())
        {
            flags |= 8;
        }
    }
    if (flags)
    {
        /* Use extended format in case witnesses or MWEB to be serialized. */
        std::vector<TxIn> vinDummy;
        s << vinDummy;
        s << flags;
    }
    s << tx.vin;
    s << tx.vout;
    if (flags & 1)
    {
        for (size_t i = 0; i < tx.vin.size(); i++)
        {
            s << tx.vin[i].scriptWitness.stack;
        }
    }
    if (flags & 8)
    {
        /* OptionalPtr: 0x01 + the mw::Transaction, or 0x00 (HogEx). */
        unsigned char presence = tx.HasMWEBTx() ? 0x01 : 0x00;
        s << presence;
        if (presence)
        {
            s.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(tx.mweb_tx_raw.data()), tx.mweb_tx_raw.size()));
        }
    }
    s << tx.locktime;
}

} // namespace coin

} // namespace ltc