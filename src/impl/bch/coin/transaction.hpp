// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <core/pack.hpp>
#include <core/opscript.hpp>
#include <core/uint256.hpp>

// ---------------------------------------------------------------------------
// bch::coin transaction -- ported from src/impl/btc/coin/transaction.hpp.
//
// >>> BCH DIVERGENCE (M1 §4.1): NO SegWit <<<
// Bitcoin Cash rejected SegWit at the Aug 2017 fork. BCH transactions use the
// LEGACY serialization only:
//     int32_t version | vector<TxIn> vin | vector<TxOut> vout | uint32_t locktime
// There is no marker/flag byte, no witness stack, and no extended format. The
// BTC source carried TxParams{allow_witness}, TxIn::scriptWitness, the dummy/
// flags branch, and HasWitness() -- ALL removed here. BCH txids are therefore
// computed over this single canonical serialization (no wtxid distinction).
//
// CashTokens (CHIP-2022-02, May 2023) wrap token data as a prefix inside the
// TxOut scriptPubKey region; that round-trips transparently through OPScript
// and needs no struct change here. Token-aware template handling is a later
// slice (coin/template_builder.hpp CTOR/token insertion point).
// ---------------------------------------------------------------------------

namespace bch
{

namespace coin
{

struct MutableTransaction;

class TxPrevOut
{
public:
    uint256 hash;
    uint32_t index;

    C2POOL_SERIALIZE_METHODS(TxPrevOut) { READWRITE(obj.hash, obj.index); }
};

class TxIn
{
public:
    TxPrevOut prevout;
    OPScript scriptSig;
    uint32_t sequence;
    // NOTE: no scriptWitness -- BCH has no SegWit (see file banner).

    C2POOL_SERIALIZE_METHODS(TxIn) { READWRITE(obj.prevout, obj.scriptSig, obj.sequence); }
};

class TxOut
{
public:
    int64_t value;
    OPScript scriptPubKey;

    C2POOL_SERIALIZE_METHODS(TxOut) { READWRITE(obj.value, obj.scriptPubKey); }
};

class Transaction
{
public:
    // Default transaction version.
    static const int32_t CURRENT_VERSION = 2;

    std::vector<TxIn> vin;
    std::vector<TxOut> vout;
    int32_t version;
    uint32_t locktime;

    /** Convert a MutableTransaction into a Transaction. */
    explicit Transaction(const MutableTransaction& tx);
    explicit Transaction(MutableTransaction&& tx);

    template <typename StreamType>
    inline void Serialize(StreamType& os) const
    {
        SerializeTransaction(*this, os);
    }
};

/** A mutable version of Transaction. */
struct MutableTransaction
{
    std::vector<TxIn> vin;
    std::vector<TxOut> vout;
    int32_t version;
    uint32_t locktime;

    explicit MutableTransaction();
    explicit MutableTransaction(const Transaction& tx);

    template <typename StreamType>
    inline void Serialize(StreamType& os) const
    {
        SerializeTransaction(*this, os);
    }

    template <typename StreamType>
    inline void Unserialize(StreamType& os)
    {
        UnserializeTransaction(*this, os);
    }
};

/**
 * BCH (legacy) transaction serialization format -- no SegWit:
 * - int32_t version
 * - std::vector<TxIn> vin
 * - std::vector<TxOut> vout
 * - uint32_t locktime
 */
template<typename StreamType, typename TxType>
void UnserializeTransaction(TxType& tx, StreamType& s)
{
    s >> tx.version;
    s >> tx.vin;
    s >> tx.vout;
    s >> tx.locktime;
}

template<typename StreamType, typename TxType>
void SerializeTransaction(const TxType& tx, StreamType& s)
{
    s << tx.version;
    s << tx.vin;
    s << tx.vout;
    s << tx.locktime;
}

} // namespace coin

} // namespace bch