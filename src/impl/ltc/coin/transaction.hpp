#pragma once

#include <core/pack.hpp>
#include <core/opscript.hpp>
#include <core/uint256.hpp>

namespace ltc
{

namespace coin
{

struct MutableTransaction;

struct TxParams
{
    const bool allow_witness;

    SER_PARAMS_OPFUNC
};

constexpr static TxParams TX_WITH_WITNESS {.allow_witness = true};
constexpr static TxParams TX_NO_WITNESS {.allow_witness = false};

class TxPrevOut
{
public:
    uint256 hash;
    uint32_t index;

    SERIALIZE_METHODS(TxPrevOut) { READWRITE(obj.hash, obj.index); }
};

class TxIn
{
public:
    TxPrevOut prevout;
    OPScript scriptSig;
    uint32_t sequence;
    OPScriptWitness scriptWitness; //!< Only serialized through Transaction

    SERIALIZE_METHODS(TxIn) { READWRITE(obj.prevout, obj.scriptSig, obj.sequence); }
};

class TxOut
{
public:
    int64_t value;
    OPScript scriptPubKey;

    SERIALIZE_METHODS(TxOut) { READWRITE(obj.value, obj.scriptPubKey); }
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
 * - uint32_t locktime
 */
template<typename StreamType, typename TxType>
void UnserializeTransaction(TxType& tx, StreamType& s, const TxParams& params)
{
    const bool fAllowWitness = params.allow_witness;

    s >> tx.version;
    unsigned char flags = 0;
    tx.vin.clear();
    tx.vout.clear();
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
    if (flags)
    {
        /* Use extended format in case witnesses are to be serialized. */
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
    s << tx.locktime;
}

} // namespace coin

} // namespace ltc
