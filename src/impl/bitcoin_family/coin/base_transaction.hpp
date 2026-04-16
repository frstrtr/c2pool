#pragma once

// Generic Bitcoin-family transaction primitive types.
// TxParams, TxPrevOut, TxIn, TxOut are identical across all Bitcoin-derived coins.
// The full Transaction/MutableTransaction classes and serialization templates
// are coin-specific (LTC has MWEB flag 0x08, Dash has no segwit, etc.).

#include <core/pack.hpp>
#include <core/opscript.hpp>
#include <core/uint256.hpp>

namespace bitcoin_family
{
namespace coin
{

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

} // namespace coin
} // namespace bitcoin_family
