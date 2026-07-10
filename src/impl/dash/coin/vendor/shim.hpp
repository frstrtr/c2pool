// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Adapter shim mapping dashcore's blockencodings type names and custom
// formatters onto c2pool's pack.hpp serialization framework.
//
// Why this exists: c2pool has two serialization frameworks in the tree —
// the Bitcoin-Core-derived btclibs/serialize.h (SERIALIZE_METHODS macro
// taking (cls, obj), VectorFormatter/CustomUintFormatter/DifferenceFormatter,
// ser_action.ForRead()) and c2pool's own pack.hpp (SERIALIZE_METHODS(TYPE),
// ListType/IntType/BigEndianFormat, formatter-variable-based
// discrimination). They collide when pulled into the same translation
// unit because the Serialize/Unserialize overloads and CompactSize
// helpers both live in the global namespace. p2p_messages.hpp is built on
// pack.hpp, and this vendor has to coexist with it.
//
// So instead of dragging btclibs/serialize.h into the vendor file, this
// shim provides drop-in replacements that mimic dashcore's formatter
// interface on top of pack.hpp. Byte-for-byte wire compatibility is
// preserved; only the C++ surface changes.
//
// Vendored files keep dashcore's class names and algorithmic bodies
// verbatim; the SERIALIZE_METHODS bodies are re-expressed in c2pool's
// FORMAT_METHODS style (single Write/Read split via the formatter-type
// discriminator — see vendor/blockencodings.hpp).

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/transaction.hpp>

#include <core/pack.hpp>
#include <core/pack_types.hpp>

#include <cassert>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <utility>

namespace dash {
namespace coin {
namespace vendor {

// ── Type mapping to c2pool primitives ──────────────────────────────────────
//
// Dashcore passes transactions by `CTransactionRef = shared_ptr<const CTransaction>`.
// c2pool-dash doesn't have an immutable serialisable `Transaction` type;
// `MutableTransaction` is the serialisable one. Keep the shared-ptr-of-const
// discipline so callers can't mutate a shared payload in-place.
using CTransactionRef = std::shared_ptr<const ::dash::coin::MutableTransaction>;

inline CTransactionRef MakeTransactionRef(const ::dash::coin::MutableTransaction& tx) {
    return std::make_shared<::dash::coin::MutableTransaction>(tx);
}

inline CTransactionRef MakeTransactionRef(::dash::coin::MutableTransaction&& tx) {
    return std::make_shared<::dash::coin::MutableTransaction>(std::move(tx));
}

using CBlockHeader = ::dash::coin::BlockHeaderType;
using CBlock       = ::dash::coin::BlockType;

// ── Mempool snapshot provider ──────────────────────────────────────────────
//
// Replaces the raw `CTxMemPool*` dashcore threads through
// PartiallyDownloadedBlock. The provider returns a snapshot of
// (txid, tx) pairs for the reassembler to try matching against the
// compact block's short IDs. Dashcore iterates `pool->vTxHashes`
// directly under its mempool lock; we ask the caller for a vector so
// the mempool-lock policy stays on their side.
//
// Phase M (mempool) returns a real snapshot here; pre-Phase-M the
// provider is null and every cmpctblock falls through to a full
// getblocktxn round-trip.
using MempoolShortIdProvider =
    std::function<std::vector<std::pair<uint256, CTransactionRef>>()>;

// ── Formatters bridging dashcore idioms to pack.hpp ────────────────────────

// 6-byte little-endian uint64 (BIP 152 SHORTTXIDS_LENGTH). Replaces
// dashcore's CustomUintFormatter<6>. Values above 2^48-1 are rejected on
// write; reads zero-extend from the 6 stream bytes.
struct ShortTxIdFormat
{
    template <typename Stream>
    static void Write(Stream& s, uint64_t v)
    {
        assert(v <= 0xFFFFFFFFFFFFULL);
        uint8_t buf[6];
        for (int i = 0; i < 6; ++i)
            buf[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xff);
        s.write(std::as_bytes(std::span{buf}));
    }

    template <typename Stream>
    static void Read(Stream& s, uint64_t& v)
    {
        uint8_t buf[6];
        s.read(std::as_writable_bytes(std::span{buf}));
        v = 0;
        for (int i = 0; i < 6; ++i)
            v |= static_cast<uint64_t>(buf[i]) << (i * 8);
    }
};

// Transaction compression = default serialization for CTransactionRef.
// Dashcore hides this behind `TransactionCompression = DefaultFormatter`
// and expects shared_ptr<const T> to round-trip; we unpack the shared_ptr
// manually to avoid needing a deserialize_type constructor on
// MutableTransaction (that constructor would force btclibs/serialize.h
// into the widely-included transaction.hpp — see shim.hpp preamble).
struct TxCompressionFormat
{
    template <typename Stream>
    static void Write(Stream& s, const CTransactionRef& p)
    {
        assert(p);
        s << *p;
    }

    template <typename Stream>
    static void Read(Stream& s, CTransactionRef& p)
    {
        auto tx = std::make_shared<::dash::coin::MutableTransaction>();
        s >> *tx;
        p = std::const_pointer_cast<const ::dash::coin::MutableTransaction>(tx);
    }
};

// Fixed-size raw byte sequence — no length prefix, just N bytes
// written/read directly. Used by Phase C-SML for opaque BLS public
// keys (48 B), key IDs (20 B), and BLS signatures (96 B) — we don't
// validate them at MVP, just pass-through-correct serialization so
// merkle-root calculations match dashcore bit-exact.
template <size_t N>
struct RawBytesFormat
{
    template <typename Stream>
    static void Write(Stream& s, const std::array<uint8_t, N>& arr)
    {
        s.write(std::as_bytes(std::span{arr}));
    }

    template <typename Stream>
    static void Read(Stream& s, std::array<uint8_t, N>& arr)
    {
        s.read(std::as_writable_bytes(std::span{arr}));
    }
};

// Differential compact-size vector encoding. Vendored verbatim from
// dashcore/src/blockencodings.h (DifferenceFormatter), re-expressed as
// a c2pool per-vector Format rather than a per-element Formatter.
// First entry writes as its absolute value; each subsequent entry is
// (current - previous - 1) so a strictly-increasing sequence stays
// compact. Required by BIP 152 getblocktxn wire layout.
struct DifferenceListFormat
{
    template <typename Stream, typename V>
    static void Write(Stream& s, const V& values)
    {
        WriteCompactSize(s, values.size());
        uint64_t shift = 0;
        for (const auto& v : values) {
            if (static_cast<uint64_t>(v) < shift ||
                static_cast<uint64_t>(v) >= std::numeric_limits<uint64_t>::max())
                throw std::ios_base::failure("differential value overflow");
            WriteCompactSize(s, static_cast<uint64_t>(v) - shift);
            shift = static_cast<uint64_t>(v) + 1;
        }
    }

    template <typename Stream, typename V>
    static void Read(Stream& s, V& values)
    {
        using I = typename V::value_type;
        values.clear();
        auto n = ReadCompactSize(s);
        values.reserve(n);
        uint64_t shift = 0;
        for (size_t i = 0; i < n; ++i) {
            uint64_t delta = ReadCompactSize(s);
            shift += delta;
            if (shift < delta
                || shift >= std::numeric_limits<uint64_t>::max()
                || shift < std::numeric_limits<I>::min()
                || shift > std::numeric_limits<I>::max())
                throw std::ios_base::failure("differential value overflow");
            values.push_back(static_cast<I>(shift));
            ++shift;
        }
    }
};

} // namespace vendor
} // namespace coin
} // namespace dash