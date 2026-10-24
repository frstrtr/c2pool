// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Litecoin MWEB wire grammar: mw::Transaction and the mw::Block body, walked
/// byte for byte as litecoind (v0.21.4 libmw models) reads them.
///
/// A tx relayed by litecoind to a NODE_MWEB peer carries its mw::Transaction
/// after the outputs (and witnesses) when serialization flag 0x08 is set and
/// the presence byte is 1. Nothing in an mw::Transaction is length-prefixed,
/// so the only way to find where it ends (and where the locktime starts) is
/// to walk the grammar:
///
///   mw::Transaction := kernel_offset[32] stealth_offset[32] TxBody   (>= 1 kernel)
///   TxBody          := vec<Input> vec<Output> vec<Kernel>            (vec = CompactSize n, n items)
///   Input           := features[1] output_id[32] commitment[33] output_pubkey[33]
///                      [input_pubkey[33] if &0x01] [vec<u8> extra if &0x02] signature[64]
///   Output          := commitment[33] sender_pubkey[33] receiver_pubkey[33] OutputMessage
///                      rangeproof[675] signature[64]
///   OutputMessage   := features[1] [key_exchange_pubkey[33] view_tag[1] masked_value[8]
///                      masked_nonce[16] if &0x01] [vec<u8> extra if &0x02]
///   Kernel          := features[1] [VARINT fee if &0x01] [VARINT pegin if &0x02]
///                      [vec<PegOutCoin> if &0x04] [VARINT lock_height if &0x08]
///                      [stealth_excess[33] if &0x10] [vec<u8> extra if &0x20] excess[33] signature[64]
///   PegOutCoin      := VARINT amount, CScript (CompactSize length + bytes; empty is invalid)
///
/// VARINT is Bitcoin's MSB base-128 varint (serialize.h ReadVarInt); vector
/// lengths are CompactSize. No signature, range proof or sum is checked --
/// the walk only finds the boundaries and reads the fields that matter to a
/// node that does not mine MWEB transactions: kernel ids (the txid of an
/// MWEB-only tx), fees, peg-ins, peg-outs and the MWEB weight.
///
/// Header-only and free of btclibs/serialize.h (see the include-order note in
/// mweb_builder.hpp): it reads from any stream with read(std::span<std::byte>).

#include <core/pack.hpp>
#include <core/opscript.hpp>
#include <core/uint256.hpp>
#include <crypto/blake3/blake3.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ios>
#include <limits>
#include <optional>
#include <span>
#include <type_traits>
#include <vector>

namespace ltc {
namespace coin {
namespace mweb_wire {

// Field sizes (libmw Hash.h, BlindingFactor.h, Commitment.h, PublicKey.h,
// Signature.h, RangeProof.h).
inline constexpr size_t HASH_SIZE = 32;
inline constexpr size_t BLINDING_FACTOR_SIZE = 32;
inline constexpr size_t COMMITMENT_SIZE = 33;
inline constexpr size_t PUBKEY_SIZE = 33;
inline constexpr size_t SIGNATURE_SIZE = 64;
inline constexpr size_t RANGEPROOF_SIZE = 675;

// Feature bits (libmw Input.h, Output.h, Kernel.h).
inline constexpr uint8_t INPUT_STEALTH_KEY = 0x01;
inline constexpr uint8_t INPUT_EXTRA_DATA = 0x02;
inline constexpr uint8_t OUTPUT_STANDARD_FIELDS = 0x01;
inline constexpr uint8_t OUTPUT_EXTRA_DATA = 0x02;
inline constexpr uint8_t KERNEL_FEE = 0x01;
inline constexpr uint8_t KERNEL_PEGIN = 0x02;
inline constexpr uint8_t KERNEL_PEGOUT = 0x04;
inline constexpr uint8_t KERNEL_HEIGHT_LOCK = 0x08;
inline constexpr uint8_t KERNEL_STEALTH_EXCESS = 0x10;
inline constexpr uint8_t KERNEL_EXTRA_DATA = 0x20;

// MWEB weight (libmw consensus/Params.h, Weight.h).
inline constexpr uint64_t BYTES_PER_WEIGHT = 42;
inline constexpr uint64_t BASE_KERNEL_WEIGHT = 2;
inline constexpr uint64_t KERNEL_WITH_STEALTH_WEIGHT = 3;
inline constexpr uint64_t BASE_OUTPUT_WEIGHT = 17;
inline constexpr uint64_t STANDARD_OUTPUT_WEIGHT = 18;

inline uint64_t extra_bytes_to_weight(uint64_t n)
{
    return (n + BYTES_PER_WEIGHT - 1) / BYTES_PER_WEIGHT;
}

// ─── Readers ────────────────────────────────────────────────────────────────

/// Reads from a byte span (throws std::ios_base::failure at the end).
struct SpanReader {
    std::span<const unsigned char> buf;
    size_t pos{0};

    explicit SpanReader(std::span<const unsigned char> b) : buf(b) {}

    void read(std::span<std::byte> out)
    {
        if (out.size() > buf.size() - pos)
            throw std::ios_base::failure("mweb_wire: end of data");
        std::memcpy(out.data(), buf.data() + pos, out.size());
        pos += out.size();
    }
    size_t remaining() const { return buf.size() - pos; }
};

/// Reads from `s` and appends every byte read to `out`. PackStream drops its
/// buffer once it is read to the end, so the bytes of a walked structure are
/// kept by recording them as they go by.
template <typename Stream>
struct Recorder {
    Stream& s;
    std::vector<unsigned char>& out;

    void read(std::span<std::byte> d)
    {
        const size_t at = out.size();
        out.resize(at + d.size());
        s.read(std::span<std::byte>(reinterpret_cast<std::byte*>(out.data() + at), d.size()));
        std::memcpy(d.data(), out.data() + at, d.size());
    }
};

template <typename Stream>
inline uint8_t read_u8(Stream& s)
{
    std::byte b;
    s.read(std::span<std::byte>(&b, 1));
    return static_cast<uint8_t>(b);
}

template <typename Stream>
inline void read_bytes(Stream& s, unsigned char* dst, size_t n)
{
    s.read(std::span<std::byte>(reinterpret_cast<std::byte*>(dst), n));
}

/// Consume `n` bytes in bounded chunks (a claimed length is never allocated
/// up front).
template <typename Stream>
inline void skip_bytes(Stream& s, size_t n)
{
    std::array<std::byte, 4096> chunk;
    while (n > 0) {
        const size_t k = std::min(n, chunk.size());
        s.read(std::span<std::byte>(chunk.data(), k));
        n -= k;
    }
}

/// Bitcoin VARINT (MSB base-128, one subtracted from every digit but the
/// last): serialize.h ReadVarInt<Stream, Mode, I>. The overflow checks depend
/// on the target type, as in litecoind (int64_t amounts, int32_t heights,
/// uint64_t MMR sizes). DEFAULT and NONNEGATIVE_SIGNED read the same bytes.
template <typename I = uint64_t, typename Stream>
inline I read_varint_msb128(Stream& s)
{
    static_assert(std::is_integral_v<I>, "integral VARINT target");
    I n = 0;
    while (true) {
        const uint8_t ch = read_u8(s);
        if (n > (std::numeric_limits<I>::max() >> 7))
            throw std::ios_base::failure("ReadVarInt(): size too large");
        n = static_cast<I>((n << 7) | (ch & 0x7F));
        if (ch & 0x80) {
            if (n == std::numeric_limits<I>::max())
                throw std::ios_base::failure("ReadVarInt(): size too large");
            n++;
        } else {
            return n;
        }
    }
}

/// CompactSize, canonical and range-checked (core/pack.hpp ReadCompactSize ==
/// serialize.h ReadCompactSize).
template <typename Stream>
inline uint64_t read_compact_size(Stream& s)
{
    return ::ReadCompactSize(s);
}

// ─── Summaries ──────────────────────────────────────────────────────────────

struct PegOut {
    int64_t amount{0};
    std::vector<uint8_t> script;
};

struct KernelSummary {
    uint8_t features{0};
    int64_t fee{0};
    std::optional<int64_t> pegin;    // set iff the PEGIN bit is (libmw HasPegIn)
    std::vector<PegOut> pegouts;
    int32_t lock_height{0};
    uint256 kernel_id;               // blake3 digest, raw byte order
    size_t off{0}, len{0};           // the kernel's wire bytes within the walked buffer
};

struct MwebBodySummary {
    size_t n_inputs{0}, n_outputs{0};
    std::vector<KernelSummary> kernels;
    uint64_t weight{0};              // libmw Weight::Calculate

    /// Sum of kernel fees (TxBody::GetTotalFee), saturating.
    int64_t total_fee() const
    {
        int64_t sum = 0;
        for (const auto& k : kernels)
            sum = (k.fee > std::numeric_limits<int64_t>::max() - sum)
                ? std::numeric_limits<int64_t>::max() : sum + k.fee;
        return sum;
    }
    /// Sum of peg-in amounts (TxBody::GetPegInAmount), saturating.
    int64_t pegin_amount() const
    {
        int64_t sum = 0;
        for (const auto& k : kernels) {
            const int64_t v = k.pegin.value_or(0);
            sum = (v > std::numeric_limits<int64_t>::max() - sum)
                ? std::numeric_limits<int64_t>::max() : sum + v;
        }
        return sum;
    }
    std::vector<PegOut> pegouts() const
    {
        std::vector<PegOut> out;
        for (const auto& k : kernels)
            out.insert(out.end(), k.pegouts.begin(), k.pegouts.end());
        return out;
    }
    size_t n_pegins() const
    {
        return static_cast<size_t>(std::count_if(kernels.begin(), kernels.end(),
            [](const KernelSummary& k) { return k.pegin.has_value(); }));
    }
    size_t n_pegouts() const
    {
        size_t n = 0;
        for (const auto& k : kernels)
            n += k.pegouts.size();
        return n;
    }
    bool has_pegin() const { return n_pegins() > 0; }
    bool has_pegout() const { return n_pegouts() > 0; }
    uint64_t mweb_weight() const { return weight; }
};

struct MwebTxSummary : MwebBodySummary {
    std::array<uint8_t, 32> kernel_offset{};
    std::array<uint8_t, 32> stealth_offset{};
    std::vector<unsigned char> raw;  // the mw::Transaction bytes as received
};

/// Kernel id: blake3 of the serialized kernel (libmw Kernel.h, Hashed(*this)).
inline uint256 kernel_id(std::span<const unsigned char> kernel_bytes)
{
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, kernel_bytes.data(), kernel_bytes.size());
    uint256 id;
    blake3_hasher_finalize(&hasher, id.data(), 32);
    return id;
}

// ─── Grammar ────────────────────────────────────────────────────────────────

namespace detail {

// The readers below take the recording stream (Recorder); read_kernel also
// takes the buffer it records into, to locate and hash the kernel's bytes.
template <typename Rec>
inline uint64_t read_input(Rec& s)
{
    const uint8_t features = read_u8(s);
    skip_bytes(s, HASH_SIZE + COMMITMENT_SIZE + PUBKEY_SIZE);  // output_id, commitment, output_pubkey
    if (features & INPUT_STEALTH_KEY)
        skip_bytes(s, PUBKEY_SIZE);                             // input_pubkey
    uint64_t extra = 0;
    if (features & INPUT_EXTRA_DATA) {
        extra = read_compact_size(s);
        skip_bytes(s, static_cast<size_t>(extra));
    }
    skip_bytes(s, SIGNATURE_SIZE);
    return extra_bytes_to_weight(extra);
}

template <typename Rec>
inline uint64_t read_output(Rec& s)
{
    skip_bytes(s, COMMITMENT_SIZE + PUBKEY_SIZE + PUBKEY_SIZE); // commitment, sender, receiver
    const uint8_t msg_features = read_u8(s);
    if (msg_features & OUTPUT_STANDARD_FIELDS)
        skip_bytes(s, PUBKEY_SIZE + 1 + 8 + 16);                // key exchange, view tag, value, nonce
    uint64_t extra = 0;
    if (msg_features & OUTPUT_EXTRA_DATA) {
        extra = read_compact_size(s);
        skip_bytes(s, static_cast<size_t>(extra));
    }
    skip_bytes(s, RANGEPROOF_SIZE + SIGNATURE_SIZE);
    return ((msg_features & OUTPUT_STANDARD_FIELDS) ? STANDARD_OUTPUT_WEIGHT : BASE_OUTPUT_WEIGHT)
         + extra_bytes_to_weight(extra);
}

template <typename Rec>
inline KernelSummary read_kernel(Rec& s, const std::vector<unsigned char>& buf, uint64_t& weight)
{
    KernelSummary k;
    k.off = buf.size();
    k.features = read_u8(s);
    if (k.features & KERNEL_FEE)
        k.fee = read_varint_msb128<int64_t>(s);
    if (k.features & KERNEL_PEGIN)
        k.pegin = read_varint_msb128<int64_t>(s);
    const size_t pegouts_at = buf.size();
    uint64_t pegout_weight = 0;
    if (k.features & KERNEL_PEGOUT) {
        const uint64_t n = read_compact_size(s);
        for (uint64_t i = 0; i < n; ++i) {
            PegOut p;
            p.amount = read_varint_msb128<int64_t>(s);
            const uint64_t len = read_compact_size(s);
            if (len == 0)
                throw std::ios_base::failure("Pegout scriptPubKey must not be empty");
            // A script is a CScript (prevector): read it in bounded chunks.
            size_t got = 0;
            while (got < len) {
                const size_t k_len = std::min<size_t>(static_cast<size_t>(len - got), 4096);
                p.script.resize(got + k_len);
                read_bytes(s, p.script.data() + got, k_len);
                got += k_len;
            }
            pegout_weight += extra_bytes_to_weight(p.script.size());
            k.pegouts.push_back(std::move(p));
        }
    }
    const size_t pegouts_end = buf.size();
    if (k.features & KERNEL_HEIGHT_LOCK)
        k.lock_height = read_varint_msb128<int32_t>(s);
    if (k.features & KERNEL_STEALTH_EXCESS)
        skip_bytes(s, PUBKEY_SIZE);
    const size_t extra_at = buf.size();
    uint64_t extra = 0;
    if (k.features & KERNEL_EXTRA_DATA) {
        extra = read_compact_size(s);
        skip_bytes(s, static_cast<size_t>(extra));
    }
    const size_t extra_end = buf.size();
    skip_bytes(s, COMMITMENT_SIZE + SIGNATURE_SIZE);            // excess, signature
    k.len = buf.size() - k.off;

    // The id hashes the kernel as libmw re-serializes it: an empty pegout
    // list or empty extra data is not written even when its feature bit is
    // set (Kernel::Serialize), so those length bytes are not hashed.
    const bool drop_pegouts = (k.features & KERNEL_PEGOUT) && k.pegouts.empty();
    const bool drop_extra = (k.features & KERNEL_EXTRA_DATA) && extra == 0;
    if (!drop_pegouts && !drop_extra) {
        k.kernel_id = kernel_id(std::span<const unsigned char>(buf.data() + k.off, k.len));
    } else {
        std::vector<unsigned char> h;
        h.reserve(k.len);
        for (size_t i = k.off; i < k.off + k.len; ++i) {
            if (drop_pegouts && i >= pegouts_at && i < pegouts_end) continue;
            if (drop_extra && i >= extra_at && i < extra_end) continue;
            h.push_back(buf[i]);
        }
        k.kernel_id = kernel_id(h);
    }

    weight += ((k.features & KERNEL_STEALTH_EXCESS) ? KERNEL_WITH_STEALTH_WEIGHT : BASE_KERNEL_WEIGHT)
            + pegout_weight + extra_bytes_to_weight(extra);
    return k;
}

template <typename Rec>
inline void read_body(Rec& s, const std::vector<unsigned char>& buf, MwebBodySummary& out)
{
    out.n_inputs = static_cast<size_t>(read_compact_size(s));
    for (size_t i = 0; i < out.n_inputs; ++i)
        out.weight += read_input(s);
    out.n_outputs = static_cast<size_t>(read_compact_size(s));
    for (size_t i = 0; i < out.n_outputs; ++i)
        out.weight += read_output(s);
    const uint64_t n_kernels = read_compact_size(s);
    for (uint64_t i = 0; i < n_kernels; ++i)
        out.kernels.push_back(read_kernel(s, buf, out.weight));
}

} // namespace detail

/// Consume exactly one mw::Transaction from `s` (libmw Transaction.h). Throws
/// std::ios_base::failure on truncation, a non-canonical or oversized
/// CompactSize, a VARINT overflow, an empty pegout script or a transaction
/// with no kernel -- the cases litecoind's deserializer throws on.
template <typename Stream>
MwebTxSummary read_mw_transaction(Stream& s)
{
    MwebTxSummary out;
    Recorder<Stream> rec{s, out.raw};
    read_bytes(rec, out.kernel_offset.data(), BLINDING_FACTOR_SIZE);
    read_bytes(rec, out.stealth_offset.data(), BLINDING_FACTOR_SIZE);
    detail::read_body(rec, out.raw, out);
    if (out.kernels.empty())
        throw std::ios_base::failure("Transaction requires at least one kernel");
    return out;
}

/// Consume one mw::Block body (TxBody: vec<Input> vec<Output> vec<Kernel>)
/// from `s`. Same failure cases as read_mw_transaction, except that a body
/// may have no kernel (an empty block).
template <typename Stream>
MwebBodySummary read_mw_body(Stream& s)
{
    MwebBodySummary out;
    std::vector<unsigned char> buf;
    Recorder<Stream> rec{s, buf};
    detail::read_body(rec, buf, out);
    return out;
}

/// The summary of an mw::Transaction held as raw bytes (nullopt when they do
/// not walk as exactly one mw::Transaction).
inline std::optional<MwebTxSummary> summarize_mw_transaction(std::span<const unsigned char> raw)
{
    try {
        SpanReader r(raw);
        MwebTxSummary s = read_mw_transaction(r);
        if (r.remaining() != 0)
            return std::nullopt;
        return s;
    } catch (const std::ios_base::failure&) {
        return std::nullopt;
    }
}

// ─── Canonical scripts that belong to MWEB ──────────────────────────────────

/// Peg-in output script: witness version 9, 32-byte program = the peg-in
/// kernel id (OP_9 PUSH32 <id>; script.cpp IsMWEBPegin).
inline std::optional<uint256> pegin_kernel_of(std::span<const unsigned char> spk)
{
    if (spk.size() != 34 || spk[0] != 0x59 || spk[1] != 0x20)
        return std::nullopt;
    uint256 id;
    std::memcpy(id.data(), spk.data() + 2, 32);
    return id;
}

inline std::optional<uint256> pegin_kernel_of(const OPScript& spk)
{
    return pegin_kernel_of(std::span<const unsigned char>(spk.m_data.data(), spk.m_data.size()));
}

/// HogAddr script: witness version 8, 32-byte program = the MWEB header hash
/// (OP_8 PUSH32 <hash>; script.cpp IsMWEBHogAddr).
inline bool is_hogaddr(std::span<const unsigned char> spk)
{
    return spk.size() == 34 && spk[0] == 0x58 && spk[1] == 0x20;
}

inline bool is_hogaddr(const OPScript& spk)
{
    return is_hogaddr(std::span<const unsigned char>(spk.m_data.data(), spk.m_data.size()));
}

} // namespace mweb_wire
} // namespace coin
} // namespace ltc
