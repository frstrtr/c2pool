// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef C2POOL_IMPL_XMR_XMR_CARRIER_WIRE_HPP
#define C2POOL_IMPL_XMR_XMR_CARRIER_WIRE_HPP
//
// xmr_carrier_wire.hpp — W3 wire SCHEMA for the v37 Family-B (Monero / RandomX)
// carrier message and its MoneroReceipt payload.
//
// This is the byte-exact, dependency-free codec for what actually travels on the
// v37 relay for a keyed_heavy (RandomX) lane. It is deliberately self-contained
// (a std::vector<uint8_t> writer/reader, explicit little-endian) so that:
//   * the wire layout is pinned in one place and can be KAT'd without the
//     c2pool tree (see check/w3_wire_check.cpp);
//   * decode is TOTAL and BOUNDED — every length prefix is range-checked against
//     a per-component sanity cap AND the running total is held under the
//     digest-committed per-receipt / per-message budget, so a hostile length
//     prefix can never force a large allocation (the cheapest DoS to close, and
//     it must be closed BEFORE the token bucket in xmr_carrier_dos_budget.hpp,
//     which meters the *RandomX* budget, not the parser).
//
// Design of record:
//   docs/c2pool-v37-share-format.md §3 (receipt envelope), §7 (params), §8
//     (whole-share pipeline); v37-monero-randomx-lane-scoping.md §1.4 items 3/5,
//     §1.5 (MoneroReceipt sketch), §4 item 12 (W3 wire), §5 X7;
//   share-format-addendum family-b-receipt-envelope-addendum.md §B6 (byte budget);
//   xmr_receipt.hpp (the MoneroReceipt struct this serializes — sibling leg).
//
// Relationship to the c2pool-native message:
//   messages.hpp defines message_xmr_carrier in the BEGIN_MESSAGE/MESSAGE_FIELDS
//   idiom (the real relay registration). Its READWRITE body delegates field
//   encoding to the functions here so the schema has ONE definition. This header
//   pulls in NO c2pool header, so it also compiles standalone for the KAT.
//
// FCMP++/CARROT FENCE: nothing here derives or interprets coinbase OUTPUTS. The
// receipt only carries an *opening* of an already-built miner_tx prefix; the wire
// layout is fork-major-version-agnostic. Output derivation is pre-CARROT and
// lives behind the W5-XMR guard in the payout leg, never on this wire.
//
// Monero symbols the payload mirrors (SChernykh/p2pool + monero-project/monero,
// read 2026-09-05): get_block_hashing_blob, rx_slow_hash, tree_hash/tree_branch,
// TransactionPrefix{version, unlock_time, vin(TXIN_GEN 0xFF), vout
// (TXOUT_TO_TAGGED_KEY 3), extra}, tx_extra tags 0x01 pubkey / 0x02 extra-nonce /
// 0x03 merge-mining, RCTTypeNull coinbase tx-hash triple.

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "xmr_receipt.hpp"   // v37::xmr::MoneroReceipt & components (sibling leg)

namespace v37 {
namespace xmr {
namespace wire {

using u8  = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

// ---------------------------------------------------------------------------
// Hard caps. The per-receipt / per-lane budgets are the DIGEST-COMMITTED
// consensus values from the receipt leg (v37::xmr::budget). The individual
// component "sanity" caps below are NON-consensus parser guards: each is a loose
// upper bound whose only job is to keep a single length-prefixed read from
// allocating more than the total budget could ever justify. The authoritative
// gate is always the running-total check against PER_RECEIPT_BUDGET.
// ---------------------------------------------------------------------------
namespace cap {
    // consensus (mirrors v37::xmr::budget — the digest-committed lane params)
    inline constexpr std::size_t PER_RECEIPT_BUDGET = budget::PER_RECEIPT_BUDGET; // 768
    inline constexpr std::size_t R_MAX_XMR          = budget::R_MAX_XMR;          // 2

    // non-consensus parser sanity guards (loose; the total check is the real one)
    inline constexpr std::size_t BLOB_SANITY   = 256;  // honest ~77 (hdr 43 + root 32 + varint)
    inline constexpr std::size_t TAIL_SANITY   = 135;  // < KECCAK_RATE_BYTES (136), by construction
    inline constexpr std::size_t EXTRA_SANITY  = 1060; // monero MAX_TX_EXTRA_SIZE (txpool-only)
    inline constexpr std::size_t DEPTH_SANITY  = 16;   // 2^16 txs >> any real Monero block

    // The carrier is itself proven like a receipt (a MoneroReceipt at the CARRIER
    // target, not the receipt target), so it is bounded by the same per-receipt
    // budget. The whole message: chain_id(4) + carrier(<=768) + count-varint(<=3)
    // + up to R_MAX receipts (<=768 each).
    inline constexpr std::size_t MSG_HEADER      = 4;                 // chain_id (u32 LE)
    inline constexpr std::size_t COUNT_VARINT_MAX = 3;                // CompactSize for <=R_MAX
    inline constexpr std::size_t MSG_MAX =
        MSG_HEADER + PER_RECEIPT_BUDGET + COUNT_VARINT_MAX
        + R_MAX_XMR * PER_RECEIPT_BUDGET;                             // 4+768+3+2*768 = 2311
}

// A wire error. The relay ingress catches this, drops the message, and (for a
// malformed frame) treats it as a structural fault for the coarse misbehavior
// counter — never as an invalid-PoW ban (that verdict requires a completed
// RandomX evaluation; see xmr_carrier_dos_budget.hpp).
struct WireError : std::runtime_error {
    explicit WireError(const std::string& what) : std::runtime_error(what) {}
};

// ---------------------------------------------------------------------------
// Byte writer / reader — explicit little-endian, one-canon. The c2pool tree
// serializes native-LE and length-prefixes vectors with CompactSize
// (core/pack.hpp WriteCompactSize/ReadCompactSize); this codec uses the SAME
// CompactSize so the standalone KAT bytes are identical to what the
// message_xmr_carrier READWRITE body produces in-tree.
// ---------------------------------------------------------------------------
class Writer {
public:
    std::vector<u8> out;

    void u8_(u8 v)   { out.push_back(v); }
    void u32_(u32 v) { for (int i = 0; i < 4; ++i) out.push_back(u8((v >> (8 * i)) & 0xff)); }
    void u64_(u64 v) { for (int i = 0; i < 8; ++i) out.push_back(u8((v >> (8 * i)) & 0xff)); }

    // CompactSize (Bitcoin/c2pool WriteCompactSize).
    void compact_(u64 n) {
        if (n < 253)               { u8_(u8(n)); }
        else if (n <= 0xffff)      { u8_(253); u8_(u8(n)); u8_(u8(n >> 8)); }
        else if (n <= 0xffffffff)  { u8_(254); u32_(u32(n)); }
        else                       { u8_(255); u64_(n); }
    }
    void bytes_(const u8* p, std::size_t n) { out.insert(out.end(), p, p + n); }
    void bytes_(const std::vector<u8>& b)   { bytes_(b.data(), b.size()); }
};

class Reader {
public:
    Reader(const u8* p, std::size_t n) : p_(p), n_(n) {}
    explicit Reader(const std::vector<u8>& b) : p_(b.data()), n_(b.size()) {}

    std::size_t remaining() const { return n_ - i_; }
    std::size_t consumed()  const { return i_; }
    bool        eof()       const { return i_ >= n_; }

    u8 u8_() {
        if (i_ + 1 > n_) throw WireError("wire: short read (u8)");
        return p_[i_++];
    }
    u32 u32_() {
        if (i_ + 4 > n_) throw WireError("wire: short read (u32)");
        u32 v = 0;
        for (int k = 0; k < 4; ++k) v |= u32(p_[i_++]) << (8 * k);
        return v;
    }
    u64 u64_() {
        if (i_ + 8 > n_) throw WireError("wire: short read (u64)");
        u64 v = 0;
        for (int k = 0; k < 8; ++k) v |= u64(p_[i_++]) << (8 * k);
        return v;
    }
    u64 compact_() {
        u8 ch = u8_();
        u64 v;
        if (ch < 253) return ch;
        else if (ch == 253) { v = u8_(); v |= u64(u8_()) << 8;
                              if (v < 253) throw WireError("wire: non-canonical CompactSize"); }
        else if (ch == 254) { v = u32_(); if (v < 0x10000ull) throw WireError("wire: non-canonical CompactSize"); }
        else                { v = u64_(); if (v < 0x100000000ull) throw WireError("wire: non-canonical CompactSize"); }
        return v;
    }
    // Read exactly n bytes, but reject n above `sanity` BEFORE allocating.
    std::vector<u8> bytes_(std::size_t n, std::size_t sanity, const char* what) {
        if (n > sanity)   throw WireError(std::string("wire: ") + what + " over sanity cap");
        if (i_ + n > n_)  throw WireError(std::string("wire: short read (") + what + ")");
        std::vector<u8> b(p_ + i_, p_ + i_ + n);
        i_ += n;
        return b;
    }
    void fixed_(u8* dst, std::size_t n, const char* what) {
        if (i_ + n > n_) throw WireError(std::string("wire: short read (") + what + ")");
        for (std::size_t k = 0; k < n; ++k) dst[k] = p_[i_++];
    }
private:
    const u8*   p_;
    std::size_t n_;
    std::size_t i_ = 0;
};

// ===========================================================================
// MoneroReceipt payload codec.
//
// Field order on the wire (one-canon; all lengths CompactSize; all ints LE):
//
//   1  hashing_blob      : compact(len) || bytes            (~77, sanity 256)
//   2  seed_ref.policy   : u8   (0 = DerivedFromBin, 1 = CarriedSeedHash)
//      seed_ref.carried  : 32 B  IFF policy == CarriedSeedHash        (else absent)
//   3  coinbase_opening:
//        midstate        : 200 B  (fixed Keccak-256 sponge state)
//        prefix_tail     : compact(len) || bytes            (< 136, sanity 135)
//        tx_extra        : compact(len) || bytes            (sanity 1060)
//   4  tree_branch:
//        depth           : u8    (= path.size(); sanity 16)
//        path            : depth * 32 B   (leaf-0 left-spine siblings, root-ward)
//   5  info_digest       : 32 B
//
// A receipt whose *decoded* size exceeds `budget_cap` (the digest-committed
// per-receipt budget) is rejected during decode: the running consumed-byte
// count is held under `budget_cap` after every field. This is the same value
// the admission pre-gate re-checks via MoneroReceipt::wire_size() — enforced
// here first so an oversize receipt never even allocates its components.
// ===========================================================================

inline void encode_receipt(Writer& w, const MoneroReceipt& r) {
    // 1 hashing_blob
    w.compact_(r.hashing_blob.bytes.size());
    w.bytes_(r.hashing_blob.bytes);
    // 2 seed_ref
    w.u8_(static_cast<u8>(r.seed_ref.policy));
    if (r.seed_ref.policy == SeedRefPolicy::CarriedSeedHash) {
        if (!r.seed_ref.carried)
            throw WireError("wire: CarriedSeedHash without a seed hash");
        w.bytes_(r.seed_ref.carried->data(), r.seed_ref.carried->size());
    }
    // 3 coinbase_opening
    w.bytes_(r.coinbase_opening.midstate.data(), r.coinbase_opening.midstate.size());
    w.compact_(r.coinbase_opening.prefix_tail.size());
    w.bytes_(r.coinbase_opening.prefix_tail);
    w.compact_(r.coinbase_opening.tx_extra.size());
    w.bytes_(r.coinbase_opening.tx_extra);
    // 4 tree_branch
    w.u8_(r.tree_branch.depth);
    for (const auto& h : r.tree_branch.path) w.bytes_(h.data(), h.size());
    // 5 info_digest
    w.bytes_(r.info_digest.data(), r.info_digest.size());
}

inline MoneroReceipt decode_receipt(Reader& rd, std::size_t budget_cap = cap::PER_RECEIPT_BUDGET) {
    const std::size_t start = rd.consumed();
    auto guard = [&](const char* where) {
        if (rd.consumed() - start > budget_cap)
            throw WireError(std::string("wire: receipt over per-receipt budget at ") + where);
    };

    MoneroReceipt r;

    // 1 hashing_blob
    {
        u64 len = rd.compact_();
        r.hashing_blob.bytes = rd.bytes_(static_cast<std::size_t>(len), cap::BLOB_SANITY, "hashing_blob");
        guard("hashing_blob");
    }
    // 2 seed_ref
    {
        u8 pol = rd.u8_();
        if (pol > static_cast<u8>(SeedRefPolicy::CarriedSeedHash))
            throw WireError("wire: unknown SeedRefPolicy");
        r.seed_ref.policy = static_cast<SeedRefPolicy>(pol);
        if (r.seed_ref.policy == SeedRefPolicy::CarriedSeedHash) {
            bytes32 s{};
            rd.fixed_(s.data(), s.size(), "seed_ref.carried");
            r.seed_ref.carried = s;
        }
        guard("seed_ref");
    }
    // 3 coinbase_opening
    {
        rd.fixed_(r.coinbase_opening.midstate.data(),
                  r.coinbase_opening.midstate.size(), "coinbase_opening.midstate");
        u64 tl = rd.compact_();
        r.coinbase_opening.prefix_tail = rd.bytes_(static_cast<std::size_t>(tl),
                                                   cap::TAIL_SANITY, "coinbase_opening.prefix_tail");
        u64 el = rd.compact_();
        r.coinbase_opening.tx_extra = rd.bytes_(static_cast<std::size_t>(el),
                                                cap::EXTRA_SANITY, "coinbase_opening.tx_extra");
        guard("coinbase_opening");
    }
    // 4 tree_branch
    {
        u8 depth = rd.u8_();
        if (depth > cap::DEPTH_SANITY) throw WireError("wire: tree_branch depth over sanity cap");
        r.tree_branch.depth = depth;
        r.tree_branch.path.resize(depth);
        for (u8 k = 0; k < depth; ++k)
            rd.fixed_(r.tree_branch.path[k].data(), r.tree_branch.path[k].size(), "tree_branch.path");
        guard("tree_branch");
    }
    // 5 info_digest
    rd.fixed_(r.info_digest.data(), r.info_digest.size(), "info_digest");
    guard("info_digest");

    // Final authoritative gate: the receipt's own wire_size() (what the admission
    // pre-gate checks) must agree with the digest-committed budget. Both the
    // running guard and this final check use the SAME value, so a receipt that
    // decodes here is guaranteed to pass admission's size pre-gate.
    if (r.wire_size() > budget_cap)
        throw WireError("wire: decoded receipt exceeds per-receipt budget");
    return r;
}

// ===========================================================================
// The carrier message payload.
//
//   chain_id   : u32 LE                 (the keyed_heavy lane; must match a lane)
//   carrier    : MoneroReceipt          (the difficulty-gated transport share;
//                                         proven at the CARRIER target)
//   receipts   : compact(count) || count * MoneroReceipt   (0 .. R_MAX_XMR)
//
// A carrier with count > R_MAX_XMR is a HARD structural reject (consensus: the
// receipt-per-carrier bound). The whole frame must stay under cap::MSG_MAX; the
// relay applies that ceiling before this decode is even entered (a frame larger
// than MSG_MAX is dropped at the transport read, never parsed).
// ===========================================================================
struct CarrierMessage {
    u32                         chain_id = 0;
    MoneroReceipt               carrier;
    std::vector<MoneroReceipt>  receipts;
};

inline std::vector<u8> encode_carrier(const CarrierMessage& m) {
    if (m.receipts.size() > cap::R_MAX_XMR)
        throw WireError("wire: receipts exceed R_MAX_XMR");
    Writer w;
    w.u32_(m.chain_id);
    encode_receipt(w, m.carrier);
    w.compact_(m.receipts.size());
    for (const auto& r : m.receipts) encode_receipt(w, r);
    if (w.out.size() > cap::MSG_MAX)
        throw WireError("wire: encoded carrier exceeds MSG_MAX");
    return std::move(w.out);
}

inline CarrierMessage decode_carrier(const u8* p, std::size_t n) {
    if (n > cap::MSG_MAX) throw WireError("wire: carrier frame exceeds MSG_MAX");
    Reader rd(p, n);
    CarrierMessage m;
    m.chain_id = rd.u32_();
    m.carrier  = decode_receipt(rd);                 // carrier target enforced at admission
    u64 count  = rd.compact_();
    if (count > cap::R_MAX_XMR) throw WireError("wire: receipts exceed R_MAX_XMR");
    m.receipts.reserve(static_cast<std::size_t>(count));
    for (u64 k = 0; k < count; ++k) m.receipts.push_back(decode_receipt(rd));
    if (!rd.eof()) throw WireError("wire: trailing bytes after carrier");
    return m;
}
inline CarrierMessage decode_carrier(const std::vector<u8>& b) {
    return decode_carrier(b.data(), b.size());
}

} // namespace wire
} // namespace xmr
} // namespace v37

#endif // C2POOL_IMPL_XMR_XMR_CARRIER_WIRE_HPP
