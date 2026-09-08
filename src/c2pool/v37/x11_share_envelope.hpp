#pragma once
// V37 Track A2 / S-1 — REAL DASH X11 SHARE ENVELOPE (carrier-wire version 0x02).
// CONSUMER-tree code (src/c2pool/v37/). Header-only, so it links into every v37
// unit suite AND the daemon exactly like w2_receipt.hpp / w3_relay.hpp. Does NOT
// touch src/sharechain/v37 canon; it stacks on the W2/W3 consumer seams and the
// shipped, KAT-proven DASH v16 share machinery in src/impl/dash (the SSOT).
//
// WHAT THIS FILE IS
//   The honest replacement for the SYNTHETIC WorkEvent (w2_receipt.hpp:206). The
//   synthetic event is a header-SHAPED sha256d preimage: it FAKES PoW (sha256d
//   leading-zero count) and FAKES the payout binding (identity literally sits in
//   the hashed preimage). A peer "verifying" it via meets_own_target() learns
//   nothing about DASH mainchain work.
//
//   X11ShareEvent is a REAL share: the 80-byte header the miner X11-hashed, its
//   nonce, the DASH mainchain target it met, the sharechain target it is credited
//   at, AND the coinbase + merkle branch that let ANY peer independently prove —
//   without trusting the sender — that (a) X11 over the header met a target = real
//   work, (b) the work is pinned to a DASH height via header.hashPrevBlock, and
//   (c) the coinbase (whose OP_RETURN commits the miner's payout identity) folds
//   through the branch up to the header's merkle_root, so WHO is credited is bound
//   under the same PoW. The RDWR binding MIGRATES from "sits in the sha256d
//   preimage" to "committed by merkle_root -> coinbase -> OP_RETURN ref_hash".
//
// WIRE VERSION 0x02 (never a re-pack of 0x01; see w3_wire_freeze.hpp VERSION
//   POLICY F-5 + HONEST BOUNDARY S-1). The 0x01 synthetic layout is a frozen,
//   golden-pinned 112-byte-prefix event; the 0x02 X11 event is variable-length
//   (two coinbase blobs + a merkle branch) and CANNOT satisfy the 0x01
//   static_assert. The two layouts COEXIST behind a dual-accept decoder for one
//   upgrade window: a 0x01 frame -> synthetic WorkEvent (w3_relay.hpp), a 0x02
//   frame -> X11ShareEvent (here). The frozen desc/ref/str/tag sub-encoding is
//   reused BYTE-IDENTICALLY so a descriptor serializes the same across versions.
//
// SSOT REUSED (never reinvented):
//   dash::crypto::hash_x11                         X11 PoW (impl/dash/crypto)
//   dash::coin::serialize_header80 / target_from_nbits / meets_target /
//     coinbase_txid                                 (impl/dash/coin/block_producer)
//   dash::check_merkle_link (index 0, DASH v16)     (impl/dash/share_check)
//   dash::MerkleLink                                (impl/dash/share_types)
//   c2pool::v37n::work_from_target (saturating narrow, credit basis §4.1)
//   the W2 seams: IMainchainIndex, IShareTracker, DedupWindow, EmittedPush,
//     Disposition, CarrierStatus, and the W3-MUST identity binding.
//
// The DEEP payout proof — recompute ref_hash from the share fields and require the
// PPLNS-recomputed coinbase txid to equal the committed one (dash::
// verify_payout_commitment / generate_share_transaction) — needs the node's share
// tracker chain, so it is injected through the X11PayoutOracle seam. The
// self-contained core here does the full cryptographic chain (coinbase ->
// merkle -> header -> X11 -> targets), extracts the OP_RETURN payout commitment,
// and enforces the W3-MUST identity binding; the oracle closes the last mile.

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "w3_relay.hpp"   // WireStatus, ReceiptWireDrop, W3_R_MAX; pulls w2_admission
                          // (IMainchainIndex, IShareTracker, DedupWindow, EmittedPush,
                          //  Disposition, CarrierStatus, RecordSink, W2_* consts) and
                          // w2_receipt (bytes32, u64, work_from_target, PayoutDescriptor).

#include <impl/dash/crypto/hash_x11.hpp>        // dash::crypto::hash_x11
#include <impl/dash/coin/block_producer.hpp>    // dash::coin::serialize_header80/target_from_nbits/meets_target/coinbase_txid
#include <impl/dash/share_check.hpp>            // dash::check_merkle_link
#include <impl/dash/share_types.hpp>            // dash::MerkleLink
#include <core/uint256.hpp>

namespace c2pool::v37n {

// The carrier-wire version tag for the real X11 share envelope. A frame led by
// this byte carries the 0x02 (variable-length) event layout below; 0x01 remains
// the frozen synthetic layout in w3_relay.hpp. Wiring the dual-accept decoder is
// the w3_relay.hpp / w3_wire_freeze.hpp patch documented in the integration note.
constexpr std::uint8_t W3_WIRE_VERSION_X11 = 0x02;

// ── uint256 (internal LE) <-> bytes32 bridges ───────────────────────────────
// The 80-byte DASH header carries prev_block / merkle_root in uint256 INTERNAL
// (little-endian) byte order — the same order hash_x11 consumes. bytes32 mirrors
// that order 1:1. work_from_target() instead wants a BIG-ENDIAN target (b[0] =
// most significant byte), so be_from_u256 reverses.
inline uint256 u256_from_internal(const bytes32& b) {
    uint256 u;
    std::memcpy(u.data(), b.data(), 32);
    return u;
}
inline bytes32 internal_from_u256(const uint256& u) {
    bytes32 b{};
    std::memcpy(b.data(), u.data(), 32);
    return b;
}
inline bytes32 be_from_u256(const uint256& u) {
    bytes32 be{};
    const unsigned char* d = u.data();
    for (int i = 0; i < 32; ++i) be[i] = d[31 - i];
    return be;
}

// ═══════════════════════════════════════════════════════════════════════════
// The real X11 share event (carrier or receipt). Field roles map onto the RDWR
// 4-tuple and routing exactly as the synthetic WorkEvent, but every synthetic
// field is replaced by the real header field it stood in for, and the coinbase +
// branch are added so the payout is trustlessly verifiable.
// ═══════════════════════════════════════════════════════════════════════════
struct X11ShareEvent {
    // ── KEEP: RDWR tuple + routing (verbatim role) ──────────────────────────
    std::uint32_t chain_id = 0;      // RDWR member 1; admitter chain check + ref_hash id
    bytes32 identity{};              // RDWR member 2 = descriptor.identity_key();
                                     // now VERIFIED by the coinbase OP_RETURN, not by
                                     // preimage inclusion (W3-MUST binds it to descriptor).
    bytes32 prev_own_share{};        // RDWR member 4; IShareTracker::has_prev_own sequence
    ::v37::PayoutDescriptor descriptor;  // real descriptor the credit is pushed under
    std::string tag;                 // bookkeeping only (never under PoW)

    // ── REPLACE lz_bits + synthetic u64 nonce with the real 80-byte header ──
    std::uint32_t version = 0;       // header nVersion (serialized as int32)
    bytes32 prev_block_hash{};       // header.hashPrevBlock (internal LE); RDWR member 3 -> bin
    std::uint32_t ntime = 0;         // header nTime
    std::uint32_t nbits = 0;         // header nBits: the DASH mainchain BLOCK target in force
                                     // (won-block detection + R-1 pin); the honest lz_bits heir
    std::uint32_t nonce = 0;         // header nNonce — REAL u32 (not the synthetic u64)
    std::uint32_t share_bits = 0;    // sharechain's own (easier) target: the CREDIT basis
    std::uint32_t max_bits = 0;      // sharechain max target (share-info max_bits)

    // ── ADD: the coinbase + branch — the whole point ────────────────────────
    // `coinbase` and `coinbase_payload` are the two pieces of the committed
    // coinbase txid preimage: concat(coinbase, coinbase_payload) is fed verbatim
    // to dash::coin::coinbase_txid (sha256d). `coinbase` is the base coinbase tx
    // (through locktime) and also the region the OP_RETURN ref_hash is read from;
    // `coinbase_payload` is the DIP4 CbTx extra_payload as it is appended (empty
    // for a legacy v1 coinbase). This mirrors DASHWorkSource::MintShareInputs
    // {coinbase_bytes, coinbase_payload}. merkle_root is NOT carried raw — it is
    // RECONSTRUCTED (fold of coinbase_txid through the branch) so a forged root is
    // caught by X11.
    std::vector<unsigned char> coinbase;          // base coinbase tx bytes (through locktime)
    std::vector<unsigned char> coinbase_payload;  // DIP4 extra_payload (appended); empty = legacy
    std::vector<bytes32> merkle_branch;           // dash::MerkleLink branch, index 0 (DASH v16)

    // ── reconstruction (steps 2-5 of the peer-verify recipe) ────────────────
    std::vector<unsigned char> full_coinbase() const {
        std::vector<unsigned char> v;
        v.reserve(coinbase.size() + coinbase_payload.size());
        v.insert(v.end(), coinbase.begin(), coinbase.end());
        v.insert(v.end(), coinbase_payload.begin(), coinbase_payload.end());
        return v;
    }
    uint256 coinbase_txid_u() const {
        return dash::coin::coinbase_txid(full_coinbase());
    }
    uint256 merkle_root_u() const {
        dash::MerkleLink link;
        link.m_index = 0;                       // DASH v16: coinbase is always the left leaf
        link.m_branch.reserve(merkle_branch.size());
        for (const bytes32& b : merkle_branch) link.m_branch.push_back(u256_from_internal(b));
        return dash::check_merkle_link(coinbase_txid_u(), link);
    }
    void fill_header80(unsigned char out[80]) const {
        dash::coin::serialize_header80(out, static_cast<std::int32_t>(version),
                                       u256_from_internal(prev_block_hash),
                                       merkle_root_u(), ntime, nbits, nonce);
    }
    uint256 pow_hash_u() const {
        unsigned char hdr[80];
        fill_header80(hdr);
        return dash::crypto::hash_x11(hdr, 80);   // the SSOT PoW (replaces sha256d)
    }

    // Canonical share id = the DASH share hash = X11(header). This is what
    // share_init_verify returns as block-AND-share identity. Dedup / relay-seen
    // key on it (replacing sha256d(preimage)). The event is treated as IMMUTABLE
    // after decode/construction (same contract as the frozen WorkEvent); if you
    // mutate a field, call reset_cache().
    bytes32 hash() const {
        if (!m_id_cache) m_id_cache = internal_from_u256(pow_hash_u());
        return *m_id_cache;
    }
    void reset_cache() const { m_id_cache.reset(); }

    // ── targets (step 6) ────────────────────────────────────────────────────
    uint256 share_target_u() const { return dash::coin::target_from_nbits(share_bits); }
    uint256 block_target_u() const { return dash::coin::target_from_nbits(nbits); }
    // The REAL "meets_own_target": X11 pow <= the sharechain (credit) target.
    bool meets_own_target() const {
        return dash::coin::meets_target(pow_hash_u(), share_bits);
    }
    // A solved DASH block: X11 pow also <= the mainchain block target.
    bool meets_block_target() const {
        return dash::coin::meets_target(pow_hash_u(), nbits);
    }
    // Credit = work of the SHARE target (target-based, ingestion-spec §4.1), via
    // the saturating floor(2^256/(T+1)) narrow shared with the synthetic path.
    u64 work() const { return work_from_target(be_from_u256(share_target_u())); }

    // ── payout commitment (step 8, structural) ──────────────────────────────
    // The coinbase's OP_RETURN output is [scriptlen 0x2a][OP_RETURN 0x6a][push
    // 0x28][ref_hash 32][nonce64 8] (share_check.hpp:806-813). Read the LAST such
    // marker in the BASE coinbase (never the DIP4 payload, which is a separate
    // field) so an accidental byte run in the payload can't spoof it. nullopt =>
    // the coinbase carries NO payout commitment (payout-unbound).
    std::optional<bytes32> op_return_ref_hash() const {
        const auto& c = coinbase;
        constexpr std::size_t kNeed = 3 + 32;   // 2a 6a 28 + ref_hash
        if (c.size() < kNeed) return std::nullopt;
        for (std::size_t i = c.size() - kNeed;; --i) {
            if (c[i] == 0x2a && c[i + 1] == 0x6a && c[i + 2] == 0x28) {
                bytes32 r{};
                for (int k = 0; k < 32; ++k) r[k] = c[i + 3 + k];
                return r;
            }
            if (i == 0) break;
        }
        return std::nullopt;
    }

    // The W3-MUST binding: the credited descriptor's identity key IS the carried
    // identity (w3_relay.hpp:208 CarrierWire::identity_bound, version-agnostic).
    bool identity_bound() const { return identity == descriptor.identity_key(); }

private:
    mutable std::optional<bytes32> m_id_cache;  // lazily-computed X11 share id (immutable event)
};

// ── a 0x02 carrier = one X11 share + 0..R_MAX X11 receipts ──────────────────
struct X11Carrier {
    X11ShareEvent carrier;
    std::vector<X11ShareEvent> receipts;
};

struct X11DecodeResult {
    WireStatus status = WireStatus::OK;             // reuses the w3_relay dispositions
    X11Carrier carrier;                             // valid iff status == OK
    std::vector<std::pair<std::string, ReceiptWireDrop>> dropped;
    bool ok() const { return status == WireStatus::OK; }
};

// ═══════════════════════════════════════════════════════════════════════════
// Wire codec for version 0x02. Little-endian, length-prefixed, no varints — the
// same idiom as CarrierWire, and the desc/ref/str/tag sub-encoding is BYTE-
// IDENTICAL to CarrierWire's so a descriptor is the same bytes on either version.
//
//   frame02 := u8 version (=0x02)
//              event02 carrier
//              u8 receipt_count (0..R_MAX; > R_MAX => REJECT_RMAX)
//              event02 receipt[receipt_count]
//   event02 := u32 chain_id
//              b32 identity
//              b32 prev_own_share
//              u32 version            (header nVersion)
//              b32 prev_block_hash    (header hashPrevBlock, INTERNAL order)
//              u32 ntime
//              u32 nbits
//              u32 nonce
//              u32 share_bits
//              u32 max_bits
//              vb  coinbase           (u32 len + bytes)
//              vb  coinbase_payload   (u32 len + bytes)
//              u8  branch_count ; branch_count x b32   (merkle branch, index 0)
//              desc descriptor        (frozen sub-encoding, verbatim)
//              str tag                (u16 len + bytes; bookkeeping, not PoW)
//   desc/ref/str/b32/uN — exactly as w3_relay.hpp's frozen v0x01 sub-encoding.
// ═══════════════════════════════════════════════════════════════════════════
class X11ShareWire {
public:
    static std::vector<std::uint8_t> encode(const X11Carrier& c) {
        std::vector<std::uint8_t> b;
        b.push_back(W3_WIRE_VERSION_X11);
        put_event(b, c.carrier);
        b.push_back(static_cast<std::uint8_t>(c.receipts.size()));
        for (const X11ShareEvent& r : c.receipts) put_event(b, r);
        return b;
    }

    // Decode + enforce the two version-agnostic anti-forgery rules (mirrors
    // CarrierWire::decode): (1) R_MAX -> whole-carrier reject; (2) W3-MUST
    // identity binding -> carrier mis-bound is fatal, a mis-bound receipt is
    // dropped (never relayed on) and the carrier stands.
    static X11DecodeResult decode(const std::vector<std::uint8_t>& b) {
        X11DecodeResult out;
        std::size_t p = 0;
        std::uint8_t ver = 0;
        if (!get_u8(b, p, ver)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }
        if (ver != W3_WIRE_VERSION_X11) { out.status = WireStatus::REJECT_BAD_VERSION; return out; }

        X11ShareEvent carrier;
        if (!get_event(b, p, carrier)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }

        std::uint8_t rc = 0;
        if (!get_u8(b, p, rc)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }
        if (rc > W3_R_MAX) { out.status = WireStatus::REJECT_RMAX; return out; }

        std::vector<X11ShareEvent> receipts;
        receipts.reserve(rc);
        for (std::uint8_t i = 0; i < rc; ++i) {
            X11ShareEvent r;
            if (!get_event(b, p, r)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }
            receipts.push_back(std::move(r));
        }
        if (p != b.size()) { out.status = WireStatus::REJECT_TRUNCATED; return out; }

        if (!carrier.identity_bound()) { out.status = WireStatus::REJECT_CARRIER_UNBOUND; return out; }
        out.carrier.carrier = std::move(carrier);
        for (X11ShareEvent& r : receipts) {
            if (!r.identity_bound()) {
                out.dropped.emplace_back(r.tag, ReceiptWireDrop::MISBOUND_IDENTITY);
                continue;
            }
            out.carrier.receipts.push_back(std::move(r));
        }
        out.status = WireStatus::OK;
        return out;
    }

    // Peek the version byte without decoding (nullopt on empty) — lets a top-level
    // dual-accept router send 0x01 to CarrierWire and 0x02 here.
    static std::optional<std::uint8_t> peek_version(const std::vector<std::uint8_t>& frame) {
        if (frame.empty()) return std::nullopt;
        return frame[0];
    }

private:
    static void put_u8(std::vector<std::uint8_t>& b, std::uint8_t v) { b.push_back(v); }
    static void put_u16(std::vector<std::uint8_t>& b, std::uint16_t v) {
        for (int i = 0; i < 2; ++i) b.push_back((std::uint8_t)(v >> (8 * i)));
    }
    static void put_u32(std::vector<std::uint8_t>& b, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) b.push_back((std::uint8_t)(v >> (8 * i)));
    }
    static void put_bytes32(std::vector<std::uint8_t>& b, const bytes32& h) {
        b.insert(b.end(), h.begin(), h.end());
    }
    static void put_varbytes(std::vector<std::uint8_t>& b, const std::vector<unsigned char>& v) {
        put_u32(b, static_cast<std::uint32_t>(v.size()));
        b.insert(b.end(), v.begin(), v.end());
    }
    // desc/ref/str: byte-identical to w3_relay.hpp CarrierWire (the frozen shape).
    static void put_ref(std::vector<std::uint8_t>& b, const ::v37::ScriptRef& r) {
        put_u8(b, static_cast<std::uint8_t>(r.kind));
        put_u8(b, static_cast<std::uint8_t>(r.payload.size()));
        b.insert(b.end(), r.payload.begin(), r.payload.end());
    }
    static void put_desc(std::vector<std::uint8_t>& b, const ::v37::PayoutDescriptor& d) {
        put_ref(b, d.pay);
        put_u8(b, d.attribution.has_value() ? 1 : 0);
        if (d.attribution.has_value()) put_ref(b, *d.attribution);
        put_u16(b, static_cast<std::uint16_t>(d.aux.size()));
        for (const auto& e : d.aux) { put_u32(b, e.chain_id); put_ref(b, e.ref); }
        put_u16(b, static_cast<std::uint16_t>(d.raw_script.size()));
        b.insert(b.end(), d.raw_script.begin(), d.raw_script.end());
    }
    static void put_str(std::vector<std::uint8_t>& b, const std::string& s) {
        put_u16(b, static_cast<std::uint16_t>(s.size()));
        b.insert(b.end(), s.begin(), s.end());
    }
    static void put_event(std::vector<std::uint8_t>& b, const X11ShareEvent& e) {
        put_u32(b, e.chain_id);
        put_bytes32(b, e.identity);
        put_bytes32(b, e.prev_own_share);
        put_u32(b, e.version);
        put_bytes32(b, e.prev_block_hash);
        put_u32(b, e.ntime);
        put_u32(b, e.nbits);
        put_u32(b, e.nonce);
        put_u32(b, e.share_bits);
        put_u32(b, e.max_bits);
        put_varbytes(b, e.coinbase);
        put_varbytes(b, e.coinbase_payload);
        put_u8(b, static_cast<std::uint8_t>(e.merkle_branch.size()));
        for (const bytes32& h : e.merkle_branch) put_bytes32(b, h);
        put_desc(b, e.descriptor);
        put_str(b, e.tag);
    }

    static bool get_u8(const std::vector<std::uint8_t>& b, std::size_t& p, std::uint8_t& v) {
        if (p + 1 > b.size()) return false;
        v = b[p++]; return true;
    }
    static bool get_u16(const std::vector<std::uint8_t>& b, std::size_t& p, std::uint16_t& v) {
        if (p + 2 > b.size()) return false;
        v = 0; for (int i = 0; i < 2; ++i) v |= (std::uint16_t)b[p++] << (8 * i);
        return true;
    }
    static bool get_u32(const std::vector<std::uint8_t>& b, std::size_t& p, std::uint32_t& v) {
        if (p + 4 > b.size()) return false;
        v = 0; for (int i = 0; i < 4; ++i) v |= (std::uint32_t)b[p++] << (8 * i);
        return true;
    }
    static bool get_bytes32(const std::vector<std::uint8_t>& b, std::size_t& p, bytes32& h) {
        if (p + 32 > b.size()) return false;
        for (int i = 0; i < 32; ++i) h[i] = b[p++];
        return true;
    }
    static bool get_varbytes(const std::vector<std::uint8_t>& b, std::size_t& p,
                             std::vector<unsigned char>& v) {
        std::uint32_t n = 0;
        if (!get_u32(b, p, n)) return false;
        if (p + n > b.size()) return false;
        v.assign(b.begin() + p, b.begin() + p + n);
        p += n;
        return true;
    }
    static bool get_ref(const std::vector<std::uint8_t>& b, std::size_t& p, ::v37::ScriptRef& r) {
        std::uint8_t kind = 0, len = 0;
        if (!get_u8(b, p, kind) || !get_u8(b, p, len)) return false;
        if (p + len > b.size()) return false;
        r.kind = static_cast<::v37::ScriptKind>(kind);
        r.payload.assign(b.begin() + p, b.begin() + p + len);
        p += len;
        return true;
    }
    static bool get_desc(const std::vector<std::uint8_t>& b, std::size_t& p, ::v37::PayoutDescriptor& d) {
        if (!get_ref(b, p, d.pay)) return false;
        std::uint8_t has_attr = 0;
        if (!get_u8(b, p, has_attr)) return false;
        if (has_attr) {
            ::v37::ScriptRef a;
            if (!get_ref(b, p, a)) return false;
            d.attribution = a;
        }
        std::uint16_t naux = 0;
        if (!get_u16(b, p, naux)) return false;
        d.aux.clear();
        for (std::uint16_t i = 0; i < naux; ++i) {
            ::v37::AuxEntry e;
            if (!get_u32(b, p, e.chain_id) || !get_ref(b, p, e.ref)) return false;
            d.aux.push_back(std::move(e));
        }
        std::uint16_t rs = 0;
        if (!get_u16(b, p, rs)) return false;
        if (p + rs > b.size()) return false;
        d.raw_script.assign(b.begin() + p, b.begin() + p + rs);
        p += rs;
        return true;
    }
    static bool get_str(const std::vector<std::uint8_t>& b, std::size_t& p, std::string& s) {
        std::uint16_t n = 0;
        if (!get_u16(b, p, n)) return false;
        if (p + n > b.size()) return false;
        s.assign(b.begin() + p, b.begin() + p + n);
        p += n;
        return true;
    }
    static bool get_event(const std::vector<std::uint8_t>& b, std::size_t& p, X11ShareEvent& e) {
        if (!get_u32(b, p, e.chain_id)) return false;
        if (!get_bytes32(b, p, e.identity)) return false;
        if (!get_bytes32(b, p, e.prev_own_share)) return false;
        if (!get_u32(b, p, e.version)) return false;
        if (!get_bytes32(b, p, e.prev_block_hash)) return false;
        if (!get_u32(b, p, e.ntime)) return false;
        if (!get_u32(b, p, e.nbits)) return false;
        if (!get_u32(b, p, e.nonce)) return false;
        if (!get_u32(b, p, e.share_bits)) return false;
        if (!get_u32(b, p, e.max_bits)) return false;
        if (!get_varbytes(b, p, e.coinbase)) return false;
        if (!get_varbytes(b, p, e.coinbase_payload)) return false;
        std::uint8_t bc = 0;
        if (!get_u8(b, p, bc)) return false;
        e.merkle_branch.clear();
        e.merkle_branch.reserve(bc);
        for (std::uint8_t i = 0; i < bc; ++i) {
            bytes32 h{};
            if (!get_bytes32(b, p, h)) return false;
            e.merkle_branch.push_back(h);
        }
        if (!get_desc(b, p, e.descriptor)) return false;
        if (!get_str(b, p, e.tag)) return false;
        e.reset_cache();
        return true;
    }
};

// Independent size model (mirrors w3_wire_freeze.hpp's frame_size/event_size).
// Lets the 0x02 golden KAT prove encode(c).size() == frame02_size(c) on any
// carrier; the 0x02 event is variable-length, so it has its own derivation.
inline std::size_t x11_desc_size(const ::v37::PayoutDescriptor& d) {
    auto ref_size = [](const ::v37::ScriptRef& r) { return 2 + r.payload.size(); };
    std::size_t n = ref_size(d.pay) + 1;                         // pay + has_attribution
    if (d.attribution.has_value()) n += ref_size(*d.attribution);
    n += 2;                                                       // aux_count u16
    for (const auto& e : d.aux) n += 4 + ref_size(e.ref);        // chain_id + ref
    n += 2 + d.raw_script.size();                                // raw_script_len u16 + bytes
    return n;
}
inline std::size_t x11_event_size(const X11ShareEvent& e) {
    return 4 + 32 + 32          // chain_id + identity + prev_own_share
         + 4 + 32               // version + prev_block_hash
         + 4 + 4 + 4 + 4 + 4    // ntime + nbits + nonce + share_bits + max_bits
         + 4 + e.coinbase.size()
         + 4 + e.coinbase_payload.size()
         + 1 + e.merkle_branch.size() * 32
         + x11_desc_size(e.descriptor)
         + 2 + e.tag.size();
}
inline std::size_t x11_frame_size(const X11Carrier& c) {
    std::size_t n = 1 + x11_event_size(c.carrier) + 1;   // version + carrier + receipt_count
    for (const X11ShareEvent& r : c.receipts) n += x11_event_size(r);
    return n;
}

// ═══════════════════════════════════════════════════════════════════════════
// The peer-verify seams (steps 7 + 8 of the recipe). Reuse the SAME W2 seams
// (IMainchainIndex::height_of, IShareTracker::has_prev_own) unchanged.
// ═══════════════════════════════════════════════════════════════════════════

// R-1 consensus-target oracle: the node's authority on the DASH mainchain BLOCK
// bits and the sharechain SHARE bits in force at a given origin bin (height).
// Replaces the synthetic consensus_lz(bin) check. nullopt => the node cannot
// confirm the bits for that bin, so R-1 fails closed.
struct IConsensusTargets {
    virtual ~IConsensusTargets() = default;
    virtual std::optional<std::uint32_t> block_bits_at(u64 bin) const = 0;
    virtual std::optional<std::uint32_t> share_bits_at(u64 bin) const = 0;
};

// The DEEP payout oracle (optional). The node binds dash::generate_share_transaction
// + dash::verify_payout_commitment (which need its share-tracker chain) here:
// given the event and the ref_hash extracted from its coinbase OP_RETURN, return
// true iff (a) ref_hash recomputes from the share fields AND (b) the coinbase pays
// the correct PPLNS window (committed gentx txid == expected). Unset (nullptr) =>
// the structural chain still holds — OP_RETURN present + identity_bound + the
// coinbase committed under X11 via the branch — the node just hasn't wired the
// PPLNS re-derivation yet (fail-open ONLY on the deep re-derivation, never on the
// cryptographic chain, which is always enforced).
using X11PayoutOracle =
    std::function<bool(const X11ShareEvent& e, const bytes32& ref_hash)>;

// ═══════════════════════════════════════════════════════════════════════════
// X11ReceiptAdmitter — the 0x02 analogue of ReceiptAdmitter. Same consensus
// disposition order (PoW -> R-1 -> identity -> prev-own -> chain -> expiry ->
// dedup), same push sequence (carrier, then receipts flagged L0F_RECEIPT), same
// target-based credit. Only step-1 PoW recompute and the step-3 identity binding
// change from synthetic-sha256d to real-X11 + coinbase-commitment. Reuses the W2
// DedupWindow / EmittedPush / seam interfaces verbatim.
// ═══════════════════════════════════════════════════════════════════════════
class X11ReceiptAdmitter {
public:
    struct Result {
        CarrierStatus carrier_status = CarrierStatus::OK;
        std::vector<std::pair<std::string, Disposition>> receipts;  // (tag, disp)
        std::vector<EmittedPush> pushes;                            // emission order
    };

    X11ReceiptAdmitter(std::uint32_t chain_id, const IMainchainIndex& index,
                       IShareTracker& tracker, const IConsensusTargets& targets,
                       X11PayoutOracle oracle = {}, u64 incarnation = 1)
        : m_chain(chain_id), m_index(index), m_tracker(tracker), m_targets(targets),
          m_oracle(std::move(oracle)), m_window(chain_id, incarnation),
          m_incarnation(incarnation) {}

    void reset_incarnation(u64 new_incarnation) {
        m_incarnation = new_incarnation;
        m_window = DedupWindow(m_chain, new_incarnation);
        m_next_pos = 0;
        m_raw_total = 0;
    }

    // R-1: the header's mainchain bits AND the share bits both match consensus for
    // the resolved bin (replaces lz_bits == consensus_lz). Fail-closed when the
    // oracle cannot supply the bits.
    bool r1_ok(const X11ShareEvent& e, u64 bin) const {
        auto bb = m_targets.block_bits_at(bin);
        auto sb = m_targets.share_bits_at(bin);
        return bb.has_value() && sb.has_value() && e.nbits == *bb && e.share_bits == *sb;
    }

    // The migrated RDWR payout/identity binding (step 8): the credited descriptor
    // owns the carried identity (W3-MUST), the coinbase carries a ref_hash payout
    // commitment (committed under X11 via the branch), and — where wired — the
    // deep PPLNS re-derivation agrees.
    bool payout_bound(const X11ShareEvent& e) const {
        if (!e.identity_bound()) return false;
        auto ref = e.op_return_ref_hash();
        if (!ref.has_value()) return false;
        if (m_oracle && !m_oracle(e, *ref)) return false;
        return true;
    }

    Disposition validate_receipt(const X11ShareEvent& r, const X11ShareEvent& carrier,
                                 u64 carrier_bin) const {
        // 1. PoW: X11 over the reconstructed header meets the share target.
        if (!r.meets_own_target()) return Disposition::REJECT_POW;
        // 2. R-1: mainchain + share bits pin to consensus for bin(receipt), when
        //    the bin resolves (an unresolvable bin is caught at step 4).
        std::optional<u64> rb = m_index.height_of(r.prev_block_hash);
        if (rb.has_value() && !r1_ok(r, *rb)) return Disposition::REJECT_R1_TARGET;
        // 3a. self-carriage + migrated coinbase-commitment identity binding.
        if (!(r.identity == carrier.identity)) return Disposition::REJECT_IDENTITY;
        if (!payout_bound(r)) return Disposition::REJECT_IDENTITY;
        // 3b. prev-own-share on the miner's chain (durable tracker).
        if (!m_tracker.has_prev_own(r.identity, r.prev_own_share))
            return Disposition::REJECT_PREV_OWN;
        // 3c. chain id.
        if (r.chain_id != m_chain) return Disposition::REJECT_CHAIN;
        // 4. context window: unresolvable / future / older than N_CTX.
        if (!rb.has_value() || *rb > carrier_bin || carrier_bin - *rb > W2_N_CTX)
            return Disposition::REJECT_EXPIRED;
        // 5. dedup (the single window dedup), keyed on the X11 share id.
        if (m_window.contains(r.hash())) return Disposition::REJECT_DEDUP;
        return Disposition::OK;
    }

    Result admit(const X11ShareEvent& carrier, const std::vector<X11ShareEvent>& receipts,
                 const RecordSink& sink = {}) {
        Result out;
        if (receipts.size() > W2_R_MAX) { out.carrier_status = CarrierStatus::REJECT_RMAX; return out; }

        std::optional<u64> carrier_bin = m_index.height_of(carrier.prev_block_hash);
        if (!carrier_bin.has_value() || !carrier.meets_own_target() ||
            !r1_ok(carrier, *carrier_bin) || carrier.chain_id != m_chain ||
            !payout_bound(carrier)) {
            out.carrier_status = CarrierStatus::REJECT_POW;
            return out;
        }
        m_window.prune(*carrier_bin);
        if (m_window.contains(carrier.hash())) { out.carrier_status = CarrierStatus::REJECT_DEDUP; return out; }

        // §4.2 step 1: the carrier push (carrier position, no receipt flag).
        emit(out, sink, carrier.identity, carrier.descriptor, carrier.work(),
             W2_CARRIER_FLAGS, *carrier_bin, *carrier_bin, carrier.tag);
        m_window.add(carrier.hash(), *carrier_bin);
        m_tracker.record_share(carrier.identity, carrier.hash());

        // §4.2 step 2: receipts in WIRE order; invalid entries ignored in place.
        for (const X11ShareEvent& r : receipts) {
            Disposition disp = validate_receipt(r, carrier, *carrier_bin);
            out.receipts.emplace_back(r.tag, disp);
            if (disp != Disposition::OK) continue;
            u64 origin_bin = *m_index.height_of(r.prev_block_hash);
            emit(out, sink, carrier.identity, carrier.descriptor, r.work(),
                 W2_CARRIER_FLAGS | W2_L0F_RECEIPT, origin_bin, *carrier_bin, r.tag);
            m_window.add(r.hash(), *carrier_bin);
        }
        return out;
    }

    const DedupWindow& window() const { return m_window; }
    u64 next_pos() const { return m_next_pos; }
    ::v37::u128 raw_total() const { return m_raw_total; }
    u64 incarnation() const { return m_incarnation; }
    std::uint32_t chain() const { return m_chain; }

private:
    void emit(Result& out, const RecordSink& sink, const bytes32& identity,
              const ::v37::PayoutDescriptor& desc, u64 w_raw, std::uint32_t flags,
              u64 origin_bin, u64 carrier_bin, const std::string& tag) {
        EmittedPush p;
        p.identity = identity;
        p.descriptor = desc;
        p.w_raw = w_raw;
        p.flags = flags;
        p.pos = m_next_pos;
        p.origin_bin = origin_bin;
        p.carrier_bin = carrier_bin;
        p.tag = tag;
        ++m_next_pos;
        m_raw_total += w_raw;
        out.pushes.push_back(p);
        if (sink) sink(p);
    }

    std::uint32_t m_chain;
    const IMainchainIndex& m_index;
    IShareTracker& m_tracker;
    const IConsensusTargets& m_targets;
    X11PayoutOracle m_oracle;
    DedupWindow m_window;
    u64 m_incarnation;
    u64 m_next_pos = 0;
    ::v37::u128 m_raw_total = 0;
};

// ═══════════════════════════════════════════════════════════════════════════
// Boot / KAT self-check. Pure and deterministic — it never needs a mined nonce
// (targets are not asserted met). It proves: (1) encode/decode is lossless; (2)
// the reconstruction chain is self-consistent (coinbase_txid -> merkle_root ->
// header -> X11 matches an independent recompute); (3) the OP_RETURN payout
// commitment is recovered; (4) tampering the coinbase changes the merkle_root,
// hence the X11 share id — the trustless property the synthetic frame cannot
// offer; (5) the share/block target ordering the credit basis relies on. The
// X11 golden-vector KAT (a pinned pow_hash for a fixed header) lives alongside
// the existing dash X11 KATs; this check computes X11 live for consistency only.
// ═══════════════════════════════════════════════════════════════════════════
struct X11SelfCheck {
    unsigned checks = 0;
    unsigned failures = 0;
    std::string log;
    bool ok() const { return failures == 0; }
};

inline bool x11_events_equal(const X11ShareEvent& a, const X11ShareEvent& b) {
    return a.chain_id == b.chain_id && a.identity == b.identity &&
           a.prev_own_share == b.prev_own_share && a.version == b.version &&
           a.prev_block_hash == b.prev_block_hash && a.ntime == b.ntime &&
           a.nbits == b.nbits && a.nonce == b.nonce && a.share_bits == b.share_bits &&
           a.max_bits == b.max_bits && a.coinbase == b.coinbase &&
           a.coinbase_payload == b.coinbase_payload && a.merkle_branch == b.merkle_branch &&
           a.tag == b.tag && a.descriptor.identity_key() == b.descriptor.identity_key();
}

inline X11SelfCheck x11_selfcheck() {
    X11SelfCheck sc;
    auto chk = [&](bool cond, const char* what) {
        ++sc.checks;
        if (!cond) { sc.failures++; sc.log += "FAIL "; sc.log += what; sc.log += "\n"; }
        return cond;
    };

    // A self-bound P2PKH descriptor (identity == identity_key()).
    ::v37::PayoutDescriptor d;
    d.pay.kind = ::v37::ScriptKind::P2PKH;
    d.pay.payload.assign(20, 0x11);

    // A minimal coinbase whose last output is the ref_hash OP_RETURN.
    bytes32 ref{};
    for (int i = 0; i < 32; ++i) ref[i] = static_cast<std::uint8_t>(0x40 + i);
    std::vector<unsigned char> cb = {0x03, 0x00, 0x01, 0x02};   // stand-in tx prefix
    cb.push_back(0x2a); cb.push_back(0x6a); cb.push_back(0x28);  // scriptlen, OP_RETURN, push40
    cb.insert(cb.end(), ref.begin(), ref.end());                // ref_hash (32)
    for (int i = 0; i < 8; ++i) cb.push_back(0x00);             // nonce64 (8)
    cb.insert(cb.end(), {0x00, 0x00, 0x00, 0x00});             // locktime

    X11ShareEvent e;
    e.chain_id = 1;
    e.descriptor = d;
    e.identity = d.identity_key();
    for (int i = 0; i < 32; ++i) e.prev_block_hash[i] = static_cast<std::uint8_t>(0x80 + i);
    e.version = 0x20000000u;
    e.ntime = 1700000000u;
    e.nbits = 0x1f00ffffu;        // harder mainchain block target
    e.share_bits = 0x207fffffu;   // easier sharechain (credit) target
    e.max_bits = 0x207fffffu;
    e.nonce = 12345u;
    e.coinbase = cb;
    e.tag = "cb";

    X11Carrier c;
    c.carrier = e;
    { X11ShareEvent r = e; r.prev_own_share[0] = 0x01; r.tag = "r0"; c.receipts.push_back(r); }

    // (1) round-trip
    auto bytes = X11ShareWire::encode(c);
    chk(bytes.size() == x11_frame_size(c), "size == x11_frame_size model");
    chk(!bytes.empty() && bytes[0] == W3_WIRE_VERSION_X11, "version byte 0x02 @0");
    X11DecodeResult dr = X11ShareWire::decode(bytes);
    chk(dr.status == WireStatus::OK, "decode OK");
    chk(dr.dropped.empty(), "no receipt dropped");
    chk(x11_events_equal(dr.carrier.carrier, c.carrier), "carrier round-trips");
    chk(dr.carrier.receipts.size() == 1 && x11_events_equal(dr.carrier.receipts[0], c.receipts[0]),
        "receipt round-trips");
    chk(X11ShareWire::encode(dr.carrier) == bytes, "re-encode byte-identical");

    // (2) reconstruction chain is self-consistent with an independent recompute
    uint256 txid = e.coinbase_txid_u();
    chk(txid == dash::coin::coinbase_txid(e.full_coinbase()), "coinbase_txid == sha256d(full)");
    chk(e.merkle_root_u() == txid, "empty branch => merkle_root == coinbase_txid");
    unsigned char hdr[80];
    e.fill_header80(hdr);
    chk(dash::crypto::hash_x11(hdr, 80) == e.pow_hash_u(), "pow == X11(independent header)");

    // (3) OP_RETURN payout commitment recovered
    auto got = e.op_return_ref_hash();
    chk(got.has_value() && *got == ref, "OP_RETURN ref_hash recovered");

    // (4) tamper-evidence: change the coinbase => different merkle_root => different id
    X11ShareEvent tampered = e;
    tampered.coinbase[1] ^= 0x01;
    tampered.reset_cache();
    chk(tampered.merkle_root_u() != e.merkle_root_u(), "tampered coinbase changes merkle_root");
    chk(tampered.hash() != e.hash(), "tampered coinbase changes X11 share id");

    // (5) target ordering the credit basis relies on
    chk(e.share_target_u() >= e.block_target_u(), "share target >= block target (easier)");
    chk(e.work() > 0, "work(share_target) > 0");
    chk(e.meets_block_target() ? e.meets_own_target() : true, "meets block => meets share");
    chk(e.identity_bound(), "identity_bound (W3-MUST)");

    // (6) W3-MUST: a mis-bound carrier is a fatal decode reject
    {
        X11Carrier bad = c;
        bad.carrier.identity[0] ^= 0x01;
        chk(X11ShareWire::encode(bad).size() == x11_frame_size(bad), "mis-bound size model holds");
        chk(X11ShareWire::decode(X11ShareWire::encode(bad)).status == WireStatus::REJECT_CARRIER_UNBOUND,
            "mis-bound carrier rejected");
    }
    // (7) a mis-bound receipt is dropped, carrier stands
    {
        X11Carrier bad = c;
        bad.receipts[0].identity[0] ^= 0x01;
        X11DecodeResult d2 = X11ShareWire::decode(X11ShareWire::encode(bad));
        chk(d2.status == WireStatus::OK && d2.dropped.size() == 1 && d2.carrier.receipts.empty(),
            "mis-bound receipt dropped, carrier stands");
    }
    // (8) R_MAX+1 receipts => whole-carrier reject
    {
        std::vector<std::uint8_t> b = bytes;
        std::size_t rc_off = 1 + x11_event_size(c.carrier);
        if (chk(rc_off < b.size(), "receipt_count offset in range")) {
            b[rc_off] = static_cast<std::uint8_t>(W3_R_MAX + 1);
            // truncated because the frame no longer carries that many receipts,
            // OR REJECT_RMAX if enough bytes follow; both are correct rejections.
            WireStatus s = X11ShareWire::decode(b).status;
            chk(s == WireStatus::REJECT_RMAX || s == WireStatus::REJECT_TRUNCATED,
                "receipt_count > R_MAX rejected");
        }
    }
    return sc;
}

} // namespace c2pool::v37n
