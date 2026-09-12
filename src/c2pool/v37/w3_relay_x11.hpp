#pragma once
// V37 Track A2 / W3 / S-1 — CARRIER-WIRE 0x02 (the REAL X11 share envelope).
// CONSUMER-tree code (src/c2pool/v37/). Header-only, stdlib-only (no sockets,
// no threads, no Boost, no btclibs) so it links into every v37 unit suite AND
// the daemon, EXACTLY like w3_relay.hpp / w3_wire_freeze.hpp. The one heavy
// dependency the honest share envelope needs — the X11 permutation itself
// (BLAKE..ECHO, which is NOT stdlib) — is reached through a single injected
// function hook (x11_hash hook, below), the same fail-closed hook pattern the
// P-1 XMR validator (v37_descriptor.hpp set_xmr_descriptor_validator) and the
// ICarrierTransport seam already use. The daemon and the dash byte-KAT install
// dash::crypto::hash_x11; a build with no hook installed verifies fail-closed.
//
// ── WHAT THIS FILE IS (S-1, the real-share-format version bump) ─────────────
//   The v0x01 carrier wire (w3_relay.hpp, FROZEN by w3_wire_freeze.hpp) carries
//   a SYNTHETIC RDWR PoW envelope: a header-SHAPED sha256d preimage whose fake
//   PoW (leading_zero_bits >= lz_bits) proves NOTHING about DASH mainchain work,
//   and whose payout identity is bound only by sitting inside that preimage. The
//   HONEST BOUNDARY note in w3_wire_freeze.hpp:98-102 always said the container
//   is frozen but the SEMANTICS widen "when real share format lands ... a
//   version bump (0x02) with its own goldens, per the version policy". THIS FILE
//   is that 0x02 bump. It carries the fields that RECONSTRUCT and VERIFY a real
//   DASH X11 share (the DASHWorkSource::MintShareInputs tuple, work_source.hpp
//   :154-185) and it is verified by reproducing the shipped node's own hot path
//   (dash::stratum::DASHWorkSource::mining_submit + dash::share_init_verify):
//     (a) X11 over the reconstructed 80-byte header meets a target  = real work;
//     (b) header.hashPrevBlock (prev_block_hash) pins the work to a DASH bin;
//     (c) coinbase_txid folds through the merkle branch up to the header's
//         merkle_root, and the coinbase's OP_RETURN ref_hash commits WHO gets
//         paid — so the RDWR identity binding MIGRATES from "sha256d preimage"
//         (v0x01) to "the ref_hash OP_RETURN carried in the coinbase that the
//         merkle branch + X11 header commit to" (v0x02). The synthetic model
//         FAKES (a) with sha256d and (c) by preimage inclusion; this EARNS both.
//
// ── NOT A RE-PACK OF v0x01 (mandated by VERSION POLICY F-5) ─────────────────
//   The 0x01 event is a FIXED 112-byte prefix pinned by static_assert
//   (w3_wire_freeze.hpp kEventFixedBytes==112) and a golden byte-KAT. The 0x02
//   event CANNOT satisfy that prefix: the field SET changes SHAPE, not just
//   meaning — the synthetic u64 nonce becomes a real u32 header nonce; lz_bits
//   (u32) is dropped in favour of header_version + ntime + nbits + nonce +
//   share_bits + max_bits; last_txout_nonce (u64) is added; and THREE variable-
//   length members (coinbase, coinbase_payload, merkle_branch) appear. Editing
//   0x01 in place would silently reinterpret every peer's frozen bytes and trip
//   the freeze KAT that exists precisely to forbid it. So 0x02 is a NEW layout
//   with its OWN size/offset model, its OWN fixtures, and its OWN golden hex
//   (namespace wire_x11, below). The frozen 0x01 codec (CarrierWire) and its
//   goldens are UNTOUCHED by this file; decode_any() below routes a 0x01 frame
//   to the frozen decoder VERBATIM and a 0x02 frame here — the dual-accept
//   window the version policy requires, with ZERO edit to the frozen file.
//
// ── THE v0x02 LAYOUT (canonical; little-endian throughout; no varints) ──────
//   frame  := u8 version(=0x02)
//             event02 carrier
//             u8      receipt_count (0..R_MAX; a decoder seeing >R_MAX rejects)
//             event02 receipt[receipt_count]
//   event02:= u32 chain_id                                  (RDWR member 1)
//             b32 identity            (payout-descriptor identity key; RDWR 2)
//             b32 prev_block_hash     (header.hashPrevBlock, INTERNAL LE; RDWR 3
//                                      AND the real header prev-block -> bin)
//             b32 prev_own_share      (RDWR member 4)
//             u32 header_version      (block header nVersion)
//             u32 ntime               (block header nTime)
//             u32 nbits               (block header nBits — mainchain target)
//             u32 nonce               (block header nonce — REAL u32 grind word)
//             u32 share_bits          (sharechain credited target; work basis)
//             u32 max_bits            (sharechain max/floor target)
//             u64 last_txout_nonce    (nonce64 in the OP_RETURN commitment slot)
//             vb32 coinbase           (u32 len + bytes = full gentx tx)
//             vb32 coinbase_payload   (u32 len + bytes = DIP4 CbTx extra_payload)
//             u8 branch_count ; branch_count x b32   (merkle branch; DASH v16
//                                      index is always 0 -> cur is always left)
//             desc descriptor         (SAME desc/ref sub-encoding as v0x01)
//             str tag                 (u16 len + bytes; bookkeeping, not PoW)
//   desc/ref/str/b32/uN : byte-identical to the v0x01 sub-encodings
//                         (w3_relay.hpp header byte-map), reused verbatim.
//   vb32   := u32 len ; len bytes                       (LITTLE-ENDIAN length)
//
//   merkle_root is NOT carried raw — it is RECONSTRUCTED (fold of coinbase_txid
//   through the branch), so a forged root is caught by X11 over the header.
//
// Transport framing ([u32 LE length][frame], 1 MiB ceiling, carrier_net.hpp) is
// unchanged and carries either version; R_MAX=4, identity-binding and dedup /
// push-sequence rules are version-agnostic and carry over (w2_admission.hpp).

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "w3_relay.hpp"   // Carrier, CarrierWire, WireStatus, ReceiptWireDrop,
                          // WorkEvent, W3_R_MAX, bytes32, sha256d, work_from_target

namespace c2pool::v37n {

// v0x02 wire version tag. This is a SEPARATE constant from W3_WIRE_VERSION
// (=0x01, the frozen synthetic wire); the two layouts COEXIST for the upgrade
// window (VERSION POLICY F-5). A node that mints real X11 carriers encodes with
// X11CarrierWire (version 0x02); a peer decodes EITHER via decode_any().
constexpr std::uint8_t W3_WIRE_VERSION_X11 = 0x02;

// Dual-accept version set for the upgrade window: {0x01, 0x02}. decode_any()
// routes by the frame's version byte; the frozen CarrierWire still accepts only
// {0x01} on its own (so the freeze KAT stays green — the dual-accept lives in
// the NEW front door, not by mutating the frozen decoder).
inline constexpr std::uint8_t kAcceptedVersionsDual[] = {
    W3_WIRE_VERSION,       // 0x01 synthetic (frozen)
    W3_WIRE_VERSION_X11,   // 0x02 real X11
};
inline bool version_accepted_dual(std::uint8_t v) {
    for (std::uint8_t a : kAcceptedVersionsDual) if (a == v) return true;
    return false;
}

// ═══════════════════════════════════════════════════════════════════════════
// The X11 permutation SEAM (the ONE non-stdlib dependency), fail-closed.
//
// This file is the WIRE layer and deliberately links nothing: no target math, no
// X11, no verify dispositions live here any more. They are the DASH SSOT
// (impl/dash/x11_share_verify.hpp -> dash::crypto::hash_x11,
// dash::coin::target_from_nbits / meets_target / serialize_header80 /
// coinbase_txid, dash::fold_merkle_branch, dash::extract_op_return_commitment),
// reached from the BIND/CREDIT layer (c2pool/v37/x11_share_envelope.hpp).
//
// The hook exists so a STDLIB-ONLY consumer (the relay hot path, a wire-only
// unit target) can be handed the genuine permutation without linking the SSOT.
// The single supported installer is
// c2pool::v37n::install_dash_x11_hook() (x11_share_envelope.hpp), which sets
//
//   set_x11_hash([](const std::uint8_t* hdr80) {
//       return internal_from_u256(dash::crypto::hash_x11(hdr80, 80));
//   });
//
// i.e. the digest in uint256 INTERNAL (little-endian data()) order — the same
// bytes dash::X11VerifyResult::pow_hash carries, so the two are directly
// comparable. v37_a2_x11_real_pow_kat (RX-12) asserts exactly that equality, and
// asserts the hook is nullptr before installation. With no hook installed a
// stdlib-only consumer gets nullptr and MUST fail closed; it never gets a
// spurious pass — identical discipline to the XMR P-1 validator seam.
//
// GAP (declared, not hidden): until the S-1 activation wires w2_admission to the
// real PoW, NOTHING in-tree calls the hook on a consensus path. It is an
// installation seam under test, not a live verifier.
// ═══════════════════════════════════════════════════════════════════════════
using x11_hash_fn = ::v37::bytes32 (*)(const std::uint8_t* header80);
inline x11_hash_fn& x11_hash_hook() {
    static x11_hash_fn fn = nullptr;   // fail-closed
    return fn;
}
inline void set_x11_hash(x11_hash_fn fn) { x11_hash_hook() = fn; }

// ═══════════════════════════════════════════════════════════════════════════
// The v0x02 X11 work event — one carrier or one receipt. A PURE POD: it carries
// the fields, it does not hash them. Replaces WorkEvent's synthetic
// {lz_bits, u64 nonce} + preimage with the real 80-byte-header fields plus the
// coinbase/branch that make the payout trustlessly verifiable. `descriptor` is
// the real self-carriage push target (as in v0x01); `identity` is still carried
// and W3-MUST-bound to descriptor.identity_key(), but its consensus binding is
// now the coinbase OP_RETURN commitment, not a preimage.
//
// The share id, the merkle fold, the 80-byte serialization, the targets and the
// credit are NOT members: they are L3 free functions (x11_share_envelope.hpp:
// x11_share_id / x11_merkle_root_u / x11_fill_header80 / x11_meets_own_target /
// x11_work) that delegate to the DASH SSOT verbatim. One PoW implementation, in
// one place. The only hash this struct computes is wire_id(), which is network
// hygiene (relay dedup before verification is possible) and NEVER consensus.
// ═══════════════════════════════════════════════════════════════════════════
struct X11WorkEvent {
    std::uint32_t chain_id = 0;              // RDWR member 1
    bytes32 identity{};                      // RDWR member 2 (descriptor identity key)
    bytes32 prev_block_hash{};               // header.hashPrevBlock (internal LE); RDWR 3
    bytes32 prev_own_share{};                // RDWR member 4
    std::uint32_t header_version = 0;        // block header nVersion  (serialize_header80)
    std::uint32_t ntime = 0;                 // block header nTime
    std::uint32_t nbits = 0;                 // block header nBits (mainchain/block target)
    std::uint32_t nonce = 0;                 // block header nonce (REAL u32 grind word)
    std::uint32_t share_bits = 0;            // sharechain credited target (work basis)
    std::uint32_t max_bits = 0;              // sharechain max/floor target
    std::uint64_t last_txout_nonce = 0;      // nonce64 in the OP_RETURN slot
    std::vector<std::uint8_t> coinbase;          // full gentx tx bytes
    std::vector<std::uint8_t> coinbase_payload;  // DIP4 CbTx extra_payload
    std::vector<bytes32> merkle_branch;          // DASH v16: index always 0
    ::v37::PayoutDescriptor descriptor;          // real descriptor (self-carriage)
    std::string tag;                             // bookkeeping only (NOT hashed)

    // A stable, X11-independent id over the identity-bearing fields, for the
    // RELAY-layer dedup set (RelaySeenSet) BEFORE X11 verification is possible
    // (mirrors v0x01 relay keying on the carrier hash — network hygiene, never
    // consensus). The CONSENSUS dedup key is the verified X11 share id
    // (dash::verify_x11_share -> X11VerifyResult::pow_hash), never this.
    bytes32 wire_id() const {
        std::vector<std::uint8_t> v;
        for (int i = 0; i < 4; ++i) v.push_back(std::uint8_t(chain_id >> (8 * i)));
        v.insert(v.end(), prev_block_hash.begin(), prev_block_hash.end());
        v.insert(v.end(), prev_own_share.begin(),  prev_own_share.end());
        v.insert(v.end(), coinbase.begin(), coinbase.end());
        for (int i = 0; i < 4; ++i) v.push_back(std::uint8_t(nonce >> (8 * i)));
        return ::v37::sha256d(v);
    }
};

// ── a v0x02 carrier = ordinary X11 share + 0..R_MAX X11 receipts ────────────
struct X11Carrier {
    X11WorkEvent carrier;
    std::vector<X11WorkEvent> receipts;
};

struct X11DecodeResult {
    WireStatus status = WireStatus::OK;
    X11Carrier carrier;                                    // valid iff status==OK
    std::vector<std::pair<std::string, ReceiptWireDrop>> dropped;
    bool ok() const { return status == WireStatus::OK; }
};

// ═══════════════════════════════════════════════════════════════════════════
// v0x02 wire codec. Little-endian fixed-width fields + u32/u16/u8 length
// prefixes, same put_/get_ idiom as w3_relay.hpp; the desc/ref/str/b32/uN sub-
// encodings are byte-identical to the frozen v0x01 ones (so a descriptor round-
// trips the same bytes under either version). It enforces the SAME two decode-
// time rules as v0x01: R_MAX (whole-carrier reject) and W3-MUST identity binding
// (carrier mis-bound -> whole reject; receipt mis-bound -> drop, carrier stands).
// ═══════════════════════════════════════════════════════════════════════════
class X11CarrierWire {
public:
    static std::vector<std::uint8_t> encode(const X11Carrier& c) {
        std::vector<std::uint8_t> b;
        b.push_back(W3_WIRE_VERSION_X11);
        put_event(b, c.carrier);
        b.push_back(static_cast<std::uint8_t>(c.receipts.size()));
        for (const X11WorkEvent& r : c.receipts) put_event(b, r);
        return b;
    }

    static X11DecodeResult decode(const std::vector<std::uint8_t>& b) {
        X11DecodeResult out;
        std::size_t p = 0;
        std::uint8_t ver = 0;
        if (!get_u8(b, p, ver)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }
        if (ver != W3_WIRE_VERSION_X11) { out.status = WireStatus::REJECT_BAD_VERSION; return out; }

        X11WorkEvent carrier;
        if (!get_event(b, p, carrier)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }

        std::uint8_t rc = 0;
        if (!get_u8(b, p, rc)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }
        if (rc > W3_R_MAX) { out.status = WireStatus::REJECT_RMAX; return out; }

        std::vector<X11WorkEvent> receipts;
        receipts.reserve(rc);
        for (std::uint8_t i = 0; i < rc; ++i) {
            X11WorkEvent r;
            if (!get_event(b, p, r)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }
            receipts.push_back(std::move(r));
        }
        if (p != b.size()) { out.status = WireStatus::REJECT_TRUNCATED; return out; }

        if (!identity_bound(carrier)) { out.status = WireStatus::REJECT_CARRIER_UNBOUND; return out; }
        out.carrier.carrier = std::move(carrier);
        for (X11WorkEvent& r : receipts) {
            if (!identity_bound(r)) {
                out.dropped.emplace_back(r.tag, ReceiptWireDrop::MISBOUND_IDENTITY);
                continue;   // never amplified onward
            }
            out.carrier.receipts.push_back(std::move(r));
        }
        out.status = WireStatus::OK;
        return out;
    }

    // W3-MUST identity binding (unchanged shape from v0x01): carried identity
    // must equal the descriptor's identity key. In v0x02 the CONSENSUS binding
    // is additionally the coinbase OP_RETURN commitment (dash SSOT), but this
    // structural check is still the cheap wire-layer guard.
    static bool identity_bound(const X11WorkEvent& e) {
        return e.identity == e.descriptor.identity_key();
    }

private:
    static void put_u8(std::vector<std::uint8_t>& b, std::uint8_t v) { b.push_back(v); }
    static void put_u16(std::vector<std::uint8_t>& b, std::uint16_t v) {
        for (int i = 0; i < 2; ++i) b.push_back(std::uint8_t(v >> (8 * i)));
    }
    static void put_u32(std::vector<std::uint8_t>& b, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) b.push_back(std::uint8_t(v >> (8 * i)));
    }
    static void put_u64(std::vector<std::uint8_t>& b, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) b.push_back(std::uint8_t(v >> (8 * i)));
    }
    static void put_bytes32(std::vector<std::uint8_t>& b, const bytes32& h) {
        b.insert(b.end(), h.begin(), h.end());
    }
    static void put_varbytes(std::vector<std::uint8_t>& b, const std::vector<std::uint8_t>& v) {
        put_u32(b, static_cast<std::uint32_t>(v.size()));
        b.insert(b.end(), v.begin(), v.end());
    }
    // desc/ref/str: byte-identical to CarrierWire's v0x01 sub-encoding.
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
    static void put_event(std::vector<std::uint8_t>& b, const X11WorkEvent& e) {
        put_u32(b, e.chain_id);
        put_bytes32(b, e.identity);
        put_bytes32(b, e.prev_block_hash);
        put_bytes32(b, e.prev_own_share);
        put_u32(b, e.header_version);
        put_u32(b, e.ntime);
        put_u32(b, e.nbits);
        put_u32(b, e.nonce);
        put_u32(b, e.share_bits);
        put_u32(b, e.max_bits);
        put_u64(b, e.last_txout_nonce);
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
        v = 0; for (int i = 0; i < 2; ++i) v |= std::uint16_t(b[p++]) << (8 * i);
        return true;
    }
    static bool get_u32(const std::vector<std::uint8_t>& b, std::size_t& p, std::uint32_t& v) {
        if (p + 4 > b.size()) return false;
        v = 0; for (int i = 0; i < 4; ++i) v |= std::uint32_t(b[p++]) << (8 * i);
        return true;
    }
    static bool get_u64(const std::vector<std::uint8_t>& b, std::size_t& p, std::uint64_t& v) {
        if (p + 8 > b.size()) return false;
        v = 0; for (int i = 0; i < 8; ++i) v |= std::uint64_t(b[p++]) << (8 * i);
        return true;
    }
    static bool get_bytes32(const std::vector<std::uint8_t>& b, std::size_t& p, bytes32& h) {
        if (p + 32 > b.size()) return false;
        for (int i = 0; i < 32; ++i) h[i] = b[p++];
        return true;
    }
    static bool get_varbytes(const std::vector<std::uint8_t>& b, std::size_t& p,
                             std::vector<std::uint8_t>& v) {
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
    static bool get_event(const std::vector<std::uint8_t>& b, std::size_t& p, X11WorkEvent& e) {
        if (!get_u32(b, p, e.chain_id)) return false;
        if (!get_bytes32(b, p, e.identity)) return false;
        if (!get_bytes32(b, p, e.prev_block_hash)) return false;
        if (!get_bytes32(b, p, e.prev_own_share)) return false;
        if (!get_u32(b, p, e.header_version)) return false;
        if (!get_u32(b, p, e.ntime)) return false;
        if (!get_u32(b, p, e.nbits)) return false;
        if (!get_u32(b, p, e.nonce)) return false;
        if (!get_u32(b, p, e.share_bits)) return false;
        if (!get_u32(b, p, e.max_bits)) return false;
        if (!get_u64(b, p, e.last_txout_nonce)) return false;
        if (!get_varbytes(b, p, e.coinbase)) return false;
        if (!get_varbytes(b, p, e.coinbase_payload)) return false;
        std::uint8_t nbranch = 0;
        if (!get_u8(b, p, nbranch)) return false;
        e.merkle_branch.clear();
        e.merkle_branch.reserve(nbranch);
        for (std::uint8_t i = 0; i < nbranch; ++i) {
            bytes32 h{};
            if (!get_bytes32(b, p, h)) return false;
            e.merkle_branch.push_back(h);
        }
        if (!get_desc(b, p, e.descriptor)) return false;
        if (!get_str(b, p, e.tag)) return false;
        return true;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// DUAL-ACCEPT front door (VERSION POLICY F-5). Peek the version byte and route:
//   0x01 -> the FROZEN CarrierWire::decode (verbatim; synthetic WorkEvent)
//   0x02 -> X11CarrierWire::decode        (real X11 X11WorkEvent)
// A 0x01 frame still decodes to the synthetic Carrier; a 0x02 frame to the X11
// carrier. Exactly one of v1/v2 is populated on OK. This is the whole "keeps
// v0x01 decodable, version-gated" guarantee — and it touches NOTHING frozen.
// ═══════════════════════════════════════════════════════════════════════════
enum class AnyWireKind { NONE, V1_SYNTHETIC, V2_X11 };

struct AnyDecode {
    AnyWireKind kind = AnyWireKind::NONE;
    WireStatus  status = WireStatus::REJECT_TRUNCATED;
    std::uint8_t version = 0;
    Carrier     v1;    // valid iff kind==V1_SYNTHETIC && status==OK
    X11Carrier  v2;    // valid iff kind==V2_X11      && status==OK
    std::vector<std::pair<std::string, ReceiptWireDrop>> dropped;
    bool ok() const { return status == WireStatus::OK; }
};

inline std::optional<std::uint8_t> peek_wire_version(const std::vector<std::uint8_t>& frame) {
    if (frame.empty()) return std::nullopt;
    return frame[0];
}

inline AnyDecode decode_any(const std::vector<std::uint8_t>& frame) {
    AnyDecode out;
    auto ver = peek_wire_version(frame);
    if (!ver) { out.status = WireStatus::REJECT_TRUNCATED; return out; }
    out.version = *ver;
    if (*ver == W3_WIRE_VERSION) {                 // 0x01 -> frozen synthetic codec
        out.kind = AnyWireKind::V1_SYNTHETIC;
        DecodeResult dr = CarrierWire::decode(frame);
        out.status = dr.status;
        out.dropped = dr.dropped;
        if (dr.ok()) out.v1 = std::move(dr.carrier);
        return out;
    }
    if (*ver == W3_WIRE_VERSION_X11) {             // 0x02 -> real X11 codec
        out.kind = AnyWireKind::V2_X11;
        X11DecodeResult dr = X11CarrierWire::decode(frame);
        out.status = dr.status;
        out.dropped = dr.dropped;
        if (dr.ok()) out.v2 = std::move(dr.carrier);
        return out;
    }
    out.status = WireStatus::REJECT_BAD_VERSION;   // outside the dual-accept set
    return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// Independent size / offset model for v0x02 (derived from the byte-map, NOT
// from X11CarrierWire::encode) + fixtures + golden hex + selfcheck(). Same
// shape as w3_wire_freeze.hpp for v0x01: a layout drift in either the codec or
// this model trips the byte-KAT. The v0x02 event is VARIABLE length (two u32-
// prefixed blobs + a u8-counted branch), so it has its OWN size derivation —
// it can NEVER satisfy the frozen 112-byte prefix, which is the whole point.
// ═══════════════════════════════════════════════════════════════════════════
namespace wire_x11 {

// Fixed portion of a v0x02 event, before the two var blobs / branch / desc / tag.
//   u32 chain_id + 3*b32 + 6*u32 (version,ntime,nbits,nonce,share_bits,max_bits)
//   + u64 last_txout_nonce
constexpr std::size_t kEventFixedHead =
    4 + 3 * 32 + 6 * 4 + 8;   // = 132
static_assert(kEventFixedHead == 132, "v0x02 fixed head is 132 bytes");

inline std::size_t ref_size(const ::v37::ScriptRef& r) { return 2 + r.payload.size(); }
inline std::size_t desc_size(const ::v37::PayoutDescriptor& d) {
    std::size_t n = ref_size(d.pay) + 1;                       // pay + has_attribution
    if (d.attribution.has_value()) n += ref_size(*d.attribution);
    n += 2;                                                     // aux_count u16
    for (const auto& e : d.aux) n += 4 + ref_size(e.ref);
    n += 2 + d.raw_script.size();                              // raw_script_len u16 + bytes
    return n;
}
inline std::size_t event_size(const X11WorkEvent& e) {
    return kEventFixedHead
         + 4 + e.coinbase.size()               // vb32 coinbase
         + 4 + e.coinbase_payload.size()       // vb32 coinbase_payload
         + 1 + e.merkle_branch.size() * 32     // u8 count + branch
         + desc_size(e.descriptor)
         + 2 + e.tag.size();                   // str tag
}
inline std::size_t frame_size(const X11Carrier& c) {
    std::size_t n = 1 + event_size(c.carrier) + 1;   // version + carrier + receipt_count
    for (const X11WorkEvent& r : c.receipts) n += event_size(r);
    return n;
}

namespace detail {
inline std::string to_hex(const std::vector<std::uint8_t>& b) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s; s.reserve(b.size() * 2);
    for (std::uint8_t x : b) { s.push_back(kHex[x >> 4]); s.push_back(kHex[x & 0x0f]); }
    return s;
}
inline int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
inline std::vector<std::uint8_t> from_hex(const std::string& h) {
    std::vector<std::uint8_t> out;
    if (h.size() % 2) return out;
    out.reserve(h.size() / 2);
    for (std::size_t i = 0; i < h.size(); i += 2) {
        int hi = hex_nibble(h[i]), lo = hex_nibble(h[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(std::uint8_t((hi << 4) | lo));
    }
    return out;
}
inline bytes32 pat(std::uint8_t base) {
    bytes32 h{};
    for (int i = 0; i < 32; ++i) h[i] = std::uint8_t(base + i);
    return h;
}
inline ::v37::ScriptRef ref(::v37::ScriptKind kind, std::size_t n, std::uint8_t fill) {
    ::v37::ScriptRef r; r.kind = kind; r.payload.assign(n, fill); return r;
}
inline ::v37::PayoutDescriptor desc_of(::v37::ScriptRef pay) {
    ::v37::PayoutDescriptor d; d.pay = std::move(pay); return d;
}
inline std::vector<std::uint8_t> bytes_of(std::initializer_list<std::uint8_t> l) {
    return std::vector<std::uint8_t>(l);
}
// A self-bound X11 event (identity == descriptor.identity_key(); W3-MUST holds).
inline X11WorkEvent event(std::uint32_t chain, const ::v37::PayoutDescriptor& d,
                          const bytes32& prev_block, const bytes32& prev_own,
                          std::uint32_t ver, std::uint32_t ntime, std::uint32_t nbits,
                          std::uint32_t nonce, std::uint32_t share_bits, std::uint32_t max_bits,
                          std::uint64_t nonce64, std::vector<std::uint8_t> coinbase,
                          std::vector<std::uint8_t> payload, std::vector<bytes32> branch,
                          std::string tag) {
    X11WorkEvent e;
    e.chain_id = chain;
    e.identity = d.identity_key();
    e.prev_block_hash = prev_block;
    e.prev_own_share = prev_own;
    e.header_version = ver;
    e.ntime = ntime;
    e.nbits = nbits;
    e.nonce = nonce;
    e.share_bits = share_bits;
    e.max_bits = max_bits;
    e.last_txout_nonce = nonce64;
    e.coinbase = std::move(coinbase);
    e.coinbase_payload = std::move(payload);
    e.merkle_branch = std::move(branch);
    e.descriptor = d;
    e.tag = std::move(tag);
    return e;
}
inline bool refs_equal(const ::v37::ScriptRef& a, const ::v37::ScriptRef& b) { return a == b; }
inline bool descs_equal(const ::v37::PayoutDescriptor& a, const ::v37::PayoutDescriptor& b) {
    if (!refs_equal(a.pay, b.pay)) return false;
    if (a.attribution.has_value() != b.attribution.has_value()) return false;
    if (a.attribution.has_value() && !refs_equal(*a.attribution, *b.attribution)) return false;
    if (a.aux.size() != b.aux.size()) return false;
    for (std::size_t i = 0; i < a.aux.size(); ++i)
        if (a.aux[i].chain_id != b.aux[i].chain_id || !refs_equal(a.aux[i].ref, b.aux[i].ref)) return false;
    return a.raw_script == b.raw_script;
}
inline bool events_equal(const X11WorkEvent& a, const X11WorkEvent& b) {
    return a.chain_id == b.chain_id && a.identity == b.identity &&
           a.prev_block_hash == b.prev_block_hash && a.prev_own_share == b.prev_own_share &&
           a.header_version == b.header_version && a.ntime == b.ntime && a.nbits == b.nbits &&
           a.nonce == b.nonce && a.share_bits == b.share_bits && a.max_bits == b.max_bits &&
           a.last_txout_nonce == b.last_txout_nonce && a.coinbase == b.coinbase &&
           a.coinbase_payload == b.coinbase_payload && a.merkle_branch == b.merkle_branch &&
           a.tag == b.tag && descs_equal(a.descriptor, b.descriptor);
}
inline bool carriers_equal(const X11Carrier& a, const X11Carrier& b) {
    if (!events_equal(a.carrier, b.carrier) || a.receipts.size() != b.receipts.size()) return false;
    for (std::size_t i = 0; i < a.receipts.size(); ++i)
        if (!events_equal(a.receipts[i], b.receipts[i])) return false;
    return true;
}
} // namespace detail

// ── Fixture X: 1 carrier + 1 receipt, real X11 field shape. ─────────────────
//   carrier : chain 1, P2PKH payout, header {version 0x20000000, ntime, nbits
//             0x1e0ffff0, nonce}, share_bits 0x1f00ffff, max_bits 0x1f0fffff,
//             a synthetic coinbase carrying an OP_RETURN (6a 28 || ref_hash ||
//             nonce64) so the bytes carry a commitment shape, a 2-hash merkle
//             branch, a DIP4 coinbase_payload, tag "cx".
//   receipt : same identity (self-carriage), a shorter coinbase, empty payload,
//             a 1-hash branch, tag "rx".
inline X11Carrier fixture_x() {
    using namespace detail;
    const auto d = desc_of(ref(::v37::ScriptKind::P2PKH, 20, 0x11));
    // A coinbase whose tail is a well-formed OP_RETURN ref_hash output script.
    std::vector<std::uint8_t> cb = {0x03, 0xaa, 0xbb, 0xcc, 0xfe, 0xed};   // opaque head
    cb.push_back(0x6a); cb.push_back(0x28);                                // OP_RETURN push 40
    for (int i = 0; i < 32; ++i) cb.push_back(std::uint8_t(0x70 + i));     // ref_hash
    for (int i = 0; i < 8; ++i)  cb.push_back(std::uint8_t(i));            // nonce64
    std::vector<std::uint8_t> cb_r = {0x02, 0x51, 0x52, 0x6a, 0x28};
    for (int i = 0; i < 32; ++i) cb_r.push_back(std::uint8_t(0x90 + i));
    for (int i = 0; i < 8; ++i)  cb_r.push_back(std::uint8_t(0xa0 + i));
    const std::vector<std::uint8_t> payload = {0x01, 0x00, 0xde, 0xad};    // DIP4 extra_payload

    X11Carrier c;
    c.carrier = event(1, d, pat(0x40), bytes32{}, 0x20000000u, 0x66aa1234u,
                      0x1e0ffff0u, 0x00c0ffeeu, 0x1f00ffffu, 0x1f0fffffu,
                      0x0011223344556677ULL, cb, payload, {pat(0x50), pat(0x60)}, "cx");
    c.receipts = { event(1, d, pat(0x80), pat(0x40), 0x20000000u, 0x66aa1300u,
                         0x1e0ffff0u, 0x11223344u, 0x1f00ffffu, 0x1f0fffffu,
                         0xfeedface0badc0deULL, cb_r, {}, {pat(0xa0)}, "rx") };
    return c;
}
// Golden hex — encode(fixture_x()) under wire v0x02. Generated by the codec and
// pinned here; a change to any field width, order, or endianness trips the KAT.
inline const char* kGoldenHexX =
    "0201000000fd2e83fe009e7e6c791745176f53719653bc35f5705564e912d4af2413cce77d404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0000000000000000000000000000000000000000000000000000000000000000000000203412aa66f0ff0f1eeeffc000ffff001fffff0f1f77665544332211003000000003aabbccfeed6a28707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f0001020304050607040000000100dead02505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f001411111111111111111111111111111111111111110000000000020063780101000000fd2e83fe009e7e6c791745176f53719653bc35f5705564e912d4af2413cce77d808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000200013aa66f0ff0f1e44332211ffff001fffff0f1fdec0ad0bcefaedfe2d0000000251526a28909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafa0a1a2a3a4a5a6a70000000001a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf00141111111111111111111111111111111111111111000000000002007278";

struct SelfCheck {
    unsigned checks = 0, failures = 0;
    std::string log;
    bool ok() const { return failures == 0; }
};

inline SelfCheck selfcheck() {
    using namespace detail;
    SelfCheck sc;
    auto chk = [&](bool cond, const std::string& what) {
        ++sc.checks;
        if (!cond) { ++sc.failures; sc.log += "FAIL " + what + "\n"; }
        return cond;
    };

    // Global pins.
    chk(W3_WIRE_VERSION_X11 == 0x02, "wire version tag is 0x02");
    chk(W3_WIRE_VERSION == 0x01, "frozen synthetic version untouched at 0x01");
    chk(version_accepted_dual(0x01) && version_accepted_dual(0x02) &&
        !version_accepted_dual(0x00) && !version_accepted_dual(0x03),
        "dual-accept set is exactly {0x01,0x02}");


    const X11Carrier c = fixture_x();

    // (1) golden bytes
    const std::vector<std::uint8_t> bytes = X11CarrierWire::encode(c);
    const std::string hex = to_hex(bytes);
    if (!chk(hex == std::string(kGoldenHexX), "fixtureX: encode == golden"))
        sc.log += "  got   : " + hex + "\n  golden: " + std::string(kGoldenHexX) + "\n";

    // (2) independent size model agrees with the codec
    chk(bytes.size() == frame_size(c), "fixtureX: size == frame_size model");
    chk(!bytes.empty() && bytes[0] == W3_WIRE_VERSION_X11, "fixtureX: version byte @0 == 0x02");

    // (3) decode(encode) round trip, lossless; (4) re-encode identity
    X11DecodeResult dr = X11CarrierWire::decode(bytes);
    chk(dr.status == WireStatus::OK, "fixtureX: decode OK");
    chk(dr.dropped.empty(), "fixtureX: no receipt dropped");
    chk(carriers_equal(dr.carrier, c), "fixtureX: decode(encode(c)) == c (all fields)");
    chk(X11CarrierWire::encode(dr.carrier) == bytes, "fixtureX: re-encode byte-identical");

    // (5) the golden itself decodes to the fixture (independent of encode)
    const std::vector<std::uint8_t> gold = from_hex(std::string(kGoldenHexX));
    chk(!gold.empty(), "fixtureX: golden hex well-formed");
    X11DecodeResult dg = X11CarrierWire::decode(gold);
    chk(dg.status == WireStatus::OK && carriers_equal(dg.carrier, c),
        "fixtureX: decode(golden) == fixture");

    // (6) every strict prefix is REJECT_TRUNCATED (no field is optional)
    bool all_trunc = true;
    for (std::size_t n = 0; n < bytes.size(); ++n) {
        std::vector<std::uint8_t> pre(bytes.begin(), bytes.begin() + n);
        if (X11CarrierWire::decode(pre).status != WireStatus::REJECT_TRUNCATED) { all_trunc = false; break; }
    }
    chk(all_trunc, "fixtureX: every strict prefix -> REJECT_TRUNCATED");

    // (7) one trailing byte -> REJECT_TRUNCATED (frame is exact-length)
    { auto t = bytes; t.push_back(0x00);
      chk(X11CarrierWire::decode(t).status == WireStatus::REJECT_TRUNCATED, "fixtureX: trailing byte rejected"); }

    // (8) version 0x01 / 0x03 in a 0x02 frame -> BAD_VERSION at the X11 decoder;
    //     the frozen 0x01 decoder still refuses a 0x02 frame (freeze intact).
    { auto t = bytes; t[0] = 0x01;
      chk(X11CarrierWire::decode(t).status == WireStatus::REJECT_BAD_VERSION, "fixtureX: 0x01 rejected by X11 decoder"); }
    chk(CarrierWire::decode(bytes).status == WireStatus::REJECT_BAD_VERSION,
        "fixtureX: frozen 0x01 decoder refuses a 0x02 frame (freeze intact)");

    // (9) carrier identity flipped -> REJECT_CARRIER_UNBOUND (W3-MUST). The
    //     identity sits at offset 1(version)+4(chain_id)=5.
    { auto t = bytes; t[5] ^= 0x01;
      chk(X11CarrierWire::decode(t).status == WireStatus::REJECT_CARRIER_UNBOUND,
          "fixtureX: mis-bound carrier rejected"); }

    // (10) dual-accept front door routes both versions.
    {
        AnyDecode a2 = decode_any(bytes);
        chk(a2.ok() && a2.kind == AnyWireKind::V2_X11 && carriers_equal(a2.v2, c),
            "decode_any: 0x02 frame -> X11 carrier");
        // A genuine frozen v0x01 frame (built with the untouched CarrierWire)
        // routes to v1 — proving the dual-accept window keeps 0x01 decodable.
        Carrier v1c;
        {
            const auto d = desc_of(ref(::v37::ScriptKind::P2PKH, 20, 0x11));
            WorkEvent w;
            w.chain_id = 1;
            w.descriptor = d;
            w.identity = d.identity_key();     // W3-MUST bound
            w.prev_block_hash = pat(0x40);
            w.lz_bits = 8;
            w.nonce = 0x0123456789abcdefULL;
            w.tag = "c";
            v1c.carrier = w;
        }
        const std::vector<std::uint8_t> v1frame = CarrierWire::encode(v1c);
        AnyDecode a1 = decode_any(v1frame);
        chk(a1.ok() && a1.kind == AnyWireKind::V1_SYNTHETIC, "decode_any: 0x01 frame -> synthetic carrier");
        AnyDecode ab = decode_any({0x03, 0x00});
        chk(ab.status == WireStatus::REJECT_BAD_VERSION, "decode_any: 0x03 -> BAD_VERSION");
    }

    // (11) the X11 crypto SEAM, structurally (stdlib-side). This file performs NO
    //      PoW policy any more — target math, the X11 recompute and every verify
    //      disposition are the DASH SSOT (impl/dash/x11_share_verify.hpp), reached
    //      from L3 (x11_share_envelope.hpp). All this byte-KAT pins is that the
    //      hook is FAIL-CLOSED by default and that set/get round-trips; that the
    //      installed hook IS dash::crypto::hash_x11 is proven byte-for-byte by
    //      v37_a2_x11_real_pow_kat (RX-12), which links the SSOT.
    {
        x11_hash_fn saved = x11_hash_hook();
        set_x11_hash(nullptr);
        chk(x11_hash_hook() == nullptr, "x11 hash hook is fail-closed when unset");
        set_x11_hash(+[](const std::uint8_t* h) -> bytes32 {
            std::vector<std::uint8_t> v(h, h + 80);
            return ::v37::sha256d(v);   // stdlib stand-in; NEVER a consensus answer
        });
        chk(x11_hash_hook() != nullptr, "x11 hash hook set/get round-trips");
        set_x11_hash(saved);
    }

    return sc;
}

} // namespace wire_x11
} // namespace c2pool::v37n
