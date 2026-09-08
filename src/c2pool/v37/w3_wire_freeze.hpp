#pragma once
// V37 Track A2 / W3-B5 — CARRIER-WIRE BYTE FREEZE (Track A2 step (b)(1)).
// CONSUMER-tree code (src/c2pool/v37/). Header-only, stdlib-only (no sockets,
// no threads, no Boost) so it links into every v37 unit suite AND the daemon.
//
// WHAT THIS FILE IS
//   The single place where the CarrierWire byte layout (w3_relay.hpp, wire
//   version 0x01) is declared FROZEN, and the machinery that makes that freeze
//   enforceable rather than a comment:
//     1. the frozen constants (version, R_MAX, every field width and offset,
//        the transport framing prefix and ceiling) with static_asserts against
//        the live codec's knobs;
//     2. an INDEPENDENT size/offset model of the layout (derived from the byte-
//        map below, NOT from CarrierWire::encode) so a KAT can prove the codec
//        and the documentation agree byte-for-byte on ANY carrier;
//     3. encodable(): the encoder-side guard for what the frozen layout can
//        express (u8 payload_len, u16 aux_count/raw_script_len/tag len, R_MAX,
//        transport ceiling) — CarrierWire's put_* helpers narrow silently;
//     4. the FROZEN-WIRE POLICY (the F-1/F-2 decisions): tag cap and V37.0
//        descriptor validity, applied AFTER decode and BEFORE admission; the
//        golden bytes are unaffected by it;
//     5. three FROZEN FIXTURES with their golden hex (A = the original 1+1
//        P2PKH carrier; B = every descriptor branch with non-trivial bytes +
//        R_MAX receipts + a tag at the cap; C = the attribution slot + zero
//        receipts) and selfcheck(): the byte-KAT body, callable from the test
//        harness AND from the daemon at boot (a build whose encoder drifted
//        from the golden must never flood frames to peers).
//
// THE FROZEN v0x01 LAYOUT (canonical; little-endian throughout; no varints)
//
//   transport := u32 length ; length bytes = frame        (carrier_net.hpp)
//   frame     := u8  version                (= 0x01)
//                event carrier
//                u8  receipt_count          (0..R_MAX=4; > R_MAX => REJECT_RMAX)
//                event receipt[receipt_count]
//   event     := u32 chain_id                                     @ +0   (4)
//                b32 identity     (payout-descriptor identity key) @ +4   (32)
//                b32 prev_block_hash (hashPrevBlock, INTERNAL order)@ +36 (32)
//                b32 prev_own_share                                @ +68  (32)
//                u32 lz_bits                                       @ +100 (4)
//                u64 nonce                                         @ +104 (8)
//                desc descriptor                                   @ +112 (var)
//                str  tag              (bookkeeping; NOT in the PoW preimage)
//   desc      := ref pay
//                u8  has_attribution ; if 1: ref attribution
//                u16 aux_count ; aux_count x { u32 chain_id ; ref ref }
//                u16 raw_script_len ; raw_script_len bytes
//   ref       := u8 kind ; u8 payload_len ; payload_len bytes
//                kind in ScriptKind: P2PKH=0 P2SH=1 P2WPKH=2 P2WSH=3 P2TR=4 RAW=255
//                (0x10/0x11 are the reserved XMR kinds, sharechain canon P-1)
//   str       := u16 len ; len bytes
//   b32       := 32 raw bytes, no length prefix
//   uN        := N/8 bytes, LITTLE-ENDIAN
//
//   Decode rules that are PART of the freeze (CarrierWire::decode):
//     version != 0x01            -> REJECT_BAD_VERSION
//     any short read             -> REJECT_TRUNCATED
//     trailing bytes after frame -> REJECT_TRUNCATED
//     receipt_count > R_MAX      -> REJECT_RMAX (whole carrier)
//     carrier.identity != carrier.descriptor.identity_key()
//                                -> REJECT_CARRIER_UNBOUND (whole carrier)
//     receipt.identity != receipt.descriptor.identity_key()
//                                -> that receipt DROPPED, carrier stands
//   Decode does NOT verify PoW, does NOT resolve prev_block_hash, does NOT run
//   PayoutDescriptor::valid(). Those are admission (W2) and policy (below).
//
// VERSION POLICY (F-5)
//   W3_WIRE_VERSION (w3_relay.hpp) is the ONLY knob. A decoder for 0x01
//   accepts exactly {0x01}. A future 0x02 MUST ship a dual-accept decoder
//   ({0x01, 0x02}) for one upgrade window before 0x01 is retired, and MUST add
//   a fixture + golden for 0x02 here; it MUST NOT re-pack 0x01 in place. The
//   goldens below are for 0x01 and never change while 0x01 is accepted.
//
// TAG POLICY (F-1)
//   `tag` is bookkeeping: outside the PoW preimage (w2_receipt.hpp
//   WorkEvent::preimage), never checked by W2, but relayed VERBATIM by
//   CarrierRelay (re_encode). Unbounded, it is up to 65535 un-PoW'd bytes per
//   event x (1 + R_MAX) events per frame riding every hop for free. FROZEN
//   decision: kTagMaxBytes = 64, enforced post-decode / pre-admit by
//   frame_policy()/apply_policy(): a carrier over the cap => frame rejected;
//   a receipt over the cap => that receipt dropped, carrier stands (the same
//   shape as decode's mis-bound-receipt rule). The wire format itself keeps
//   the u16 length (the golden is unaffected); the cap is policy, not layout.
//
// DESCRIPTOR POLICY (F-2)
//   decode accepts any kind/payload_len/raw_script, W2 admission never runs
//   PayoutDescriptor::valid(), and the engine rejects an invalid descriptor
//   only at push (SubmitStatus::RejectedInvalidDescriptor) — by which time
//   CarrierIngest's fire-and-forget submit has already returned OK to the
//   relay, which has flooded the frame onward. FROZEN decision: valid(false)
//   (V37.0: attribution MUST be absent; payload widths by kind; RAW pay must
//   bind to its carried raw_script) is checked in the same pre-admit policy,
//   with the same carrier-reject / receipt-drop shape.
//
// TRANSPORT (carrier_net.hpp) — frozen alongside: [u32 LE length][frame],
//   length > kTransportMaxFrame (1 MiB) => protocol error, peer dropped.
//
// HONEST BOUNDARY (S-1 / real share format, unchanged by this freeze): the
//   CONTAINER is frozen. prev_block_hash / lz_bits / nonce still carry the
//   SYNTHETIC RDWR sha256d envelope, not a DASH X11 share; a peer cannot verify
//   the real stratum share from a v0x01 frame. When real share format lands it
//   is a version bump (0x02) with its own goldens, per the version policy.
//
// HOW TO CHANGE THE WIRE (the only sanctioned path)
//   bump W3_WIRE_VERSION -> add a fixture + golden for the new version here ->
//   ship the dual-accept decoder -> keep the 0x01 goldens until 0x01 retires.
//   Never edit kGoldenHex* to "fix" a red KAT: a red KAT is the freeze working.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "w3_relay.hpp"   // Carrier, CarrierWire, WireStatus, W3_WIRE_VERSION, W3_R_MAX

namespace c2pool::v37n::wire_freeze {

// ═══════════════════════════════════════════════════════════════════════════
// 1. Frozen constants — pinned against the live codec at compile time.
// ═══════════════════════════════════════════════════════════════════════════
constexpr std::uint8_t  kFrozenVersion = 0x01;
constexpr std::uint32_t kFrozenRMax    = 4;
static_assert(kFrozenVersion == W3_WIRE_VERSION,
              "W3-B5: the frozen wire version is 0x01; a wire change is a "
              "VISIBLE bump with new goldens, never a re-pack of 0x01");
static_assert(kFrozenRMax == W3_R_MAX,
              "W3-B5: receipt_count bound is frozen at 4 (== W2_R_MAX)");

// Version acceptance set (F-5). Exactly {0x01} while 0x01 is the only wire.
inline constexpr std::uint8_t kAcceptedVersions[] = { kFrozenVersion };
inline bool version_accepted(std::uint8_t v) {
    for (std::uint8_t a : kAcceptedVersions) if (a == v) return true;
    return false;
}
// Peek the version byte of a frame without decoding it (nullopt on empty).
inline std::optional<std::uint8_t> peek_version(const std::vector<std::uint8_t>& frame) {
    if (frame.empty()) return std::nullopt;
    return frame[0];
}

// Field widths (bytes).
constexpr std::size_t kVersionBytes        = 1;
constexpr std::size_t kChainIdBytes        = 4;
constexpr std::size_t kHashBytes           = 32;
constexpr std::size_t kLzBitsBytes         = 4;
constexpr std::size_t kNonceBytes          = 8;
constexpr std::size_t kEventFixedBytes     = kChainIdBytes + 3 * kHashBytes + kLzBitsBytes + kNonceBytes;  // 112
constexpr std::size_t kRefHeaderBytes      = 2;   // u8 kind + u8 payload_len
constexpr std::size_t kHasAttributionBytes = 1;
constexpr std::size_t kAuxCountBytes       = 2;
constexpr std::size_t kAuxChainIdBytes     = 4;
constexpr std::size_t kRawScriptLenBytes   = 2;
constexpr std::size_t kStrLenBytes         = 2;
constexpr std::size_t kReceiptCountBytes   = 1;
static_assert(kEventFixedBytes == 112, "frozen event fixed prefix is 112 bytes");

// Offsets INSIDE an event (relative to the event's first byte).
constexpr std::size_t kOffChainId    = 0;
constexpr std::size_t kOffIdentity   = kOffChainId + kChainIdBytes;     // 4
constexpr std::size_t kOffPrevBlock  = kOffIdentity + kHashBytes;       // 36
constexpr std::size_t kOffPrevOwn    = kOffPrevBlock + kHashBytes;      // 68
constexpr std::size_t kOffLzBits     = kOffPrevOwn + kHashBytes;        // 100
constexpr std::size_t kOffNonce      = kOffLzBits + kLzBitsBytes;       // 104
constexpr std::size_t kOffDescriptor = kOffNonce + kNonceBytes;         // 112
static_assert(kOffDescriptor == kEventFixedBytes, "descriptor follows the fixed prefix");

// Offsets INSIDE a frame.
constexpr std::size_t kOffVersion = 0;
constexpr std::size_t kOffCarrier = kOffVersion + kVersionBytes;        // 1

// Width limits the layout can express (the put_* helpers narrow silently).
constexpr std::size_t kMaxRefPayload = 0xff;
constexpr std::size_t kMaxAuxCount   = 0xffff;
constexpr std::size_t kMaxRawScript  = 0xffff;
constexpr std::size_t kMaxTagWire    = 0xffff;   // wire width; policy cap is kTagMaxBytes

// Transport framing (carrier_net.hpp) frozen alongside. The KAT static_asserts
// carrier_net.hpp's kMaxCarrierFrame against this so the two cannot drift; this
// header deliberately does NOT include carrier_net.hpp (sockets/threads).
constexpr std::size_t   kTransportLenBytes = 4;
constexpr std::uint32_t kTransportMaxFrame = 1u << 20;

inline const char* layout_id() { return "w3-carrier-wire/v0x01/frozen-2026-09-07"; }

// ═══════════════════════════════════════════════════════════════════════════
// 2. Independent size / offset model — derived from the byte-map, NOT from
//    CarrierWire::encode. selfcheck() proves encode(c).size() == frame_size(c)
//    and that the receipt_count byte and every receipt sit where this model
//    says; a layout drift in either the codec or this file trips the KAT.
// ═══════════════════════════════════════════════════════════════════════════
inline std::size_t ref_size(const ::v37::ScriptRef& r) {
    return kRefHeaderBytes + r.payload.size();
}
inline std::size_t desc_size(const ::v37::PayoutDescriptor& d) {
    std::size_t n = ref_size(d.pay) + kHasAttributionBytes;
    if (d.attribution.has_value()) n += ref_size(*d.attribution);
    n += kAuxCountBytes;
    for (const auto& e : d.aux) n += kAuxChainIdBytes + ref_size(e.ref);
    n += kRawScriptLenBytes + d.raw_script.size();
    return n;
}
inline std::size_t event_size(const WorkEvent& e) {
    return kEventFixedBytes + desc_size(e.descriptor) + kStrLenBytes + e.tag.size();
}
inline std::size_t frame_size(const Carrier& c) {
    std::size_t n = kVersionBytes + event_size(c.carrier) + kReceiptCountBytes;
    for (const WorkEvent& r : c.receipts) n += event_size(r);
    return n;
}
inline std::size_t transport_size(const Carrier& c) {
    return kTransportLenBytes + frame_size(c);
}
// Frame offset of the receipt_count byte.
inline std::size_t receipt_count_offset(const Carrier& c) {
    return kOffCarrier + event_size(c.carrier);
}
// Frame offset of receipt i's first byte (i < receipts.size()).
inline std::size_t receipt_offset(const Carrier& c, std::size_t i) {
    std::size_t off = receipt_count_offset(c) + kReceiptCountBytes;
    for (std::size_t k = 0; k < i && k < c.receipts.size(); ++k) off += event_size(c.receipts[k]);
    return off;
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Encoder-side guard: can the frozen layout express this carrier EXACTLY?
//    CarrierWire::encode narrows payload_len to u8 and aux_count / raw_script
//    / tag lengths to u16 without checking; an over-wide field yields a frame
//    that decodes to something else (or not at all). Emitters call this before
//    encode; it is NOT a decode-side rule (decode cannot see a narrowed field).
// ═══════════════════════════════════════════════════════════════════════════
inline bool ref_encodable(const ::v37::ScriptRef& r) { return r.payload.size() <= kMaxRefPayload; }
inline bool desc_encodable(const ::v37::PayoutDescriptor& d) {
    if (!ref_encodable(d.pay)) return false;
    if (d.attribution.has_value() && !ref_encodable(*d.attribution)) return false;
    if (d.aux.size() > kMaxAuxCount) return false;
    for (const auto& e : d.aux) if (!ref_encodable(e.ref)) return false;
    return d.raw_script.size() <= kMaxRawScript;
}
inline bool event_encodable(const WorkEvent& e) {
    return desc_encodable(e.descriptor) && e.tag.size() <= kMaxTagWire;
}
inline bool encodable(const Carrier& c, std::string* why = nullptr) {
    auto fail = [&](const char* w) { if (why) *why = w; return false; };
    if (c.receipts.size() > kFrozenRMax) return fail("receipt_count > R_MAX");
    if (!event_encodable(c.carrier)) return fail("carrier field exceeds frozen width");
    for (const WorkEvent& r : c.receipts)
        if (!event_encodable(r)) return fail("receipt field exceeds frozen width");
    if (frame_size(c) > kTransportMaxFrame) return fail("frame exceeds transport ceiling");
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Frozen-wire POLICY (F-1 tag cap, F-2 descriptor validity). Post-decode,
//    pre-admit. Never touches the byte layout; the goldens are unaffected.
// ═══════════════════════════════════════════════════════════════════════════
constexpr std::size_t kTagMaxBytes = 64;

enum class Policy {
    OK,
    RECEIPT_COUNT,        // > R_MAX receipts presented to the policy (defensive;
                          // decode already rejects this on the wire)
    TAG_TOO_LONG,         // tag > kTagMaxBytes (F-1)
    DESCRIPTOR_INVALID,   // !PayoutDescriptor::valid(false) under V37.0 (F-2)
};
inline const char* policy_name(Policy p) {
    switch (p) {
    case Policy::OK:                 return "OK";
    case Policy::RECEIPT_COUNT:      return "RECEIPT_COUNT";
    case Policy::TAG_TOO_LONG:       return "TAG_TOO_LONG";
    case Policy::DESCRIPTOR_INVALID: return "DESCRIPTOR_INVALID";
    }
    return "?";
}

// Per-event verdict (order: tag, then descriptor).
inline Policy event_policy(const WorkEvent& e) {
    if (e.tag.size() > kTagMaxBytes) return Policy::TAG_TOO_LONG;
    if (!e.descriptor.valid(false)) return Policy::DESCRIPTOR_INVALID;
    return Policy::OK;
}

// STRICT whole-frame verdict: the first violation anywhere (carrier first, then
// receipts in wire order). Use for "is this frame policy-clean as a whole".
inline Policy frame_policy(const Carrier& c) {
    if (c.receipts.size() > kFrozenRMax) return Policy::RECEIPT_COUNT;
    if (Policy p = event_policy(c.carrier); p != Policy::OK) return p;
    for (const WorkEvent& r : c.receipts)
        if (Policy p = event_policy(r); p != Policy::OK) return p;
    return Policy::OK;
}

// RELAY-shaped application (mirrors CarrierWire::decode's receipt-drop rule):
//   carrier-level violation  -> returns the verdict, `c` untouched, frame must
//                               be rejected (never admitted, never relayed);
//   receipt-level violation  -> that receipt is ERASED from `c` and recorded in
//                               `dropped` as (tag, reason); the carrier stands.
// Returns Policy::OK when the (possibly cleaned) carrier may proceed to admit.
inline Policy apply_policy(Carrier& c,
                           std::vector<std::pair<std::string, Policy>>* dropped = nullptr) {
    if (c.receipts.size() > kFrozenRMax) return Policy::RECEIPT_COUNT;
    if (Policy p = event_policy(c.carrier); p != Policy::OK) return p;
    std::vector<WorkEvent> kept;
    kept.reserve(c.receipts.size());
    for (WorkEvent& r : c.receipts) {
        Policy p = event_policy(r);
        if (p == Policy::OK) { kept.push_back(std::move(r)); continue; }
        if (dropped) dropped->emplace_back(r.tag, p);
    }
    c.receipts = std::move(kept);
    return Policy::OK;
}

// Counters for the relay hook (diagnostics only, never consensus). Atomic
// because CarrierPeerNode runs ONE READER THREAD PER PEER and each calls
// CarrierRelay::handle_inbound -> this hook concurrently (carrier_net.hpp
// reader_loop). Relaxed: they are counters, not synchronization.
struct PolicyStats {
    std::atomic<std::uint64_t> frames_rejected{0};    // carrier-level policy rejects
    std::atomic<std::uint64_t> receipts_dropped{0};   // receipt-level policy drops
    std::atomic<std::uint64_t> frames_passed{0};
};

// The hook shape CarrierRelay::set_frame_policy takes: bool(Carrier&) — false
// => the relay rejects the frame (WireStatus::REJECT_POLICY); true => proceed
// with the (possibly cleaned) carrier. Stats pointer may be null; if non-null
// it must outlive the relay.
inline std::function<bool(Carrier&)> make_relay_policy(PolicyStats* stats = nullptr) {
    return [stats](Carrier& c) -> bool {
        std::vector<std::pair<std::string, Policy>> dropped;
        const Policy p = apply_policy(c, &dropped);
        if (stats) {
            stats->receipts_dropped.fetch_add(dropped.size(), std::memory_order_relaxed);
            (p == Policy::OK ? stats->frames_passed : stats->frames_rejected)
                .fetch_add(1, std::memory_order_relaxed);
        }
        return p == Policy::OK;
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Frozen fixtures + goldens + the byte-KAT body.
// ═══════════════════════════════════════════════════════════════════════════
namespace detail {
inline std::string to_hex(const std::vector<std::uint8_t>& b) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (std::uint8_t x : b) { s.push_back(kHex[x >> 4]); s.push_back(kHex[x & 0x0f]); }
    return s;
}
inline int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
// Empty on malformed input (odd length / non-hex char).
inline std::vector<std::uint8_t> from_hex(const std::string& h) {
    std::vector<std::uint8_t> out;
    if (h.size() % 2) return out;
    out.reserve(h.size() / 2);
    for (std::size_t i = 0; i < h.size(); i += 2) {
        int hi = hex_nibble(h[i]), lo = hex_nibble(h[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}
// A legible 32-byte pattern: byte i = base + i (mod 256).
inline bytes32 pat(std::uint8_t base) {
    bytes32 h{};
    for (int i = 0; i < 32; ++i) h[i] = static_cast<std::uint8_t>(base + i);
    return h;
}
inline ::v37::ScriptRef ref(::v37::ScriptKind kind, std::size_t n, std::uint8_t fill) {
    ::v37::ScriptRef r;
    r.kind = kind;
    r.payload.assign(n, fill);
    return r;
}
inline ::v37::PayoutDescriptor desc_of(::v37::ScriptRef pay) {
    ::v37::PayoutDescriptor d;
    d.pay = std::move(pay);
    return d;
}
// A self-bound event (identity == descriptor.identity_key(), W3-MUST holds).
inline WorkEvent event(std::uint32_t chain, const ::v37::PayoutDescriptor& d,
                       const bytes32& prev_block, const bytes32& prev_own,
                       std::uint32_t lz, u64 nonce, std::string tag) {
    WorkEvent e;
    e.chain_id        = chain;
    e.identity        = d.identity_key();
    e.prev_block_hash = prev_block;
    e.prev_own_share  = prev_own;
    e.lz_bits         = lz;
    e.nonce           = nonce;
    e.descriptor      = d;
    e.tag             = std::move(tag);
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
inline bool events_equal(const WorkEvent& a, const WorkEvent& b) {
    return a.chain_id == b.chain_id && a.identity == b.identity &&
           a.prev_block_hash == b.prev_block_hash && a.prev_own_share == b.prev_own_share &&
           a.lz_bits == b.lz_bits && a.nonce == b.nonce && a.tag == b.tag &&
           descs_equal(a.descriptor, b.descriptor);
}
inline bool carriers_equal(const Carrier& a, const Carrier& b) {
    if (!events_equal(a.carrier, b.carrier) || a.receipts.size() != b.receipts.size()) return false;
    for (std::size_t i = 0; i < a.receipts.size(); ++i)
        if (!events_equal(a.receipts[i], b.receipts[i])) return false;
    return true;
}
} // namespace detail

struct FrozenFixture {
    const char* name;
    Carrier     carrier;
    const char* golden_hex;       // encode(carrier) under wire v0x01
    Policy      expected_policy;  // frame_policy(carrier)
};

// ── Fixture A: the original 1 carrier + 1 receipt, P2PKH, tags "c"/"r0". ────
// Byte-identical to the fixture the first freeze KAT pinned (the golden below
// is that KAT's kGoldenHex verbatim). No attribution / aux / raw_script bytes.
inline Carrier fixture_a() {
    using namespace detail;
    const auto d = desc_of(ref(::v37::ScriptKind::P2PKH, 20, 0x11));
    Carrier c;
    c.carrier = event(1, d, pat(0x40), bytes32{}, 8, 0x0123456789abcdefULL, "c");
    c.receipts = { event(1, d, pat(0x60), pat(0x40), 8, 0xfeedface0badc0deULL, "r0") };
    return c;
}
inline const char* kGoldenHexA =
    "0101000000fd2e83fe009e7e6c791745176f53719653bc35f5705564e912d4af2413cce77d404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000000000000000000000000000000000000000000000000000000000000008000000efcdab89674523010014111111111111111111111111111111111111111100000000000100630101000000fd2e83fe009e7e6c791745176f53719653bc35f5705564e912d4af2413cce77d606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f08000000dec0ad0bcefaedfe00141111111111111111111111111111111111111111000000000002007230";

// ── Fixture B: FULL branch coverage, policy-clean (F-4). ───────────────────
//   carrier : chain 5; pay = RAW bound to raw_script 6a04deadbeef (OP_RETURN
//             push4) so raw_script_len > 0 AND the RAW binding holds; 1 aux
//             entry {0x2a, P2WPKH 20x33}; lz 9; tag EXACTLY kTagMaxBytes (64).
//   receipts: R_MAX = 4, one per remaining kind — P2SH(1), P2WSH(3) with an
//             EMPTY tag, P2TR(4) with nonce all-ones, P2PKH(0) with TWO sorted
//             aux entries {1,P2PKH 20x88} < {7,P2WSH 32x99}.
//   Every ScriptKind byte value (0,1,2,3,4,255) appears; has_attribution stays
//   0 here because V37.0 validity forbids it — fixture C pins that branch.
inline Carrier fixture_b() {
    using namespace detail;
    const std::vector<std::uint8_t> raw = {0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef};
    ::v37::PayoutDescriptor dc;
    dc.pay        = ::v37::canonicalize_script(raw);   // RAW, payload = sha256d(raw)
    dc.raw_script = raw;
    dc.aux.push_back(::v37::AuxEntry{0x2a, ref(::v37::ScriptKind::P2WPKH, 20, 0x33)});

    std::string tag_at_cap = "B.carrier.tag-at-cap:";
    tag_at_cap.append(kTagMaxBytes - tag_at_cap.size(), 'x');

    Carrier c;
    c.carrier = event(5, dc, pat(0x80), pat(0xa0), 9, 0x1122334455667788ULL, tag_at_cap);

    const auto d0 = desc_of(ref(::v37::ScriptKind::P2SH,  20, 0x44));
    const auto d1 = desc_of(ref(::v37::ScriptKind::P2WSH, 32, 0x55));
    const auto d2 = desc_of(ref(::v37::ScriptKind::P2TR,  32, 0x66));
    ::v37::PayoutDescriptor d3 = desc_of(ref(::v37::ScriptKind::P2PKH, 20, 0x77));
    d3.aux.push_back(::v37::AuxEntry{1, ref(::v37::ScriptKind::P2PKH, 20, 0x88)});
    d3.aux.push_back(::v37::AuxEntry{7, ref(::v37::ScriptKind::P2WSH, 32, 0x99)});

    c.receipts = {
        event(5, d0, pat(0xc0), pat(0x80), 8, 0x0000000000000001ULL, "r0"),
        event(5, d1, pat(0xd0), pat(0xc0), 9, 0x0000000100000000ULL, ""),
        event(5, d2, pat(0xe0), pat(0x01), 8, 0xffffffffffffffffULL, "r2"),
        event(5, d3, pat(0xf0), pat(0x02), 8, 0x8000000000000000ULL, "r3"),
    };
    return c;
}
inline const char* kGoldenHexB =
    "0105000000ea52ca7f1548684e30d336d8c18cf7e8fedf091cd5b9afca93d2c5474cdb9883808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf090000008877665544332211ff20b697e503a530429f57e4a197f7aa0f37c38aaaa803f29839ab49062f345daea40001002a0000000214333333333333333333333333333333333333333306006a04deadbeef4000422e636172726965722e7461672d61742d6361703a78787878787878787878787878787878787878787878787878787878787878787878787878787878787878040500000025ef7da35aa62fb1efe73c82e13ed86c288ed5478b011d68de38a3ae69a1f7fcc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f0800000001000000000000000114444444444444444444444444444444444444444400000000000200723005000000f2af3b63ad987b888cf4ad86ed5c06ba8611fdc9185c42c35cc46c06fe301eaed0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeefc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf0900000000000000010000000320555555555555555555555555555555555555555555555555555555555555555500000000000000050000005a983a97b2df748e4a13849701c7e34b7b3b2586cc02fc9ac4afcdae87503dc5e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2008000000ffffffffffffffff0420666666666666666666666666666666666666666666666666666666666666666600000000000200723205000000776eeba67324756c82881f4daa5e439605cdff0c6f65ef283cc99c5f4313c234f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210800000000000000000000800014777777777777777777777777777777777777777700020001000000001488888888888888888888888888888888888888880700000003209999999999999999999999999999999999999999999999999999999999999999000002007233";

// ── Fixture C: the attribution slot (has_attribution = 1) + ZERO receipts. ──
//   Wire-coverage only: V37.0 validity forbids attribution, so frame_policy
//   is DESCRIPTOR_INVALID by design — this fixture proves the bytes of the F-2
//   slot are pinned for the V37.x rule change AND that the policy gate catches
//   it today. receipt_count = 0 pins the empty-receipts tail.
inline Carrier fixture_c() {
    using namespace detail;
    ::v37::PayoutDescriptor d = desc_of(ref(::v37::ScriptKind::P2WPKH, 20, 0xaa));
    d.attribution = ref(::v37::ScriptKind::P2SH, 20, 0xbb);
    Carrier c;
    c.carrier = event(1, d, pat(0x10), bytes32{}, 8, 0, "attr-slot");
    return c;
}
inline const char* kGoldenHexC =
    "0101000000421c7cf39233e87b3a5fc2be14e301f5edf2ed6736faae969c2ce668a0fe5682101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f00000000000000000000000000000000000000000000000000000000000000000800000000000000000000000214aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010114bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000000900617474722d736c6f7400";

inline std::vector<FrozenFixture> frozen_fixtures() {
    return {
        {"A.p2pkh.1+1",           fixture_a(), kGoldenHexA, Policy::OK},
        {"B.all-branches.1+4",    fixture_b(), kGoldenHexB, Policy::OK},
        {"C.attribution-slot.1+0", fixture_c(), kGoldenHexC, Policy::DESCRIPTOR_INVALID},
    };
}

// ── the byte-KAT body ───────────────────────────────────────────────────────
// Pure: no I/O. `log` holds one line per failed check (plus a golden dump on a
// byte mismatch) so a harness or a boot log can print exactly what drifted.
struct SelfCheck {
    unsigned    checks   = 0;
    unsigned    failures = 0;
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
    auto le_u32 = [](const std::vector<std::uint8_t>& b, std::size_t at) {
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= std::uint32_t(b[at + i]) << (8 * i);
        return v;
    };
    auto le_u64 = [](const std::vector<std::uint8_t>& b, std::size_t at) {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= std::uint64_t(b[at + i]) << (8 * i);
        return v;
    };
    auto b32_at = [](const std::vector<std::uint8_t>& b, std::size_t at) {
        bytes32 h{};
        for (int i = 0; i < 32; ++i) h[i] = b[at + i];
        return h;
    };
    auto event_bytes_match = [&](const std::vector<std::uint8_t>& b, std::size_t at,
                                 const WorkEvent& e, const std::string& who) {
        if (!chk(b.size() >= at + kEventFixedBytes, who + ": fixed prefix in range")) return;
        chk(le_u32(b, at + kOffChainId) == e.chain_id,        who + ": chain_id @+0 LE u32");
        chk(b32_at(b, at + kOffIdentity) == e.identity,       who + ": identity @+4");
        chk(b32_at(b, at + kOffPrevBlock) == e.prev_block_hash, who + ": prev_block_hash @+36");
        chk(b32_at(b, at + kOffPrevOwn) == e.prev_own_share,  who + ": prev_own_share @+68");
        chk(le_u32(b, at + kOffLzBits) == e.lz_bits,          who + ": lz_bits @+100 LE u32");
        chk(le_u64(b, at + kOffNonce) == e.nonce,             who + ": nonce @+104 LE u64");
        // descriptor starts at +112 with the pay ref: kind byte then payload_len
        chk(b[at + kOffDescriptor] == static_cast<std::uint8_t>(e.descriptor.pay.kind),
            who + ": pay.kind @+112");
        chk(b[at + kOffDescriptor + 1] == static_cast<std::uint8_t>(e.descriptor.pay.payload.size()),
            who + ": pay.payload_len @+113");
        // tag is the LAST field: u16 len then bytes, ending exactly at event_size
        const std::size_t end = at + event_size(e);
        if (chk(b.size() >= end, who + ": tag in range")) {
            const std::size_t tl = end - e.tag.size();
            chk(b[tl - 2] == std::uint8_t(e.tag.size() & 0xff) &&
                b[tl - 1] == std::uint8_t(e.tag.size() >> 8), who + ": tag len u16 LE");
            chk(std::string(b.begin() + tl, b.begin() + end) == e.tag, who + ": tag bytes");
        }
    };

    // Global pins.
    chk(kFrozenVersion == 0x01 && W3_WIRE_VERSION == 0x01, "wire version frozen at 0x01");
    chk(kFrozenRMax == 4 && W3_R_MAX == 4, "R_MAX frozen at 4");
    chk(version_accepted(0x01) && !version_accepted(0x00) && !version_accepted(0x02),
        "accepted version set is exactly {0x01}");
    chk(kTransportMaxFrame == (1u << 20), "transport ceiling frozen at 1 MiB");

    for (const FrozenFixture& f : frozen_fixtures()) {
        const std::string who = std::string("fixture ") + f.name;
        const Carrier& c = f.carrier;
        chk(encodable(c), who + ": encodable under frozen widths");

        // (1) golden bytes
        const std::vector<std::uint8_t> bytes = CarrierWire::encode(c);
        const std::string hex = to_hex(bytes);
        if (!chk(hex == f.golden_hex, who + ": encode == golden"))
            sc.log += "  got   : " + hex + "\n  golden: " + f.golden_hex + "\n";

        // (2) independent size/offset model agrees with the codec
        chk(bytes.size() == frame_size(c), who + ": size == frame_size model");
        chk(transport_size(c) == kTransportLenBytes + bytes.size(), who + ": transport_size model");
        chk(!bytes.empty() && bytes[kOffVersion] == kFrozenVersion, who + ": version byte @0");
        chk(peek_version(bytes) == std::optional<std::uint8_t>(kFrozenVersion), who + ": peek_version");
        const std::size_t rc_off = receipt_count_offset(c);
        if (chk(rc_off < bytes.size(), who + ": receipt_count offset in range"))
            chk(bytes[rc_off] == c.receipts.size(), who + ": receipt_count byte @ model offset");
        event_bytes_match(bytes, kOffCarrier, c.carrier, who + " carrier");
        for (std::size_t i = 0; i < c.receipts.size(); ++i)
            event_bytes_match(bytes, receipt_offset(c, i), c.receipts[i],
                              who + " receipt[" + std::to_string(i) + "]");
        chk(receipt_offset(c, c.receipts.size()) == bytes.size(),
            who + ": receipts end exactly at frame end");

        // (3) decode(encode) round trip, lossless; (4) re-encode identity
        DecodeResult dr = CarrierWire::decode(bytes);
        chk(dr.status == WireStatus::OK, who + ": decode OK");
        chk(dr.dropped.empty(), who + ": no receipt dropped");
        chk(carriers_equal(dr.carrier, c), who + ": decode(encode(c)) == c (all fields)");
        chk(CarrierWire::encode(dr.carrier) == bytes, who + ": re-encode byte-identical");

        // (5) the GOLDEN itself decodes to the fixture (independent of encode)
        const std::vector<std::uint8_t> gold = from_hex(f.golden_hex);
        chk(!gold.empty(), who + ": golden hex well-formed");
        DecodeResult dg = CarrierWire::decode(gold);
        chk(dg.status == WireStatus::OK && carriers_equal(dg.carrier, c),
            who + ": decode(golden) == fixture");

        // (6) policy verdict is the frozen expectation
        chk(frame_policy(c) == f.expected_policy,
            who + ": frame_policy == " + policy_name(f.expected_policy));

        // (7) every strict prefix is REJECT_TRUNCATED (no field is optional)
        bool all_trunc = true;
        for (std::size_t n = 0; n < bytes.size(); ++n) {
            std::vector<std::uint8_t> pre(bytes.begin(), bytes.begin() + n);
            if (CarrierWire::decode(pre).status != WireStatus::REJECT_TRUNCATED) { all_trunc = false; break; }
        }
        chk(all_trunc, who + ": every strict prefix -> REJECT_TRUNCATED");

        // (8) one trailing byte -> REJECT_TRUNCATED (frame is exact-length)
        { auto t = bytes; t.push_back(0x00);
          chk(CarrierWire::decode(t).status == WireStatus::REJECT_TRUNCATED, who + ": trailing byte rejected"); }

        // (9) version policy: 0x00 / 0x02 / 0xff -> REJECT_BAD_VERSION
        for (std::uint8_t v : {std::uint8_t(0x00), std::uint8_t(0x02), std::uint8_t(0xff)}) {
            auto t = bytes; t[kOffVersion] = v;
            chk(CarrierWire::decode(t).status == WireStatus::REJECT_BAD_VERSION,
                who + ": version 0x" + to_hex({v}) + " rejected");
        }

        // (10) receipt_count = R_MAX+1 -> REJECT_RMAX (whole carrier)
        if (rc_off < bytes.size()) {
            auto t = bytes; t[rc_off] = static_cast<std::uint8_t>(kFrozenRMax + 1);
            chk(CarrierWire::decode(t).status == WireStatus::REJECT_RMAX, who + ": R_MAX+1 rejected");
        }

        // (11) carrier identity flipped -> REJECT_CARRIER_UNBOUND (W3-MUST)
        { auto t = bytes; t[kOffCarrier + kOffIdentity] ^= 0x01;
          chk(CarrierWire::decode(t).status == WireStatus::REJECT_CARRIER_UNBOUND,
              who + ": mis-bound carrier rejected"); }

        // (12) receipt[0] identity flipped -> OK, that receipt dropped, rest stand
        if (!c.receipts.empty()) {
            auto t = bytes; t[receipt_offset(c, 0) + kOffIdentity] ^= 0x01;
            DecodeResult dd = CarrierWire::decode(t);
            chk(dd.status == WireStatus::OK && dd.dropped.size() == 1 &&
                dd.carrier.receipts.size() == c.receipts.size() - 1,
                who + ": mis-bound receipt dropped, carrier stands");
        }
    }

    // Policy unit pins (synthetic violations, no goldens involved).
    {
        Carrier c = fixture_a();
        c.carrier.tag.assign(kTagMaxBytes + 1, 't');
        chk(frame_policy(c) == Policy::TAG_TOO_LONG, "policy: carrier tag cap+1 -> TAG_TOO_LONG");
        chk(apply_policy(c) == Policy::TAG_TOO_LONG, "policy: apply rejects over-cap carrier");

        c = fixture_a();
        c.receipts[0].tag.assign(kTagMaxBytes + 1, 't');
        std::vector<std::pair<std::string, Policy>> dropped;
        chk(frame_policy(c) == Policy::TAG_TOO_LONG, "policy: strict verdict sees receipt tag");
        chk(apply_policy(c, &dropped) == Policy::OK && dropped.size() == 1 &&
            dropped[0].second == Policy::TAG_TOO_LONG && c.receipts.empty(),
            "policy: apply drops over-cap receipt, carrier stands");

        c = fixture_a();
        c.carrier.descriptor.attribution = c.carrier.descriptor.pay;
        chk(frame_policy(c) == Policy::DESCRIPTOR_INVALID, "policy: attribution -> DESCRIPTOR_INVALID");

        c = fixture_a();
        for (int i = 0; i < 4; ++i) c.receipts.push_back(c.receipts[0]);   // 5 receipts
        chk(frame_policy(c) == Policy::RECEIPT_COUNT && !encodable(c),
            "policy+encodable: 5 receipts refused");

        c = fixture_a();
        c.carrier.descriptor.pay.payload.assign(256, 0x01);
        chk(!encodable(c), "encodable: payload_len 256 does not fit u8");

        PolicyStats st;
        auto hook = make_relay_policy(&st);
        Carrier good = fixture_a(), bad = fixture_c();
        chk(hook(good) && !hook(bad) && st.frames_passed.load() == 1 && st.frames_rejected.load() == 1,
            "relay hook: passes A, rejects C, counts both");
    }
    return sc;
}

} // namespace c2pool::v37n::wire_freeze
