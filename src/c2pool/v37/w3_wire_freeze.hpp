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
// VERSION POLICY (F-5) — DISCHARGED BY S-1c (2026-09-12)
//   W3_WIRE_VERSION (w3_relay.hpp) is the ONLY knob. The 0x02 bump below is
//   exactly the sanctioned path this policy laid out, taken verbatim:
//     * the decoder DUAL-ACCEPTS {0x01, 0x02} for the upgrade window;
//     * 0x01 is NOT re-packed — kGoldenHexA/B/C are byte-for-byte the values
//       they were on 2026-09-07, and selfcheck() re-runs them through the
//       EXPLICIT CarrierWire::encode_version(c, 0x01) seam;
//     * 0x02 ships its own fixtures (D, E) and its own goldens here;
//     * the emitter emits the CURRENT version (0x02) for every frame, so a
//       v0x01-only peer rejects it at decode (REJECT_BAD_VERSION). That is the
//       FLAG DAY, and it is deliberately LOUD: a mixed fleet must not be able
//       to half-relay a block-winner descriptor (a v0x01 hop would silently
//       strip the cut and desynchronise the OWED ledger downstream of it).
//
// THE FROZEN v0x02 LAYOUT (S-1c cut descriptor; the v0x01 body VERBATIM plus a
// TRAILER, so every v0x01 offset and every v0x01 size-model function above
// stays valid over the v0x02 prefix)
//
//   frame_v2  := u8      version (= 0x02)
//                event   carrier                    (v0x01 event, unchanged)
//                u8      receipt_count              (unchanged)
//                event   receipt[receipt_count]     (unchanged)
//                cutdesc trailer   @ v0x01 frame_size(c) == receipt_offset(c, n)
//   cutdesc   := u8  won_block                  (0 | 1; else REJECT_BAD_CUT)
//                if won_block == 1:
//                  b32 bid                     @ +1    (32)
//                  u64 h_b                     @ +33   (8)
//                  u64 cut_next_pos  (P)       @ +41   (8)
//                  b32 cut_spine_digest        @ +49   (32)
//                  u64 reward                  @ +81   (8)
//                  u8  payout_emitted          @ +89   (1; else REJECT_BAD_CUT)
//                  b32 owed_digest_at_win      @ +90   (32)
//                                              total 122 bytes (1 when won=0)
//
//   Decode rules that are PART of the 0x02 freeze:
//     won_block outside {0,1}       -> REJECT_BAD_CUT (whole frame)
//     payout_emitted outside {0,1}  -> REJECT_BAD_CUT (whole frame)
//     a short trailer               -> REJECT_TRUNCATED
//     trailing bytes after cutdesc  -> REJECT_TRUNCATED (frame is exact-length)
//   A v0x01 frame decodes with NO descriptor; a v0x02 frame with won_block == 0
//   also decodes with no descriptor — indistinguishable above the codec.
//
//   NOT on this wire, on purpose: lane version / incarnation (node-local —
//   incarnation is executor-minted and version is a per-lane PUBLICATION count
//   that depends on burst coalescing, so neither can address a PEER's cut), the
//   coinbase payout map (unbounded), and any MMR peak (a receiver must APPEND
//   the identical leaf itself, never insert a peer's peak).
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

#include <algorithm>
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
constexpr std::uint8_t  kFrozenVersion   = 0x01;   // W3-B5 frozen 2026-09-07
constexpr std::uint8_t  kFrozenVersionV2 = 0x02;   // S-1c  frozen 2026-09-12
constexpr std::uint8_t  kFrozenVersionV3 = 0x03;   // DROPS-R3 frozen 2026-09-12
constexpr std::uint32_t kFrozenRMax      = 4;
static_assert(kFrozenVersion == W3_WIRE_VERSION_V1,
              "W3-B5: the v0x01 frozen wire version tag is 0x01 and never moves");
static_assert(kFrozenVersionV2 == W3_WIRE_VERSION_V2,
              "S-1c: the v0x02 frozen wire version tag is 0x02");
static_assert(kFrozenVersionV3 == W3_WIRE_VERSION_V3,
              "DROPS-R3: the v0x03 frozen wire version tag is 0x03");
static_assert(kFrozenVersionV3 == W3_WIRE_VERSION,
              "DROPS-R3: this build EMITS the current frozen version (0x03); a "
              "wire change is a VISIBLE bump with new goldens, never a re-pack");
static_assert(kFrozenRMax == W3_R_MAX,
              "W3-B5: receipt_count bound is frozen at 4 (== W2_R_MAX)");

// Version acceptance set (F-5). {0x01, 0x02, 0x03} for the DROPS-R3 upgrade
// window: an older peer's frames are still decoded and accounted; a version
// retires only when the operator says so, and its goldens stay green until then.
inline constexpr std::uint8_t kAcceptedVersions[] = { kFrozenVersion, kFrozenVersionV2,
                                                      kFrozenVersionV3 };
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

// ── S-1c v0x02 cut-descriptor trailer widths / offsets (inside the trailer) ──
constexpr std::size_t kWonBlockBytes      = 1;
constexpr std::size_t kHbBytes            = 8;
constexpr std::size_t kCutNextPosBytes    = 8;
constexpr std::size_t kRewardBytes        = 8;
constexpr std::size_t kPayoutEmittedBytes = 1;
constexpr std::size_t kOffWonBlock        = 0;
constexpr std::size_t kOffCutBid          = kOffWonBlock + kWonBlockBytes;        // 1
constexpr std::size_t kOffCutHb           = kOffCutBid + kHashBytes;              // 33
constexpr std::size_t kOffCutNextPos      = kOffCutHb + kHbBytes;                 // 41
constexpr std::size_t kOffCutSpineDigest  = kOffCutNextPos + kCutNextPosBytes;    // 49
constexpr std::size_t kOffCutReward       = kOffCutSpineDigest + kHashBytes;      // 81
constexpr std::size_t kOffCutPayoutEmit   = kOffCutReward + kRewardBytes;         // 89
constexpr std::size_t kOffCutOwedAtWin    = kOffCutPayoutEmit + kPayoutEmittedBytes; // 90
constexpr std::size_t kCutDescBytesAbsent = kWonBlockBytes;                       // 1
constexpr std::size_t kCutDescBytesPresent = kOffCutOwedAtWin + kHashBytes;       // 122
static_assert(kCutDescBytesPresent == 122, "frozen v0x02 cut descriptor is 122 bytes");

// ── ★ DROPS-R3 v0x03 credit-map trailer widths (inside the trailer) ─────────
// present(1) [ count(2) + count x (payee 32 + credit 8) + enrollment_digest(32) ]
constexpr std::size_t kDropsPresentBytes = 1;
constexpr std::size_t kDropsCountBytes   = 2;
constexpr std::size_t kDropsCreditBytes  = 8;
constexpr std::size_t kDropsEntryBytes   = kHashBytes + kDropsCreditBytes;        // 40
constexpr std::size_t kDropsBytesAbsent  = kDropsPresentBytes;                    // 1
static_assert(kDropsEntryBytes == 40, "frozen v0x03 credit-map entry is 40 bytes");
inline std::size_t drops_bytes_present(std::size_t n) {
    return kDropsPresentBytes + kDropsCountBytes + n * kDropsEntryBytes + kHashBytes;
}
static_assert(kOffCutHb == 33 && kOffCutNextPos == 41 && kOffCutSpineDigest == 49 &&
              kOffCutReward == 81 && kOffCutPayoutEmit == 89 && kOffCutOwedAtWin == 90,
              "frozen v0x02 cut-descriptor offsets");

// The frozen LAYOUT IDs. Two ids, not one: a node logs both so an operator
// reading two nodes' boot lines can see at a glance which wire each SPEAKS and
// which it ACCEPTS. layout_id() keeps its 2026-09-07 value verbatim — changing
// it would be a re-pack claim about v0x01, which S-1c does not make.
inline const char* layout_id()    { return "w3-carrier-wire/v0x01/frozen-2026-09-07"; }
inline const char* layout_id_v2() { return "w3-carrier-wire/v0x02/frozen-2026-09-12"; }
inline const char* layout_id_v3() { return "w3-carrier-wire/v0x03/frozen-2026-09-12"; }
// The FLAG-DAY MARKER: what this build emits, and what it accepts. A v0x01-only
// peer REJECTS every frame this build sends (REJECT_BAD_VERSION at its decode)
// — the flag day is loud on purpose, so a mixed fleet cannot silently strip a
// block-winner cut descriptor at a v0x01 hop.
inline const char* flag_day_id() {
    return "w3-carrier-wire/flag-day/drops-r3-2026-09-12: emit=v0x03 "
           "accept={v0x01,v0x02,v0x03}";
}

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
// v0x01 frame size — UNCHANGED, and still the exact size of an encode_version(
// c, 0x01) frame. Under v0x02 it is the offset of the cut-descriptor trailer.
inline std::size_t frame_size(const Carrier& c) {
    std::size_t n = kVersionBytes + event_size(c.carrier) + kReceiptCountBytes;
    for (const WorkEvent& r : c.receipts) n += event_size(r);
    return n;
}
// S-1c: the trailer's own size, and the whole v0x02 frame.
inline std::size_t cutdesc_size(const Carrier& c) {
    return c.cut.has_value() ? kCutDescBytesPresent : kCutDescBytesAbsent;
}
inline std::size_t frame_size_v2(const Carrier& c) {
    return frame_size(c) + cutdesc_size(c);
}
// DROPS-R3: the credit-map trailer's own size, and the whole v0x03 frame. The
// v0x03 frame is the v0x02 frame VERBATIM plus this trailer, so every v0x01 and
// v0x02 offset above stays valid over the v0x03 prefix.
inline std::size_t drops_size(const Carrier& c) {
    return c.drops.has_value() ? drops_bytes_present(c.drops->credit.size())
                               : kDropsBytesAbsent;
}
inline std::size_t frame_size_v3(const Carrier& c) {
    return frame_size_v2(c) + drops_size(c);
}
// Frame offset of the v0x03 credit-map trailer's first byte (== the v0x02 frame
// size, which is the whole point of putting it at the END).
inline std::size_t drops_offset(const Carrier& c) { return frame_size_v2(c); }
// Frame offset of the v0x02 cut-descriptor trailer's first byte (== the v0x01
// frame size, which is the whole point of putting it at the END).
inline std::size_t cutdesc_offset(const Carrier& c) { return frame_size(c); }
// Size at an explicit version (0 for a combination the layout cannot express:
// an unknown version, or v0x01 asked to carry a cut descriptor).
inline std::size_t frame_size_at(const Carrier& c, std::uint8_t ver) {
    // A credit map with no cut names no settlement: the encoder refuses it at
    // EVERY version, so the model says 0 bytes there too.
    if (c.drops.has_value() && !c.cut.has_value()) return 0;
    if (ver == kFrozenVersionV3) return frame_size_v3(c);
    if (ver == kFrozenVersionV2) return c.drops.has_value() ? 0 : frame_size_v2(c);
    if (ver == kFrozenVersion)
        return (c.cut.has_value() || c.drops.has_value()) ? 0 : frame_size(c);
    return 0;
}
inline std::size_t transport_size(const Carrier& c) {
    return kTransportLenBytes + frame_size(c);
}
inline std::size_t transport_size_v2(const Carrier& c) {
    return kTransportLenBytes + frame_size_v2(c);
}
inline std::size_t transport_size_v3(const Carrier& c) {
    return kTransportLenBytes + frame_size_v3(c);
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
    // The cut descriptor is all fixed-width (b32 / u64 / bool bytes) — there is
    // no field a caller can over-fill — so the only v0x02 ceiling check is the
    // whole-frame one, taken at the LARGER of the two versions.
    if (frame_size_v2(c) > kTransportMaxFrame) return fail("frame exceeds transport ceiling");
    return true;
}
// Can this carrier be expressed at THIS version? v0x01 cannot carry a cut
// descriptor; encode_version(c, 0x01) refuses (empty vector) rather than
// silently dropping it, and this is the caller-side form of that refusal.
inline bool encodable_at(const Carrier& c, std::uint8_t ver, std::string* why = nullptr) {
    if (ver != kFrozenVersion && ver != kFrozenVersionV2 && ver != kFrozenVersionV3) {
        if (why) *why = "unknown wire version";
        return false;
    }
    if (ver == kFrozenVersion && c.cut.has_value()) {
        if (why) *why = "v0x01 cannot express a cut descriptor (S-1c needs v0x02)";
        return false;
    }
    if (ver != kFrozenVersionV3 && c.drops.has_value()) {
        if (why) *why = "only v0x03 can express a DROPS credit map (DROPS-R3)";
        return false;
    }
    if (c.drops.has_value() && !c.cut.has_value()) {
        if (why) *why = "a DROPS credit map with no cut descriptor names no settlement";
        return false;
    }
    if (c.drops.has_value() &&
        c.drops->credit.size() > static_cast<std::size_t>(W3_DROPS_MAX_ENTRIES)) {
        if (why) *why = "DROPS credit map over W3_DROPS_MAX_ENTRIES";
        return false;
    }
    return encodable(c, why);
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
    // S-1c / DROPS-R3: both trailers are part of carrier identity.
    return a.cut == b.cut && a.drops == b.drops;
}
// A legible S-1c cut descriptor for the v0x02 fixtures.
inline CutDescriptor cut(std::uint8_t bid_base, u64 h_b, u64 p, std::uint8_t spine_base,
                         u64 reward, bool payout_emitted, std::uint8_t owed_base) {
    CutDescriptor c;
    c.bid                = pat(bid_base);
    c.h_b                = h_b;
    c.cut_next_pos       = p;
    c.cut_spine_digest   = pat(spine_base);
    c.reward             = reward;
    c.payout_emitted     = payout_emitted;
    c.owed_digest_at_win = pat(owed_base);
    return c;
}
// A legible DROPS-R3 credit map for the v0x03 fixtures: three payees in the
// STRICTLY ASCENDING order the wire requires, one NEGATIVE delta (the replace
// composition is signed, so the two's-complement path must be pinned too), and
// an enrolment-book digest that is distinguishable from every other pattern.
inline DropsCredit drops(std::uint8_t a, std::uint8_t b, std::uint8_t c,
                         std::uint8_t enrol_base) {
    DropsCredit d;
    d.credit.emplace_back(pat(a), 1);
    d.credit.emplace_back(pat(b), -4200000000LL);
    d.credit.emplace_back(pat(c), 9007199254740993LL);
    d.enrollment_digest = pat(enrol_base);
    return d;
}
} // namespace detail

struct FrozenFixture {
    const char*   name;
    Carrier       carrier;
    const char*   golden_hex;       // encode_version(carrier, `version`)
    Policy        expected_policy;  // frame_policy(carrier)
    std::uint8_t  version = kFrozenVersion;
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

// ══ S-1c wire v0x02 fixtures ═══════════════════════════════════════════════
// ── Fixture D: the v0x02 NO-DESCRIPTOR shape (won_block = 0). ───────────────
//   Body byte-for-byte fixture A; the ONLY differences from kGoldenHexA are the
//   version byte (01 -> 02) and the single trailing 00. This is the shape EVERY
//   ordinary share carrier takes on the new wire, so its golden is the one that
//   pins "v0x02 costs exactly one byte when there is nothing to say".
inline Carrier fixture_d() {
    Carrier c = fixture_a();
    c.cut.reset();
    return c;
}
inline const char* kGoldenHexD =
    
    "0201000000fd2e83fe009e7e6c791745176f53719653bc35f5705564e912d4af2413cce77d404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000000000000000000000000000000000000000000000000000000000000008000000efcdab89674523010014111111111111111111111111111111111111111100000000000100630101000000fd2e83fe009e7e6c791745176f53719653bc35f5705564e912d4af2413cce77d606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f08000000dec0ad0bcefaedfe0014111111111111111111111111111111111111111100000000000200723000";

// ── Fixture E: the v0x02 FULL cut descriptor on a full-branch body. ────────
//   Body byte-for-byte fixture B (every ScriptKind, R_MAX receipts, tag at the
//   cap) + a descriptor whose every field is distinguishable: bid pat(0x01),
//   H_b = 0x0000000000031337, P = 0x00000000000004d2, spine pat(0x20),
//   reward = 0x0000000012a05f200 truncated to u64 5000000000 (a whole-coin
//   subsidy), payout_emitted = 0 (the fresh-win shape the receiver accepts),
//   owed_digest_at_win pat(0xc3). Pins EVERY offset in the trailer at once.
inline Carrier fixture_e() {
    using namespace detail;
    Carrier c = fixture_b();
    c.cut = cut(/*bid_base=*/0x01, /*h_b=*/0x31337, /*p=*/1234, /*spine_base=*/0x20,
                /*reward=*/5000000000ULL, /*payout_emitted=*/false, /*owed_base=*/0xc3);
    return c;
}
inline const char* kGoldenHexE =
    "0205000000ea52ca7f1548684e30d336d8c18cf7e8fedf091cd5b9afca93d2c5474cdb9883808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf090000008877665544332211ff20b697e503a530429f57e4a197f7aa0f37c38aaaa803f29839ab49062f345daea40001002a0000000214333333333333333333333333333333333333333306006a04deadbeef4000422e636172726965722e7461672d61742d6361703a78787878787878787878787878787878787878787878787878787878787878787878787878787878787878040500000025ef7da35aa62fb1efe73c82e13ed86c288ed5478b011d68de38a3ae69a1f7fcc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f0800000001000000000000000114444444444444444444444444444444444444444400000000000200723005000000f2af3b63ad987b888cf4ad86ed5c06ba8611fdc9185c42c35cc46c06fe301eaed0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeefc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf0900000000000000010000000320555555555555555555555555555555555555555555555555555555555555555500000000000000050000005a983a97b2df748e4a13849701c7e34b7b3b2586cc02fc9ac4afcdae87503dc5e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2008000000ffffffffffffffff0420666666666666666666666666666666666666666666666666666666666666666600000000000200723205000000776eeba67324756c82881f4daa5e439605cdff0c6f65ef283cc99c5f4313c234f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210800000000000000000000800014777777777777777777777777777777777777777700020001000000001488888888888888888888888888888888888888880700000003209999999999999999999999999999999999999999999999999999999999999999000002007233010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f203713030000000000d204000000000000202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00f2052a0100000000c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2";   // filled by the v0x02 freeze KAT's generator

// ── Fixture F: payout_emitted = 1 — the one shape a receiver REFUSES. ──────
//   Wire-coverage: the flag's byte position and its value must be pinned, and
//   the KAT asserts the receiver's fail-closed refusal rides exactly this bit.
inline Carrier fixture_f() {
    using namespace detail;
    Carrier c = fixture_a();
    c.cut = cut(/*bid_base=*/0xf0, /*h_b=*/1, /*p=*/0, /*spine_base=*/0x00,
                /*reward=*/0, /*payout_emitted=*/true, /*owed_base=*/0xb4);
    return c;
}
inline const char* kGoldenHexF =
    "0201000000fd2e83fe009e7e6c791745176f53719653bc35f5705564e912d4af2413cce77d404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000000000000000000000000000000000000000000000000000000000000008000000efcdab89674523010014111111111111111111111111111111111111111100000000000100630101000000fd2e83fe009e7e6c791745176f53719653bc35f5705564e912d4af2413cce77d606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f08000000dec0ad0bcefaedfe0014111111111111111111111111111111111111111100000000000200723001f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f01000000000000000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000000000000000001b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3";   // filled by the v0x02 freeze KAT's generator

// ══ DROPS-R3 wire v0x03 fixtures ═══════════════════════════════════════════
// ── Fixture G: the v0x03 NOTHING-TO-SAY shape (no cut, no credit map). ─────
//   Body byte-for-byte fixture A; the ONLY differences from kGoldenHexA are the
//   version byte (01 -> 03) and TWO trailing zeros — one for the absent cut, one
//   for the absent credit map. This is the shape every ordinary share carrier
//   takes on the DROPS wire, so its golden is the one that pins "v0x03 costs
//   exactly one more byte than v0x02 when there is nothing to say".
inline Carrier fixture_g() {
    Carrier c = fixture_a();
    c.cut.reset();
    c.drops.reset();
    return c;
}
inline const char* kGoldenHexG =
    "0301000000fd2e83fe009e7e6c791745176f53719653bc35f5705564e912d4af2413cce77d404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000000000000000000000000000000000000000000000000000000000000008000000efcdab89674523010014111111111111111111111111111111111111111100000000000100630101000000fd2e83fe009e7e6c791745176f53719653bc35f5705564e912d4af2413cce77d606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f08000000dec0ad0bcefaedfe001411111111111111111111111111111111111111110000000000020072300000";

// ── Fixture H: the v0x03 FULL shape — cut descriptor + credit map. ────────
//   Body + cut byte-for-byte fixture E, plus a three-entry credit map with a
//   negative row and a row above 2^53 (so no float can round-trip it) and a
//   distinguishable enrolment digest. Pins every offset of the new trailer.
inline Carrier fixture_h() {
    using namespace detail;
    Carrier c = fixture_e();
    c.drops = drops(/*a=*/0x11, /*b=*/0x22, /*c=*/0x33, /*enrol_base=*/0xe7);
    return c;
}
inline const char* kGoldenHexH =
    "0305000000ea52ca7f1548684e30d336d8c18cf7e8fedf091cd5b9afca93d2c5474cdb9883808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf090000008877665544332211ff20b697e503a530429f57e4a197f7aa0f37c38aaaa803f29839ab49062f345daea40001002a0000000214333333333333333333333333333333333333333306006a04deadbeef4000422e636172726965722e7461672d61742d6361703a78787878787878787878787878787878787878787878787878787878787878787878787878787878787878040500000025ef7da35aa62fb1efe73c82e13ed86c288ed5478b011d68de38a3ae69a1f7fcc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f0800000001000000000000000114444444444444444444444444444444444444444400000000000200723005000000f2af3b63ad987b888cf4ad86ed5c06ba8611fdc9185c42c35cc46c06fe301eaed0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeefc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf0900000000000000010000000320555555555555555555555555555555555555555555555555555555555555555500000000000000050000005a983a97b2df748e4a13849701c7e34b7b3b2586cc02fc9ac4afcdae87503dc5e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2008000000ffffffffffffffff0420666666666666666666666666666666666666666666666666666666666666666600000000000200723205000000776eeba67324756c82881f4daa5e439605cdff0c6f65ef283cc99c5f4313c234f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210800000000000000000000800014777777777777777777777777777777777777777700020001000000001488888888888888888888888888888888888888880700000003209999999999999999999999999999999999999999999999999999999999999999000002007233010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f203713030000000000d204000000000000202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00f2052a0100000000c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e20103001112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30010000000000000022232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40410016a905ffffffff333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051520100000000002000e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff00010203040506";

// The v0x01 freeze set — UNCHANGED (these goldens never move while 0x01 is
// accepted; S-1c does not re-pack them, it only stops being the only wire).
inline std::vector<FrozenFixture> frozen_fixtures() {
    return {
        {"A.p2pkh.1+1",            fixture_a(), kGoldenHexA, Policy::OK,                 kFrozenVersion},
        {"B.all-branches.1+4",     fixture_b(), kGoldenHexB, Policy::OK,                 kFrozenVersion},
        {"C.attribution-slot.1+0", fixture_c(), kGoldenHexC, Policy::DESCRIPTOR_INVALID, kFrozenVersion},
    };
}
// The v0x02 freeze set (S-1c).
inline std::vector<FrozenFixture> frozen_fixtures_v2() {
    return {
        {"D.v2.no-descriptor",  fixture_d(), kGoldenHexD, Policy::OK, kFrozenVersionV2},
        {"E.v2.full-cut",       fixture_e(), kGoldenHexE, Policy::OK, kFrozenVersionV2},
        {"F.v2.payout-emitted", fixture_f(), kGoldenHexF, Policy::OK, kFrozenVersionV2},
    };
}
// The v0x03 freeze set (DROPS-R3).
inline std::vector<FrozenFixture> frozen_fixtures_v3() {
    return {
        {"G.v3.nothing-to-say", fixture_g(), kGoldenHexG, Policy::OK, kFrozenVersionV3},
        {"H.v3.cut+credit-map", fixture_h(), kGoldenHexH, Policy::OK, kFrozenVersionV3},
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
    chk(kFrozenVersion == 0x01, "v0x01 wire version tag frozen at 0x01");
    chk(kFrozenVersionV2 == 0x02 && kFrozenVersionV3 == 0x03 && W3_WIRE_VERSION == 0x03,
        "DROPS-R3: this build EMITS wire v0x03");
    chk(kFrozenRMax == 4 && W3_R_MAX == 4, "R_MAX frozen at 4");
    chk(version_accepted(0x01) && version_accepted(0x02) && version_accepted(0x03) &&
        !version_accepted(0x00) && !version_accepted(0x04) && !version_accepted(0xff),
        "accepted version set is exactly {0x01, 0x02, 0x03} (F-5 accept window)");
    chk(kTransportMaxFrame == (1u << 20), "transport ceiling frozen at 1 MiB");
    chk(std::string(layout_id()) == "w3-carrier-wire/v0x01/frozen-2026-09-07",
        "v0x01 layout id UNCHANGED by the S-1c bump");
    chk(std::string(layout_id_v2()) == "w3-carrier-wire/v0x02/frozen-2026-09-12",
        "v0x02 layout id pinned");
    chk(std::string(layout_id_v3()) == "w3-carrier-wire/v0x03/frozen-2026-09-12",
        "v0x03 layout id pinned");
    chk(kCutDescBytesPresent == 122 && kCutDescBytesAbsent == 1,
        "cut descriptor is 122 bytes present / 1 byte absent");
    chk(kDropsEntryBytes == 40 && kDropsBytesAbsent == 1 &&
            drops_bytes_present(0) == 35 && drops_bytes_present(3) == 155,
        "DROPS credit-map trailer: 1 byte absent, 35 + 40n present");

    // ── the per-fixture body, run over BOTH frozen version sets ─────────────
    auto run_fixture = [&](const FrozenFixture& f) {
        const std::string who = std::string("fixture ") + f.name;
        const Carrier& c = f.carrier;
        // Both v0x02 and v0x03 carry the cut trailer; v0x03 adds the credit map.
        const bool v2 = (f.version == kFrozenVersionV2 || f.version == kFrozenVersionV3);
        const bool v3 = (f.version == kFrozenVersionV3);
        chk(encodable_at(c, f.version), who + ": encodable at its frozen version");

        // (1) golden bytes, through the EXPLICIT version seam
        const std::vector<std::uint8_t> bytes = CarrierWire::encode_version(c, f.version);
        const std::string hex = to_hex(bytes);
        if (!chk(hex == f.golden_hex, who + ": encode_version == golden"))
            sc.log += "  got   : " + hex + "\n  golden: " + f.golden_hex + "\n";

        // (2) independent size/offset model agrees with the codec
        chk(bytes.size() == frame_size_at(c, f.version), who + ": size == frame_size model");
        chk(kTransportLenBytes + bytes.size() ==
                (v3 ? transport_size_v3(c)
                    : (v2 ? transport_size_v2(c) : transport_size(c))),
            who + ": transport_size model");
        chk(!bytes.empty() && bytes[kOffVersion] == f.version, who + ": version byte @0");
        chk(peek_version(bytes) == std::optional<std::uint8_t>(f.version), who + ": peek_version");
        const std::size_t rc_off = receipt_count_offset(c);
        if (chk(rc_off < bytes.size(), who + ": receipt_count offset in range"))
            chk(bytes[rc_off] == c.receipts.size(), who + ": receipt_count byte @ model offset");
        event_bytes_match(bytes, kOffCarrier, c.carrier, who + " carrier");
        for (std::size_t i = 0; i < c.receipts.size(); ++i)
            event_bytes_match(bytes, receipt_offset(c, i), c.receipts[i],
                              who + " receipt[" + std::to_string(i) + "]");
        chk(receipt_offset(c, c.receipts.size()) == (v2 ? cutdesc_offset(c) : bytes.size()),
            who + ": receipts end exactly where the model says");

        // (2b) S-1c: the trailer's own bytes, field by field, at the frozen
        //      offsets — the v0x01 half of the frame is not re-checked here,
        //      it is already pinned above.
        if (v2) {
            const std::size_t t = cutdesc_offset(c);
            chk(bytes.size() == t + cutdesc_size(c) + (v3 ? drops_size(c) : 0),
                who + ": trailer ends at frame end");
            if (chk(t < bytes.size(), who + ": trailer in range")) {
                chk(bytes[t + kOffWonBlock] == (c.cut.has_value() ? 1 : 0),
                    who + ": won_block byte @ trailer+0");
                if (c.cut) {
                    chk(b32_at(bytes, t + kOffCutBid) == c.cut->bid, who + ": bid @ trailer+1");
                    chk(le_u64(bytes, t + kOffCutHb) == c.cut->h_b, who + ": h_b @ trailer+33 LE");
                    chk(le_u64(bytes, t + kOffCutNextPos) == c.cut->cut_next_pos,
                        who + ": cut_next_pos @ trailer+41 LE");
                    chk(b32_at(bytes, t + kOffCutSpineDigest) == c.cut->cut_spine_digest,
                        who + ": cut_spine_digest @ trailer+49");
                    chk(le_u64(bytes, t + kOffCutReward) == c.cut->reward,
                        who + ": reward @ trailer+81 LE");
                    chk(bytes[t + kOffCutPayoutEmit] == (c.cut->payout_emitted ? 1 : 0),
                        who + ": payout_emitted @ trailer+89");
                    chk(b32_at(bytes, t + kOffCutOwedAtWin) == c.cut->owed_digest_at_win,
                        who + ": owed_digest_at_win @ trailer+90");
                }
            }
        }

        // (3) decode(encode) round trip, lossless; (4) re-encode identity
        DecodeResult dr = CarrierWire::decode(bytes);
        chk(dr.status == WireStatus::OK, who + ": decode OK");
        chk(dr.dropped.empty(), who + ": no receipt dropped");
        chk(carriers_equal(dr.carrier, c), who + ": decode(encode(c)) == c (all fields)");
        chk(CarrierWire::encode_version(dr.carrier, f.version) == bytes,
            who + ": re-encode byte-identical");

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

        // (9) version policy: 0x00 / 0x04 / 0xff -> REJECT_BAD_VERSION (0x02 and
        //     0x03 are ACCEPTED versions now, so neither is a rejection probe)
        for (std::uint8_t v : {std::uint8_t(0x00), std::uint8_t(0x04), std::uint8_t(0xff)}) {
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

        // (13) S-1c trailer validity: the two boolean bytes are BOOLEANS. A
        //      frame whose cut cannot be read is NEVER admitted (admitting the
        //      share and dropping the cut is precisely the divergence S-1c
        //      exists to close).
        if (v2) {
            const std::size_t t = cutdesc_offset(c);
            { auto b2 = bytes; b2[t + kOffWonBlock] = 0x02;
              chk(CarrierWire::decode(b2).status == WireStatus::REJECT_BAD_CUT,
                  who + ": won_block = 2 -> REJECT_BAD_CUT"); }
            if (c.cut) {
                auto b2 = bytes; b2[t + kOffCutPayoutEmit] = 0x7f;
                chk(CarrierWire::decode(b2).status == WireStatus::REJECT_BAD_CUT,
                    who + ": payout_emitted = 0x7f -> REJECT_BAD_CUT");
            }
        }
    };

    for (const FrozenFixture& f : frozen_fixtures())    run_fixture(f);
    for (const FrozenFixture& f : frozen_fixtures_v2()) run_fixture(f);
    for (const FrozenFixture& f : frozen_fixtures_v3()) run_fixture(f);

    // ── DROPS-R3 v0x03 byte pins + the decode refusals ──────────────────────
    {
        const Carrier& h = fixture_h();
        const auto b = CarrierWire::encode_version(h, kFrozenVersionV3);
        const std::size_t t = drops_offset(h);
        chk(b.size() == t + drops_bytes_present(3), "H: credit-map trailer size");
        if (chk(t + 3 <= b.size(), "H: credit-map trailer in range")) {
            chk(b[t] == 1, "H: drops present byte @ trailer+0");
            chk(le_u32(b, t + 1) % 65536u ==
                    static_cast<std::uint32_t>(h.drops->credit.size()),
                "H: entry count u16 LE @ trailer+1");
            chk(b32_at(b, t + 3) == h.drops->credit[0].first, "H: payee[0] @ trailer+3");
            chk(le_u64(b, t + 35) == static_cast<std::uint64_t>(h.drops->credit[0].second),
                "H: credit[0] u64 two's complement LE @ trailer+35");
            chk(le_u64(b, t + 3 + kDropsEntryBytes + kHashBytes) ==
                    static_cast<std::uint64_t>(h.drops->credit[1].second),
                "H: the NEGATIVE credit row round-trips as two's complement");
            chk(b32_at(b, t + drops_bytes_present(3) - kHashBytes) ==
                    h.drops->enrollment_digest,
                "H: enrolment digest is the LAST 32 bytes of the frame");
        }
        const DecodeResult dr = CarrierWire::decode(b);
        chk(dr.status == WireStatus::OK && dr.carrier.drops.has_value() &&
                *dr.carrier.drops == *h.drops,
            "H: the credit map decodes back EXACTLY, negative row included");

        // the refusals, one bit each
        auto b_bad = b;  b_bad[t] = 0x7f;
        chk(CarrierWire::decode(b_bad).status == WireStatus::REJECT_BAD_DROPS,
            "drops present byte outside {0,1} -> REJECT_BAD_DROPS");
        auto b_big = b;  b_big[t + 1] = 0xff; b_big[t + 2] = 0xff;
        chk(CarrierWire::decode(b_big).status != WireStatus::OK,
            "an entry count above the cap is never accepted");
        {   // payees out of order: swap entry 0 and entry 1's payees
            auto b_ord = b;
            for (std::size_t i = 0; i < kHashBytes; ++i)
                std::swap(b_ord[t + 3 + i], b_ord[t + 3 + kDropsEntryBytes + i]);
            chk(CarrierWire::decode(b_ord).status == WireStatus::REJECT_BAD_DROPS,
                "payees not strictly ascending -> REJECT_BAD_DROPS (no ambiguous fold)");
        }
        {   // a credit map with NO cut descriptor: refused at encode AND decode
            Carrier nocut = fixture_a();
            nocut.cut.reset();
            nocut.drops = detail::drops(0x11, 0x22, 0x33, 0xe7);
            chk(CarrierWire::encode_version(nocut, kFrozenVersionV3).empty(),
                "a credit map with no cut is not encodable at any version");
            // hand-build the same shape and prove decode refuses it too
            Carrier bare = fixture_a();
            bare.cut.reset();
            auto raw = CarrierWire::encode_version(bare, kFrozenVersionV3);
            raw.pop_back();                                   // drop drops_present=0
            std::vector<std::uint8_t> map_bytes;
            {
                Carrier tmp = fixture_h();
                const auto full = CarrierWire::encode_version(tmp, kFrozenVersionV3);
                const std::size_t off = drops_offset(tmp);
                map_bytes.assign(full.begin() + static_cast<long>(off), full.end());
            }
            raw.insert(raw.end(), map_bytes.begin(), map_bytes.end());
            chk(CarrierWire::decode(raw).status == WireStatus::REJECT_BAD_DROPS,
                "a decoded credit map with no cut descriptor -> REJECT_BAD_DROPS");
        }
        // v0x02 cannot express a credit map, and says so instead of dropping it
        chk(CarrierWire::encode_version(h, kFrozenVersionV2).empty(),
            "v0x02 refuses a DROPS credit map (never silently dropped)");
        chk(CarrierWire::encode_version(h, kFrozenVersion).empty(),
            "v0x01 refuses it too");
        chk(!encodable_at(h, kFrozenVersionV2) && encodable_at(h, kFrozenVersionV3),
            "encodable_at: v0x02 no / v0x03 yes for a credit-map carrier");
    }

    // ── S-1c cross-version pins ─────────────────────────────────────────────
    {
        // (i) A v0x02 frame WITHOUT a descriptor is the v0x01 frame with the
        //     version byte bumped and ONE zero byte appended. This is the
        //     no-re-pack claim, asserted rather than asserted-in-prose.
        for (const FrozenFixture& f : frozen_fixtures()) {
            const Carrier& c = f.carrier;
            const auto v1 = CarrierWire::encode_version(c, kFrozenVersion);
            const auto v2 = CarrierWire::encode_version(c, kFrozenVersionV2);
            const std::string who = std::string("cross ") + f.name;
            if (!chk(v2.size() == v1.size() + 1, who + ": v0x02 costs exactly one byte")) continue;
            chk(v2[0] == kFrozenVersionV2 && v1[0] == kFrozenVersion, who + ": version bytes");
            chk(std::equal(v1.begin() + 1, v1.end(), v2.begin() + 1), who + ": body byte-identical");
            chk(v2.back() == 0x00, who + ": won_block trailer = 0");
        }
        // (ii) v0x01 REFUSES to carry a descriptor (empty vector), and the
        //      encodable_at() guard says so before the encoder is called.
        Carrier w = fixture_e();
        chk(CarrierWire::encode_version(w, kFrozenVersion).empty(),
            "v0x01 refuses a cut descriptor (never silently dropped)");
        chk(!encodable_at(w, kFrozenVersion) && encodable_at(w, kFrozenVersionV2),
            "encodable_at: v0x01 no / v0x02 yes for a block-winner carrier");
        chk(CarrierWire::encode_version(w, 0x04).empty(), "unknown version encodes nothing");
        // (ii-b) DROPS-R3: a v0x03 frame with NOTHING to say is the v0x02 frame
        //        with the version byte bumped and ONE zero byte appended — the
        //        same no-re-pack claim, one version further on.
        for (const FrozenFixture& f : frozen_fixtures()) {
            const Carrier& c = f.carrier;
            const auto v2b = CarrierWire::encode_version(c, kFrozenVersionV2);
            const auto v3b = CarrierWire::encode_version(c, kFrozenVersionV3);
            const std::string who = std::string("cross-v3 ") + f.name;
            if (!chk(v3b.size() == v2b.size() + 1, who + ": v0x03 costs exactly one byte")) continue;
            chk(v3b[0] == kFrozenVersionV3 && v2b[0] == kFrozenVersionV2, who + ": version bytes");
            chk(std::equal(v2b.begin() + 1, v2b.end(), v3b.begin() + 1), who + ": body byte-identical");
            chk(v3b.back() == 0x00, who + ": drops trailer = 0");
        }
        // (iii) the default encode() emits the CURRENT version.
        chk(CarrierWire::encode(fixture_a()) == CarrierWire::encode_version(fixture_a(), kFrozenVersionV3),
            "encode() == encode_version(., 0x03)");
        // (iv) bid <-> hex is an exact round trip, and only 64 hex chars parse.
        const bytes32 bid = detail::pat(0x5a);
        chk(cut_bid_bytes(cut_bid_hex(bid)) == std::optional<bytes32>(bid),
            "cut bid hex round-trips exactly");
        chk(!cut_bid_bytes("00").has_value() && !cut_bid_bytes(std::string(64, 'z')).has_value(),
            "cut bid hex refuses short / non-hex input");
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
