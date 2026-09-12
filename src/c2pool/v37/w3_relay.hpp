#pragma once
// V37 Track A2 / W3 — carrier relay over the v36 p2p layer.
// CONSUMER-tree code (src/c2pool/v37/), stacked on the W2 receipt layer
// (w2_receipt.hpp / w2_admission.hpp). This slice owns the RELAY / wire layer
// ONLY; it never touches v37_engine.hpp or v37_lane_executor.hpp internals
// (disjoint file ownership with the W4-unblock lane), and it never calls
// Lane::push / receive() — every append goes through W2 admission into the W0
// V37Engine seam, and every read is an immutable snapshot (O1, §6 of the spec).
//
// Spec: /home/ubuntu/v37-work/v37-a2-w3-relay-spec.md (§2 wire extension, §3
// relay/gossip, §4 block-winning unconditional append, §5 ordering + dedup
// interplay, §8.4 bloat hook, and the closing "W3-MUST" identity-binding
// requirement). Wire contract of record: docs/c2pool-v37-share-format.md
// (frstrtr/the, blob 08f157df) §1-§8 — the RDWR receipt envelope / carrier
// rules; this header is the encode/decode of that contract.
//
// ── W3-B5 CARRIER-WIRE BYTE FREEZE (Track A2 step (b), 2026-09-07) ───────────
// The CarrierWire layout below is FROZEN as canonical wire version 0x01. The
// send-side (a node emitting its own stratum wins as carriers) relies on this
// being stable across nodes and builds, so the layout is now byte-pinned by a
// golden byte-KAT (src/c2pool/v37/test/v37_w3_wire_freeze_kat.cpp) — any change
// to a field, its width, its order, or its endianness trips that test. A future
// wire change is a VISIBLE version bump (W3_WIRE_VERSION), never a silent
// re-pack of 0x01. The frozen v0x01 layout, little-endian throughout:
//
//   frame  := u8 version(=0x01)
//             event   carrier
//             u8      receipt_count (0..R_MAX; a decoder seeing >R_MAX rejects)
//             event   receipt[receipt_count]
//   event  := u32 chain_id
//             b32 identity              (payout-descriptor identity key)
//             b32 prev_block_hash       (header hashPrevBlock, INTERNAL order)
//             b32 prev_own_share
//             u32 lz_bits
//             u64 nonce
//             desc descriptor
//             str tag                   (u16 len + bytes; bookkeeping, not PoW)
//   desc   := ref pay
//             u8  has_attribution ; if 1: ref attribution
//             u16 aux_count ; aux_count × { u32 chain_id ; ref ref }
//             u16 raw_script_len ; raw_script_len bytes
//   ref    := u8 kind ; u8 payload_len ; payload_len bytes
//   str    := u16 len ; len bytes
//   b32    := 32 raw bytes (no length prefix)
//   uN     := N/8 bytes, LITTLE-ENDIAN
//
// The transport framing that carries a frame between nodes (carrier_net.hpp) is
// [u32 LE length][length bytes = frame]; that prefix is transport-layer, not
// part of the carrier body, and is frozen alongside this layout.
// NOTE (still deferred to S-1/real share format): prev_block_hash/lz_bits carry
// the SYNTHETIC RDWR PoW envelope, not a real DASH block-header PoW. The freeze
// pins the CONTAINER; the field SEMANTICS widen when real share format lands.
//
// ── S-1c CARRIER-WIRE v0x02: THE FLAT CUT DESCRIPTOR (2026-09-12) ────────────
// v0x02 is the sanctioned version bump of the F-5 policy (w3_wire_freeze.hpp
// "VERSION POLICY"): v0x01 is NOT re-packed — its bytes stay byte-identical and
// its goldens stay green — and v0x02 appends ONE trailer after the last receipt,
// so every v0x01 offset and every v0x01 size-model function remains valid over
// the v0x02 prefix. The decoder DUAL-ACCEPTS {0x01, 0x02} for the upgrade
// window; the encoder emits the CURRENT W3_WIRE_VERSION.
//
//   frame_v2 := u8      version (= 0x02)
//               event   carrier                      (v0x01 event, unchanged)
//               u8      receipt_count                (unchanged)
//               event   receipt[receipt_count]       (unchanged)
//               cutdesc trailer                      @ v0x01 frame_size(c)
//   cutdesc  := u8  won_block                  (0 | 1; anything else REJECT_BAD_CUT)
//               if won_block == 1:
//                 b32 bid                      (hex(bid) IS the OwedLedger key)
//                 u64 h_b                      (H_b, the block's OWN height)
//                 u64 cut_next_pos             (P — the prefix the winner folded at)
//                 b32 cut_spine_digest         (LaneSnapshot::digest at P)
//                 u64 reward                   (the winner's block_reward(H_b))
//                 u8  payout_emitted           (0 | 1; 1 => receiver fail-closed)
//                 b32 owed_digest_at_win       (VERIFY field, never consensus)
//
// WHY THESE FIELDS AND NO OTHERS (S-1c cross-node convergence, the CUT RULE).
// A receiver must credit its OWN ledger with the SAME E_b the winner credited.
// E_b = fold_eb(reward, view@P) is a pure function of (reward, view.payout,
// view.identities) at ONE lane prefix P (w4_settlement.hpp S8), so the wire must
// pin BOTH arguments:
//   * `reward` — DashRpcCoinBackend::block_reward(h) answers fail-closed 0 when
//     its cached template height != h, and the receiver's height-watch has
//     already refreshed the template to H_b+1 by the time the carrier lands. A
//     receiver that asked its own backend would fold reward 0 => a VALUELESS
//     credit => A != B. Carrying it makes the credit a pure function of the wire.
//   * `cut_next_pos` + `cut_spine_digest` — the receiver must fold at the
//     WINNER'S cut, not at its own tip at receipt time (its tip already includes
//     this very carrier). (chain, next_pos, spine_digest) is the ONLY
//     cross-node-comparable cut key (w4_settlement.hpp CutToken :938-939, w6
//     PrefixResolver); CutToken::incarnation and LaneSnapshot::version are
//     NODE-LOCAL (executor-minted / publication-count) and are deliberately NOT
//     on the wire.
//   * `payout_emitted` — the winner's coinbase outputs are NOT on the wire (they
//     are an unbounded map). A FRESH win is at depth 0, so the W5 burial gate
//     withholds and the payout map is EMPTY on BOTH sides by construction; this
//     flag lets the receiver REFUSE fail-closed in the one shape it could not
//     reproduce (a winner that registered an already-buried block).
//   * `owed_digest_at_win` — diagnostics only: the winner's owed_digest at the
//     instant of the win. A receiver whose own digest differs at that moment has
//     ALREADY diverged upstream; logging it names the divergence at the first
//     block instead of at the audit.
// A peak / MMR leaf is deliberately NOT on this wire: a receiver must APPEND the
// identical leaf itself, never insert a peer's peak. The owed-event MMR is a
// separate, un-nodded track; v0x02 converges the EXISTING flat owed_digest.
//
// ── the v36 transport this layer REUSES (cite, never reinvent) ──────────────
// W3 adds ZERO new transport. A carrier is an extended share body, not a new
// message type; it rides the existing shares/sharereq/sharereply verbs and the
// existing broadcast path. In production ICarrierTransport is bound to the v36
// seams (verified present in this tree on 2026-09-04):
//   * SEND choke point : pool::Peer::write(std::unique_ptr<RawMessage>)
//                        (src/pool/peer.hpp:55 — every outbound pool message in
//                         every coin lane; bumps core::obs::p2p_stats()).
//   * forward loop     : NodeImpl::broadcast_share / post_broadcast_share
//                        (src/impl/ltc/node.cpp:969 / :942 — the proven ltc
//                         reference; walks un-broadcast shares, sends to each
//                         peer in m_peers, then commit_broadcast_marks marks
//                         ONLY what reached >=1 peer).
//   * RECEIVE choke    : pool::NodeBridge::handle (src/pool/node.hpp) ->
//                        pool::Protocol::handle_message (src/pool/protocol.hpp).
//   * sync / catch-up  : pool::download::DownloadGate (src/pool/share_download.hpp).
// CarrierRelay drives those through the ICarrierTransport seam so the relay
// logic (decode / bind-check / dedup / bloat / unconditional-append) is unit-
// testable stdlib-only, exactly like the W0/W1/W2 suites; the loopback-socket
// transport in the KAT is a test binding of the SAME seam.

#include <array>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "w2_admission.hpp"   // ReceiptAdmitter, WorkEvent, W2_R_MAX, ...
#include "w2_receipt.hpp"

namespace c2pool::v37n {

// W3 wire version tags. 0x01 is the W3-B5 FROZEN carrier-wire layout (see the
// byte-map in this file's header and the golden byte-KAT). 0x02 is the S-1c
// bump: the v0x01 body VERBATIM plus the flat cut-descriptor trailer. A wire
// change is always a visible bump of this tag, never a silent re-pack.
constexpr std::uint8_t W3_WIRE_VERSION_V1 = 0x01;   // frozen; bytes never move
constexpr std::uint8_t W3_WIRE_VERSION_V2 = 0x02;   // frozen; v1 body + cut trailer
constexpr std::uint8_t W3_WIRE_VERSION_V3 = 0x03;   // frozen; v2 frame + DROPS trailer

// The version this build EMITS. Decode multi-accepts {V1, V2, V3} for the
// upgrade window (F-5); an older peer rejects a newer frame outright at decode —
// the flag day is LOUD, never a silently half-relayed descriptor.
constexpr std::uint8_t W3_WIRE_VERSION = W3_WIRE_VERSION_V3;

// ★★ DROPS-R3: the bound on the composed credit map a winner may carry. The map
// is the ONE part of a DROPS settlement a receiver cannot recompute (a raindrop
// is a node-local observation the peer never saw), so it has to ride the wire —
// and anything that rides an un-PoW'd frame needs a ceiling. 4096 payees at 40
// bytes each is 160 KiB, comfortably inside the 1 MiB transport frame and far
// above any plausible payee count at one cut. A frame claiming more is rejected
// whole; it is never truncated (a truncated credit map is a silent fork).
constexpr std::uint16_t W3_DROPS_MAX_ENTRIES = 4096;

// R_MAX is the W2-layer consensus bound (share-format §7); W3 enforces it at
// DECODE, before any push (spec §2.3 / WT-1). Named through W2 so there is one
// definition, never a second copy that could drift.
constexpr std::uint32_t W3_R_MAX = W2_R_MAX;

// ── S-1c: the flat cut descriptor a BLOCK-WINNING carrier carries (v0x02) ───
// Everything a peer needs to credit its OWN OwedLedger with the SAME E_b the
// winner credited, and nothing else. Consensus-relevant fields: bid, h_b,
// cut_next_pos, cut_spine_digest, reward (they determine the credit and the
// finalize bin). Diagnostic: owed_digest_at_win. Fail-closed: payout_emitted.
// NEVER on this wire: incarnation / lane version (node-local), the payout map
// (unbounded), any MMR peak (a receiver appends its own leaf, never a peak).
struct CutDescriptor {
    bytes32       bid{};                  // hex(bid) IS the OwedLedger key
    std::uint64_t h_b = 0;                // the block's OWN height (D8)
    std::uint64_t cut_next_pos = 0;       // P — the prefix the winner folded at
    bytes32       cut_spine_digest{};     // LaneSnapshot::digest at P
    std::uint64_t reward = 0;             // the winner's block_reward(H_b)
    bool          payout_emitted = false; // winner's W5 assembly emitted outputs
    bytes32       owed_digest_at_win{};   // VERIFY field (diagnostics, never consensus)
    bool operator==(const CutDescriptor&) const = default;
};

// bid as the ledger key: a pure lowercase-hex codec over the 32 raw bytes, so
// string -> bytes -> string is EXACT and carries no endianness question (the
// daemon's bid is uint256::GetHex(), 64 hex chars, and that string — not any
// re-ordered form of it — is what OwedLedger keys on).
inline std::string cut_bid_hex(const bytes32& b) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (std::uint8_t x : b) { s.push_back(kHex[x >> 4]); s.push_back(kHex[x & 0x0f]); }
    return s;
}
// nullopt unless `hex` is exactly 64 lowercase/uppercase hex chars.
inline std::optional<bytes32> cut_bid_bytes(const std::string& hex) {
    if (hex.size() != 64) return std::nullopt;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    bytes32 b{};
    for (int i = 0; i < 32; ++i) {
        const int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        b[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return b;
}

// ── ★★ DROPS-R3 (wire v0x03): the winner's COMPOSED DROPS CREDIT MAP ───────
//
// THE DEFECT IT CLOSES. The S-1c peer path re-folds E_b locally at the winner's
// cut — correct, because E_b is a pure function of (reward, payout, identities)
// and the peer holds all three. It then ADDED ITS OWN buried harvest. But a
// raindrop is a below-target work event one node happened to see on its own
// wire: two nodes observe DIFFERENT raindrop sets by construction. So the
// moment harvesters are attached, two nodes credit DIFFERENT numbers for the
// SAME peer win and their owed_digests part at the first block. Recompute is
// not available here the way it is for a canonical coinbase: the peer never saw
// the evidence.
//
// THE RULING (R3). The WINNER'S VIEW IS AUTHORITATIVE. The winner composes its
// DROPS delta once, credits it to its own ledger, and puts that same map on the
// wire; the peer folds the RECEIVED map and its own local harvest plays no part
// in a peer win at all. The map is a DELTA, signed, in the SAME coin
// denomination as E_b (DROPS-R1), keyed by canonical identity.
//
// `enrollment_digest` is the witness for R-SYBIL: the winner's ex-ante enrolment
// book digest at the cut. It is diagnostic — a receiver cannot verify an
// enrolment it was never told about — but it makes a divergent enrolment set
// VISIBLE at the earliest moment instead of inferable from a bad number later.
struct DropsCredit {
    // (payee, composed delta). STRICTLY ASCENDING by payee on the wire, so the
    // encoding of a given map is unique and a duplicate key is a decode reject
    // rather than an ambiguous fold.
    std::vector<std::pair<bytes32, long long>> credit;
    bytes32 enrollment_digest{};      // winner's EnrollmentBook::book_digest()
    bool operator==(const DropsCredit&) const = default;
};

// ── a carrier = ordinary share + 0..R_MAX receipts (spec §2.1) ──────────────
struct Carrier {
    WorkEvent carrier;                 // the ordinary V37 share (advances clock)
    std::vector<WorkEvent> receipts;   // ref-protected payload, order-free
    // S-1c (wire v0x02): set iff this carrier is ALSO a coin block winner. A
    // v0x01 frame decodes to nullopt; a v0x02 frame with won_block == 0 also
    // decodes to nullopt — the two are indistinguishable to every consumer
    // above the codec, which is exactly the upgrade-window property we want.
    std::optional<CutDescriptor> cut;
    // DROPS-R3 (wire v0x03): the winner's composed DROPS credit map. Only ever
    // set together with `cut` (a credit map without a cut names no settlement;
    // decode rejects that shape). A v0x01/v0x02 frame decodes to nullopt, and so
    // does a v0x03 frame with drops_present == 0 — again indistinguishable above
    // the codec, so a DROPS-dormant fleet on the v0x03 wire pays exactly one
    // extra byte per frame and changes nothing else.
    std::optional<DropsCredit> drops;
};

// ── decode dispositions ─────────────────────────────────────────────────────
enum class WireStatus {
    OK,
    REJECT_TRUNCATED,          // ran off the end of the buffer (malformed)
    REJECT_BAD_VERSION,        // unknown wire version tag
    REJECT_RMAX,              // > R_MAX receipts: whole carrier rejected (§2.3)
    REJECT_CARRIER_UNBOUND,   // W3-MUST: carrier identity != descriptor key
    REJECT_POLICY,            // W3-B5 frozen-wire policy (w3_wire_freeze.hpp):
                              // tag cap (F-1) / V37.0 descriptor validity (F-2)
                              // on the CARRIER; applied post-decode, pre-admit
    REJECT_BAD_CUT,           // S-1c v0x02: won_block byte outside {0,1}, or the
                              // payout_emitted byte outside {0,1} — a malformed
                              // trailer is NEVER admitted (it would otherwise
                              // credit a peer's ledger off a guessed cut)
    REJECT_BAD_DROPS,         // DROPS-R3 v0x03: present byte outside {0,1}, an
                              // entry count above W3_DROPS_MAX_ENTRIES, payees
                              // not strictly ascending (duplicate or unordered),
                              // or a credit map carried with NO cut descriptor.
                              // Same rule as the cut: reject the frame whole,
                              // never fold a partially-read credit map
};

// Why a single receipt was dropped at decode (carrier still stands, §2.4/WT-2).
enum class ReceiptWireDrop {
    MISBOUND_IDENTITY,        // W3-MUST: receipt identity != descriptor key
};

struct DecodeResult {
    WireStatus status = WireStatus::OK;
    Carrier carrier;                                    // valid iff status==OK
    // receipts rejected at DECODE (not admission) with the reason. The carrier
    // and the surviving receipts stand; a mis-bound receipt never rides on.
    std::vector<std::pair<std::string, ReceiptWireDrop>> dropped;
    bool ok() const { return status == WireStatus::OK; }
};

// ═══════════════════════════════════════════════════════════════════════════
// Wire codec (spec §2; share-format §1/§3) — FROZEN wire v0x01 (W3-B5; byte-map
// in this file's header, constants/size-model/goldens in w3_wire_freeze.hpp).
// Little-endian fixed-width fields, simple length prefixes, no varints. The
// carrier's receipts ride the ref_hash-committed region conceptually; here they
// are serialized in-body so a downloaded carrier carries its receipts with it
// (spec §3.3 — receipts add nothing to the sync protocol).
// ═══════════════════════════════════════════════════════════════════════════
class CarrierWire {
public:
    // Emit at the build's CURRENT wire version (W3_WIRE_VERSION).
    static std::vector<std::uint8_t> encode(const Carrier& c) {
        return encode_version(c, W3_WIRE_VERSION);
    }

    // Emit at an EXPLICIT version. This is the seam the byte freeze pins: the
    // v0x01 goldens are re-run through encode_version(c, 0x01) and must stay
    // byte-identical forever, while encode_version(c, 0x02) appends the S-1c
    // trailer to the SAME v0x01 body. An unknown version, or a v0x01 request
    // for a carrier that HAS a cut descriptor (v0x01 cannot express one — a
    // silent drop would lose a peer's block credit), returns an EMPTY vector.
    static std::vector<std::uint8_t> encode_version(const Carrier& c, std::uint8_t ver) {
        std::vector<std::uint8_t> b;
        if (ver != W3_WIRE_VERSION_V1 && ver != W3_WIRE_VERSION_V2 &&
            ver != W3_WIRE_VERSION_V3) return b;
        if (ver == W3_WIRE_VERSION_V1 && c.cut.has_value()) return b;
        // A version below v0x03 cannot express a DROPS credit map. Silently
        // dropping it would relay a block-winner descriptor whose settlement the
        // receiver would then compose from ITS OWN harvest — the exact
        // divergence R3 removes — so the encoder refuses instead.
        if (ver != W3_WIRE_VERSION_V3 && c.drops.has_value()) return b;
        // A credit map with no cut names no settlement; refuse to encode it.
        if (c.drops.has_value() && !c.cut.has_value()) return b;
        if (c.drops.has_value() &&
            c.drops->credit.size() > static_cast<std::size_t>(W3_DROPS_MAX_ENTRIES))
            return b;
        b.push_back(ver);
        put_event(b, c.carrier);
        // receipt_count is a single byte; R_MAX=4 fits trivially. Encoders never
        // emit > R_MAX (the emitter is bounded); a decoder that SEES > R_MAX
        // rejects the whole carrier (§2.3, WT-1).
        b.push_back(static_cast<std::uint8_t>(c.receipts.size()));
        for (const WorkEvent& r : c.receipts) put_event(b, r);
        if (ver == W3_WIRE_VERSION_V2 || ver == W3_WIRE_VERSION_V3) put_cutdesc(b, c.cut);
        if (ver == W3_WIRE_VERSION_V3) put_drops(b, c.drops);
        return b;
    }

    // Decode + enforce the two decode-time consensus/anti-forgery rules:
    //   (1) R_MAX: a carrier presenting > R_MAX receipts is malformed => the
    //       WHOLE carrier is rejected (never truncate-and-accept; truncation
    //       would make the digest ambiguous — spec §2.3).
    //   (2) W3-MUST identity binding (the W2->W3 seam obligation, spec close):
    //       preimage.identity == descriptor.identity_key() on EVERY event.
    //       * carrier mis-bound  => whole-carrier reject (credit-misdirection
    //         on the carrier itself is fatal);
    //       * receipt mis-bound  => that receipt dropped, carrier STANDS
    //         (a mis-bound receipt is never a fork tool, and is never relayed on).
    static DecodeResult decode(const std::vector<std::uint8_t>& b) {
        DecodeResult out;
        std::size_t p = 0;
        std::uint8_t ver = 0;
        if (!get_u8(b, p, ver)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }
        // F-5 multi-accept for the upgrade window: {0x01, 0x02, 0x03}.
        if (ver != W3_WIRE_VERSION_V1 && ver != W3_WIRE_VERSION_V2 &&
            ver != W3_WIRE_VERSION_V3) {
            out.status = WireStatus::REJECT_BAD_VERSION;
            return out;
        }

        WorkEvent carrier;
        if (!get_event(b, p, carrier)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }

        std::uint8_t rc = 0;
        if (!get_u8(b, p, rc)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }
        if (rc > W3_R_MAX) { out.status = WireStatus::REJECT_RMAX; return out; }  // (1)

        std::vector<WorkEvent> receipts;
        receipts.reserve(rc);
        for (std::uint8_t i = 0; i < rc; ++i) {
            WorkEvent r;
            if (!get_event(b, p, r)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }
            receipts.push_back(std::move(r));
        }
        // (1b) S-1c v0x02 trailer. A malformed trailer is a HARD reject: the
        // whole point of the descriptor is that a receiver credits its ledger at
        // the winner's cut, so a frame whose cut cannot be read is never admitted
        // (never "admit the share and drop the cut" — that is the divergence).
        std::optional<CutDescriptor> cut;
        if (ver == W3_WIRE_VERSION_V2 || ver == W3_WIRE_VERSION_V3) {
            const WireStatus cs = get_cutdesc(b, p, cut);
            if (cs != WireStatus::OK) { out.status = cs; return out; }
        }
        // (1c) DROPS-R3 v0x03 trailer. Same hard-reject rule as the cut: the
        // whole point of the map is that a receiver credits its ledger with the
        // WINNER'S composed delta, so a frame whose map cannot be read is never
        // admitted, and a map with no cut to attach to is malformed.
        std::optional<DropsCredit> drops;
        if (ver == W3_WIRE_VERSION_V3) {
            const WireStatus ds = get_drops(b, p, drops);
            if (ds != WireStatus::OK) { out.status = ds; return out; }
            if (drops.has_value() && !cut.has_value()) {
                out.status = WireStatus::REJECT_BAD_DROPS;
                return out;
            }
        }
        // Trailing bytes are a malformed frame (we consumed a fixed structure).
        if (p != b.size()) { out.status = WireStatus::REJECT_TRUNCATED; return out; }

        // (2a) carrier identity binding — fatal.
        if (!identity_bound(carrier)) {
            out.status = WireStatus::REJECT_CARRIER_UNBOUND;
            return out;
        }
        // (2b) per-receipt identity binding — drop the offender, carrier stands.
        out.carrier.carrier = std::move(carrier);
        out.carrier.cut = std::move(cut);
        out.carrier.drops = std::move(drops);
        for (WorkEvent& r : receipts) {
            if (!identity_bound(r)) {
                out.dropped.emplace_back(r.tag, ReceiptWireDrop::MISBOUND_IDENTITY);
                continue;   // NOT carried on — forgery is not amplified
            }
            out.carrier.receipts.push_back(std::move(r));
        }
        out.status = WireStatus::OK;
        return out;
    }

    // The W3-MUST predicate, isolated so the KAT can assert it directly.
    // W2 binds the PoW to `identity` but credits under `descriptor`; in the
    // synthetic model these are decoupled fields and W2 does NOT check their
    // correspondence (deferred, SF-OQ1/OQ4). W3 closes the seam here.
    static bool identity_bound(const WorkEvent& e) {
        return e.identity == e.descriptor.identity_key();
    }

private:
    static void put_u8(std::vector<std::uint8_t>& b, std::uint8_t v) { b.push_back(v); }
    static void put_u16(std::vector<std::uint8_t>& b, std::uint16_t v) {
        for (int i = 0; i < 2; ++i) b.push_back((std::uint8_t)(v >> (8 * i)));
    }
    static void put_u32(std::vector<std::uint8_t>& b, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) b.push_back((std::uint8_t)(v >> (8 * i)));
    }
    static void put_u64(std::vector<std::uint8_t>& b, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) b.push_back((std::uint8_t)(v >> (8 * i)));
    }
    static void put_bytes32(std::vector<std::uint8_t>& b, const bytes32& h) {
        b.insert(b.end(), h.begin(), h.end());
    }
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
    static void put_event(std::vector<std::uint8_t>& b, const WorkEvent& e) {
        put_u32(b, e.chain_id);
        put_bytes32(b, e.identity);
        put_bytes32(b, e.prev_block_hash);
        put_bytes32(b, e.prev_own_share);
        put_u32(b, e.lz_bits);
        put_u64(b, e.nonce);
        put_desc(b, e.descriptor);
        put_str(b, e.tag);   // local bookkeeping (NOT in preimage); carried so a
                             // round-trip is exact, never covered by PoW/consensus.
    }

    // ── S-1c v0x02 trailer codec ────────────────────────────────────────────
    static void put_cutdesc(std::vector<std::uint8_t>& b,
                            const std::optional<CutDescriptor>& c) {
        if (!c) { put_u8(b, 0); return; }           // won_block = 0: ONE byte
        put_u8(b, 1);
        put_bytes32(b, c->bid);
        put_u64(b, c->h_b);
        put_u64(b, c->cut_next_pos);
        put_bytes32(b, c->cut_spine_digest);
        put_u64(b, c->reward);
        put_u8(b, c->payout_emitted ? 1 : 0);
        put_bytes32(b, c->owed_digest_at_win);
    }
    // ── DROPS-R3 v0x03 trailer codec ───────────────────────────────────────
    //   u8   present                     (0 => ONE byte and nothing else)
    //   u16  entry_count                 (<= W3_DROPS_MAX_ENTRIES)
    //   entry_count x { bytes32 payee ; u64 credit (two's-complement i64, LE) }
    //   bytes32 enrollment_digest
    static void put_drops(std::vector<std::uint8_t>& b,
                          const std::optional<DropsCredit>& d) {
        if (!d) { put_u8(b, 0); return; }           // absent: ONE byte
        put_u8(b, 1);
        put_u16(b, static_cast<std::uint16_t>(d->credit.size()));
        for (const auto& [payee, amt] : d->credit) {
            put_bytes32(b, payee);
            put_u64(b, static_cast<std::uint64_t>(amt));   // two's complement
        }
        put_bytes32(b, d->enrollment_digest);
    }
    static WireStatus get_drops(const std::vector<std::uint8_t>& b, std::size_t& p,
                                std::optional<DropsCredit>& out) {
        std::uint8_t present = 0;
        if (!get_u8(b, p, present)) return WireStatus::REJECT_TRUNCATED;
        if (present == 0) { out.reset(); return WireStatus::OK; }
        if (present != 1) return WireStatus::REJECT_BAD_DROPS;   // not a boolean
        std::uint16_t n = 0;
        if (!get_u16(b, p, n)) return WireStatus::REJECT_TRUNCATED;
        if (n > W3_DROPS_MAX_ENTRIES) return WireStatus::REJECT_BAD_DROPS;
        DropsCredit d;
        d.credit.reserve(n);
        bytes32 prev{};
        for (std::uint16_t i = 0; i < n; ++i) {
            bytes32 payee{};
            std::uint64_t bits = 0;
            if (!get_bytes32(b, p, payee)) return WireStatus::REJECT_TRUNCATED;
            if (!get_u64(b, p, bits))      return WireStatus::REJECT_TRUNCATED;
            // STRICTLY ascending: a duplicate or unordered key would make the
            // fold depend on decode order, which is a fork surface, not a taste.
            if (i > 0 && !(prev < payee)) return WireStatus::REJECT_BAD_DROPS;
            prev = payee;
            d.credit.emplace_back(payee, static_cast<long long>(bits));
        }
        if (!get_bytes32(b, p, d.enrollment_digest)) return WireStatus::REJECT_TRUNCATED;
        out = std::move(d);
        return WireStatus::OK;
    }

    static WireStatus get_cutdesc(const std::vector<std::uint8_t>& b, std::size_t& p,
                                  std::optional<CutDescriptor>& out) {
        std::uint8_t won = 0;
        if (!get_u8(b, p, won)) return WireStatus::REJECT_TRUNCATED;
        if (won == 0) { out.reset(); return WireStatus::OK; }
        if (won != 1) return WireStatus::REJECT_BAD_CUT;   // not a boolean
        CutDescriptor c;
        std::uint8_t pe = 0;
        if (!get_bytes32(b, p, c.bid))              return WireStatus::REJECT_TRUNCATED;
        if (!get_u64(b, p, c.h_b))                  return WireStatus::REJECT_TRUNCATED;
        if (!get_u64(b, p, c.cut_next_pos))         return WireStatus::REJECT_TRUNCATED;
        if (!get_bytes32(b, p, c.cut_spine_digest)) return WireStatus::REJECT_TRUNCATED;
        if (!get_u64(b, p, c.reward))               return WireStatus::REJECT_TRUNCATED;
        if (!get_u8(b, p, pe))                      return WireStatus::REJECT_TRUNCATED;
        if (pe > 1) return WireStatus::REJECT_BAD_CUT;     // not a boolean
        if (!get_bytes32(b, p, c.owed_digest_at_win)) return WireStatus::REJECT_TRUNCATED;
        c.payout_emitted = (pe == 1);
        out = c;
        return WireStatus::OK;
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
    static bool get_u64(const std::vector<std::uint8_t>& b, std::size_t& p, std::uint64_t& v) {
        if (p + 8 > b.size()) return false;
        v = 0; for (int i = 0; i < 8; ++i) v |= (std::uint64_t)b[p++] << (8 * i);
        return true;
    }
    static bool get_bytes32(const std::vector<std::uint8_t>& b, std::size_t& p, bytes32& h) {
        if (p + 32 > b.size()) return false;
        for (int i = 0; i < 32; ++i) h[i] = b[p++];
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
    static bool get_event(const std::vector<std::uint8_t>& b, std::size_t& p, WorkEvent& e) {
        if (!get_u32(b, p, e.chain_id)) return false;
        if (!get_bytes32(b, p, e.identity)) return false;
        if (!get_bytes32(b, p, e.prev_block_hash)) return false;
        if (!get_bytes32(b, p, e.prev_own_share)) return false;
        if (!get_u32(b, p, e.lz_bits)) return false;
        if (!get_u64(b, p, e.nonce)) return false;
        if (!get_desc(b, p, e.descriptor)) return false;
        if (!get_str(b, p, e.tag)) return false;
        return true;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Relay dedup set (spec §5.2, right column) — NETWORK HYGIENE ONLY.
// Keyed on the carrier's own header hash. This set is NEVER consensus, NEVER a
// digest leaf, and MUST NOT gate the W2 consensus append (rule §5.2.1:
// relay-seen != chain-have). It is physically separate from the W2 DedupWindow
// (rule §5.2.4: they must not share a prune trigger) and starts empty on a W6
// rebuild (rule §5.2.3). Pruning here follows v36 policy (peer lifetime / cycle
// reset) — modeled as a caller-driven clear(); it has no consensus effect.
// ═══════════════════════════════════════════════════════════════════════════
class RelaySeenSet {
public:
    // Returns true if this carrier hash was NOT seen before (i.e. relay it).
    bool mark_and_test(const bytes32& carrier_hash) {
        return m_seen.insert(carrier_hash).second;
    }
    bool seen(const bytes32& carrier_hash) const {
        return m_seen.count(carrier_hash) != 0;
    }
    void clear() { m_seen.clear(); }        // v36-policy prune (no consensus effect)
    std::size_t size() const { return m_seen.size(); }
private:
    std::set<bytes32> m_seen;
};

// ═══════════════════════════════════════════════════════════════════════════
// Carrier-bloat measurement hook (spec §8.4; feeds testnet BM-2).
// OBSERVE-ONLY, OFF BY DEFAULT — modeled on the v36 opt-in p2p observe surface
// (core::obs::p2p_stats(), the relaxed fetch_add counters in
// src/pool/peer.hpp / src/pool/node.hpp). NEVER in any digest, NEVER on the
// consensus path (it is the magnifying glass, not the mechanism). Provisional
// simnet readings only; real numbers are Phase-B BM-2.
// ═══════════════════════════════════════════════════════════════════════════
struct CarrierBloatStats {
    bool enabled = false;

    std::uint64_t carriers_accepted = 0;
    std::array<std::uint64_t, W3_R_MAX + 1> receipt_count_hist{};  // [0..R_MAX]
    std::uint64_t carrier_body_bytes = 0;       // Σ whole-carrier wire bytes
    std::uint64_t receipt_payload_bytes = 0;    // Σ receipt-only wire bytes
    std::uint64_t wire_bytes_sent = 0;          // Σ over the per-peer send loop
    std::uint64_t relay_received = 0;
    std::uint64_t relay_dedup_hits = 0;         // echoes suppressed
    std::uint64_t download_fanin = 0;           // DownloadGate in-flight/retry

    void observe_accepted(const std::vector<std::uint8_t>& whole_frame,
                          const Carrier& c) {
        if (!enabled) return;
        ++carriers_accepted;
        std::size_t n = c.receipts.size();
        if (n <= W3_R_MAX) ++receipt_count_hist[n];
        carrier_body_bytes += whole_frame.size();
        // receipt-only bytes = whole frame - (version + carrier + count [+ the
        // S-1c v0x02 trailer]) prefix. The bare frame carries the SAME cut so
        // the subtraction isolates the receipts and never charges a block
        // winner's 122-byte descriptor to receipt bloat.
        Carrier bare; bare.carrier = c.carrier; bare.cut = c.cut;
        receipt_payload_bytes +=
            whole_frame.size() - CarrierWire::encode(bare).size();
    }
    void observe_sent(std::size_t bytes, std::size_t n_peers) {
        if (!enabled) return;
        wire_bytes_sent += (std::uint64_t)bytes * n_peers;   // flood amplification
    }
    void observe_received(bool was_dedup_hit) {
        if (!enabled) return;
        ++relay_received;
        if (was_dedup_hit) ++relay_dedup_hits;
    }

    // The BM-2 ratios (guarded against divide-by-zero).
    double bytes_per_carrier() const {
        return carriers_accepted ? (double)carrier_body_bytes / carriers_accepted : 0.0;
    }
    double bytes_per_receipt() const {
        std::uint64_t rc = 0;
        for (std::size_t k = 0; k <= W3_R_MAX; ++k) rc += k * receipt_count_hist[k];
        return rc ? (double)receipt_payload_bytes / rc : 0.0;
    }
    double bloat_ratio() const {   // receipt payload / total carrier bytes
        return carrier_body_bytes ? (double)receipt_payload_bytes / carrier_body_bytes : 0.0;
    }
    double dedup_hit_rate() const {
        return relay_received ? (double)relay_dedup_hits / relay_received : 0.0;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// The transport seam (spec §1.3 / §3) — REUSE, not reinvent.
// Production impl: forward to pool::Peer::write over the m_peers set, driven by
// NodeImpl::broadcast_share (marking only what reached >=1 peer via
// commit_broadcast_marks). The KAT impl is a loopback-socket binding of the
// SAME seam. n_peers() lets the bloat hook account flood amplification.
// ═══════════════════════════════════════════════════════════════════════════
struct ICarrierTransport {
    virtual ~ICarrierTransport() = default;
    // Flood the frame to every peer. Returns the number of peers it reached
    // (>=1 means the v36 layer would commit_broadcast_marks; 0 means DEFER —
    // the share stays in-chain and un-marked, retried later, NEVER dropped).
    virtual std::size_t broadcast(const std::vector<std::uint8_t>& frame) = 0;
    virtual std::size_t n_peers() const = 0;
};

// ═══════════════════════════════════════════════════════════════════════════
// CarrierRelay — the flood-fill + admission-routing orchestrator.
//
// The append is ALWAYS via the W2 admission callback (into the W0 V37Engine
// seam). This class holds NO lane reference and calls NO executor method — it
// only routes decoded carriers into W2 and decides relay (§1.2, O1).
//
// Two dedup mechanisms are kept strictly separate (§5.2): the W2 DedupWindow
// (consensus, inside the admit callback) and this class's RelaySeenSet (network
// hygiene). Relay-seen NEVER gates the consensus append — that is the whole
// point of the block-winning guarantee (§4).
// ═══════════════════════════════════════════════════════════════════════════
class CarrierRelay {
public:
    // The admission callback wraps a W2 ReceiptAdmitter + the V37Engine sink.
    // It returns the admission Result so the relay can report credit outcomes.
    using AdmitFn = std::function<
        ReceiptAdmitter::Result(const WorkEvent& carrier,
                                const std::vector<WorkEvent>& receipts)>;

    CarrierRelay(AdmitFn admit, ICarrierTransport& transport)
        : m_admit(std::move(admit)), m_transport(transport) {}

    // W3-B5 frozen-wire POLICY hook (F-1 tag cap, F-2 descriptor validity),
    // run on an INBOUND frame after decode and before admission. false =>
    // the frame is rejected as WireStatus::REJECT_POLICY (never admitted,
    // never relayed); true => proceed with the carrier as (possibly) cleaned
    // by the hook (a policy-dropped receipt is stripped exactly like a
    // mis-bound one). Bind wire_freeze::make_relay_policy(); unset => no-op,
    // so every existing KAT keeps its behavior. Never consensus.
    using FramePolicyFn = std::function<bool(Carrier&)>;
    void set_frame_policy(FramePolicyFn f) { m_policy = std::move(f); }

    // THREADING (Track A2 step (b)): the three public handlers below are
    // serialized under m_mtx. CarrierPeerNode runs ONE READER THREAD PER PEER
    // into handle_inbound (carrier_net.hpp reader_loop), and the send-side
    // worker (carrier_send.hpp) drives handle_local / append_block_winner from
    // its own thread — without this lock RelaySeenSet (a bare std::set) and
    // CarrierBloatStats race with >= 2 peers. Lock order (never reversed):
    //   relay m_mtx -> CarrierIngest::m_mtx -> engine mailbox
    //   relay m_mtx -> CarrierPeerNode::m_write_mtx (inside do_broadcast)
    //   CarrierSendQueue::m_emit_mtx -> relay m_mtx
    // stats()/seen() are unlocked accessors for single-threaded KAT reads.
    CarrierBloatStats& stats() { return m_stats; }
    RelaySeenSet& seen() { return m_seen; }

    struct Outcome {
        WireStatus wire = WireStatus::OK;
        ReceiptAdmitter::Result admission;   // valid iff wire==OK
        bool admitted = false;               // a fresh consensus append happened
        bool relayed = false;                // re-broadcast onward
        std::size_t peers_reached = 0;
        std::vector<std::pair<std::string, ReceiptWireDrop>> wire_dropped;
        // S-1c: the v0x02 cut descriptor this frame carried, surfaced so the
        // daemon's inbound seam can drive its OWN settlement at the winner's cut
        // WITHOUT decoding the frame a second time. Valid iff wire == OK; set
        // only for a BLOCK-WINNING carrier (nullopt for every share and for
        // every v0x01 frame). The relay itself does nothing with it — routing
        // settlement is the daemon's job, not the relay's (§1.2, O1).
        std::optional<CutDescriptor> cut;
        // DROPS-R3: the v0x03 composed credit map the SAME frame carried,
        // surfaced beside the cut for exactly the same reason. Valid iff
        // wire == OK; nullopt for every share, every pre-v0x03 frame, and every
        // winner that had no DROPS to name (which folds as empty and still
        // converges, because that winner credited none either).
        std::optional<DropsCredit> drops;
    };

    // ── inbound (peer -> us), spec §3.2 ─────────────────────────────────────
    // decode (enforce R_MAX + W3-MUST binding) -> W2 admission -> relay onward.
    // The relay-seen set suppresses the ECHO only; a novel carrier still admits.
    Outcome handle_inbound(const std::vector<std::uint8_t>& frame) {
        std::lock_guard<std::mutex> lk(m_mtx);
        Outcome o;
        DecodeResult dr = CarrierWire::decode(frame);
        o.wire = dr.status;
        o.wire_dropped = dr.dropped;
        if (!dr.ok()) return o;                 // malformed / R_MAX / carrier unbound / bad cut
        if (m_policy && !m_policy(dr.carrier)) {   // W3-B5 policy (tag cap / desc validity)
            o.wire = WireStatus::REJECT_POLICY;
            return o;
        }
        o.cut = dr.carrier.cut;                 // S-1c: surfaced for the daemon's settlement seam
        o.drops = dr.carrier.drops;             // DROPS-R3: the winner's composed credit map

        bool novel_to_relay = !m_seen.seen(dr.carrier.carrier.hash());
        m_stats.observe_received(!novel_to_relay);

        // Consensus append is INDEPENDENT of relay-seen (§5.2.1). Admit always;
        // W2's own window is the authority on credit-once.
        o.admission = m_admit(dr.carrier.carrier, dr.carrier.receipts);
        o.admitted = (o.admission.carrier_status == CarrierStatus::OK);
        if (o.admitted) m_stats.observe_accepted(re_encode(dr.carrier), dr.carrier);

        // Relay onward only if novel to the relay layer (flood-fill dedup, §5.2).
        // We re-encode the CLEANED carrier so a mis-bound receipt dropped at
        // decode is never amplified onto the network.
        if (novel_to_relay && o.admitted) {
            m_seen.mark_and_test(dr.carrier.carrier.hash());
            o.peers_reached = do_broadcast(dr.carrier);
            o.relayed = o.peers_reached > 0;
        }
        return o;
    }

    // ── local carrier (mined, or newly accepted), spec §3.1 ─────────────────
    // Ordinary local flow: admit, then relay (marking only what reached a peer).
    Outcome handle_local(const Carrier& c) {
        std::lock_guard<std::mutex> lk(m_mtx);
        Outcome o;
        o.wire = WireStatus::OK;
        o.cut = c.cut;
        o.drops = c.drops;
        o.admission = m_admit(c.carrier, c.receipts);
        o.admitted = (o.admission.carrier_status == CarrierStatus::OK);
        if (o.admitted) m_stats.observe_accepted(re_encode(c), c);
        if (o.admitted && m_seen.mark_and_test(c.carrier.hash())) {
            o.peers_reached = do_broadcast(c);
            o.relayed = o.peers_reached > 0;
        }
        return o;
    }

    // ── the block-winning-carrier guarantee (spec §4, W3-G1) ────────────────
    // A carrier that is ALSO a valid mainchain block solution MUST be appended
    // and credited UNCONDITIONALLY — never gated by:
    //   (1) relay dedup — we do NOT consult m_seen before appending;
    //   (2) admission backpressure / rate-limit — there is no shed path here;
    //   (3) a busy submit path — the admit callback funnels into the V37Engine
    //       MPSC mailbox (a lock-free-ish enqueue, NOT a try_to_lock that can
    //       defer forever — the v36 stratum-freeze bug, spec §3.4);
    // Append is unconditional; RELAY may still legitimately defer (0 peers) and
    // retry — the credit is NEVER conditional on the relay succeeding (§4 close,
    // the #889/#903 defect: a block-winning share silently dropped => PPLNS loss).
    Outcome append_block_winner(const Carrier& c) {
        std::lock_guard<std::mutex> lk(m_mtx);
        Outcome o;
        o.wire = WireStatus::OK;
        o.cut = c.cut;
        o.drops = c.drops;
        // Unconditional append: no m_seen check, no backpressure gate.
        o.admission = m_admit(c.carrier, c.receipts);
        o.admitted = (o.admission.carrier_status == CarrierStatus::OK);
        if (o.admitted) m_stats.observe_accepted(re_encode(c), c);
        // Relay is best-effort and may defer; append already stands.
        m_seen.mark_and_test(c.carrier.hash());
        o.peers_reached = do_broadcast(c);
        o.relayed = o.peers_reached > 0;
        return o;
    }

private:
    std::vector<std::uint8_t> re_encode(const Carrier& c) const {
        return CarrierWire::encode(c);
    }
    std::size_t do_broadcast(const Carrier& c) {
        std::vector<std::uint8_t> frame = CarrierWire::encode(c);
        std::size_t np = m_transport.n_peers();
        std::size_t reached = m_transport.broadcast(frame);
        m_stats.observe_sent(frame.size(), reached ? reached : np);
        return reached;
    }

    AdmitFn m_admit;
    ICarrierTransport& m_transport;
    FramePolicyFn m_policy;      // unset => no policy gate (KAT default)
    mutable std::mutex m_mtx;    // serializes the three public handlers (see THREADING)
    RelaySeenSet m_seen;
    CarrierBloatStats m_stats;
};

} // namespace c2pool::v37n
