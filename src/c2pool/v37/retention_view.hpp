#pragma once
// V37 — RECORD/MESSAGE RETENTION TIERS: the ruled 2+1 model, VIEW-LAYER.
// CONSUMER-tree code (src/c2pool/v37/). Stdlib-only, header-only, like its
// siblings. It reads the PURE ladder functions out of the consensus module and
// the W2 push stream out of the admission pipeline; it writes to NEITHER.
//
// ═══════════════════════════════════════════════════════════════════════════
// THE WALL — read this before changing anything in here
// ═══════════════════════════════════════════════════════════════════════════
// Retention is NON-CONSENSUS (R-RT4 / OQ-M1). This header:
//   * never edits, calls into, or depends on the mutable state of
//     src/sharechain/v37 — it uses only the PURE, public ladder functions
//     nr::lambda_pow / nr::group_hi / nr::sealed_bin / nr::pow_R /
//     nr::for_version, which are functions of their arguments and nothing else;
//   * never touches a Lane cell, bucket or PeakSet;
//   * never touches owed_digest(), fold_eb, settle_block, the OWED ledger, or
//     the owed-event MMR (owed_event_log.hpp) — whose leaf_count == ledger_seq
//     bijection this feature must not perturb; retention events go to a
//     SEPARATE RecordLog instance with its own "V37R" tag (retention_log.hpp);
//   * never commits its root into the w5 StateCommitment tree or a coinbase —
//     the root is computed and persisted view-layer only;
//   * NEVER rejects a share. Every failure mode below returns an Outcome, and
//     the carrier that carried the request is admitted or refused entirely by
//     W2, exactly as it would have been with this file deleted. This is the
//     miner-messages §3.4 ruling (OQ-M1: ignore, don't reject) applied to
//     retention: an adversarial retention request must never be a fork tool.
//
// ═══════════════════════════════════════════════════════════════════════════
// THE 2+1 MODEL (operator ruling, 2026-09-12)
// ═══════════════════════════════════════════════════════════════════════════
// WINDOW (free)  — the already-ratified renewable TTL of miner-messages §3.3:
//        ttl_bins = clamp( floor(decayed_weight / TTL_WORK_UNIT),
//                          TTL_MIN = R = 8, TTL_MAX = C0 = 4096 )
//        expiry   = round_up_to_lattice(inclusion_bin + ttl_bins)
//   Renewed by RE-INCLUSION in a later share (recomputed at the new carrier
//   bin). REQUIRES, NEVER BURNS: it READS the decayed standing and never debits
//   it — retention is payout-neutral. Expiry is rounded UP to the next
//   R^fold_cap lattice boundary (nr::group_hi) so garbage collection rides the
//   fold rather than cutting across it; the record is actually dropped when
//   nr::sealed_bin(expiry, t_now, H_open) — the same open-horizon predicate the
//   lane folds on. Per-sender cap MSG_LIVE_CAP = 3, oldest deterministically
//   expired (no queue games).
//
// PINNED (paid) — beyond-window retention for a FIXED horizon
//        H_pin = 4096 bins = C0  (inside the ruled TTL_MAX; wall clock: BTC
//        ~28 d, LTC/DASH ~7 d, DOGE ~2.8 d).
//   Expiry is a WALL-CLOCK horizon on the bin clock: the record is pinned while
//   t_now < anchor_bin + H_pin. RENEWABLE: a new payment RESETS anchor_bin to
//   the payment bin. There is NO CHAINING — two payments do not buy 2*H_pin,
//   they buy H_pin from the later payment. (KAT R-P4 pins exactly this.)
//
// HASH (paid)   — a PERMANENT 32-byte leaf. The record BODY IS NOT KEPT: it is
//   dropped at promotion and only its hash survives, forever, as a leaf in the
//   retention RecordLog. This is the tier that makes "permanent" affordable and
//   byte-safe at the same time: permanence costs 32 bytes, not len(body).
//
// ═══════════════════════════════════════════════════════════════════════════
// PRICING — LINEAR RENT, and why it is the byte bound
// ═══════════════════════════════════════════════════════════════════════════
//        price_mwu = c * ceil(bytes / 1024) * H_tier,      c = 2
// paid in A-2 SACRIFICE-SHARE CREDIT (miner-messages §3.3: a sacrifice share is
// a valid PoW share paying the operator/donation descriptor; 1 share = 256 MWU
// of carriage credit). The credit balance IS debited — that is what "paid"
// means and what bounds bytes. The LANE ACCUMULATOR IS NOT: the sacrifice share
// already entered the lane as an ordinary push to the operator descriptor, and
// nothing here writes to the roundabout. "Requires, never burns" is a statement
// about the payout accumulator, and it holds exactly.
//
// WHY NOT THE DECAY-FLOOR PRICE (the rejected model): a price that does not
// scale with SIZE bounds only TIME. A griefer then buys one cheap promotion and
// parks an arbitrarily large body in it — byte amplification with no ceiling.
// Linear rent prices the thing that actually costs a node: BYTE-BINS. The
// resulting invariant, which rent_bound_holds() states and the KAT proves by
// sweep, is
//        retained_bytes(tier, n) * H_tier  *  c   <=   price_mwu(tier, n) * 1024
// i.e. NO tier hands out more than 1024/c = 512 byte-bins per MWU. PINNED sits
// exactly on the bound (it is the rent law); HASH is 32x WORSE per byte-bin
// (32 retained bytes billed as one KiB unit), so "buy the longer tier to get a
// cheaper rate" is not merely unprofitable, it is arithmetically impossible.
// The free WINDOW tier is bounded by QUOTA, not by rent: at most MSG_LIVE_CAP
// live free records per sender, each at most TTL_MAX bins and at most
// RET_MAX_RECORD_BYTES long, and every one of them costs a mined share to
// carry.
//
// ═══════════════════════════════════════════════════════════════════════════
// THE TWO PREREQUISITES (ttl-messaging.md §7 + §11a adversarial review)
// ═══════════════════════════════════════════════════════════════════════════
// TM-OQ1 — EXOGENOUS DIFFICULTY ANCHOR. A volume-based retarget of the
//   retention work unit is BROKEN by withhold-to-depress: withhold shares for
//   an epoch, in-window work collapses, the unit collapses, and
//   clamp(standing/unit, 8, 4096) hands EVERY sender the 4096-bin maximum free
//   retention. So the unit is denominated from the COMMITTED MAINCHAIN
//   DIFFICULTY at a finalized bin (IExogenousDifficultyAnchor) — a number no
//   pool participant can withhold, depress or fabricate — scaled by a FIXED
//   per-channel constant (RETENTION_UNIT_SHIFT) with a global floor
//   (RETENTION_UNIT_FLOOR). Coarse, and deliberately so (§7: "manipulation-
//   resistant but coarse").
//   *** DELIBERATE DEPARTURE FROM OQ-M2's LITERAL WORDING — FLAGGED FOR THE
//   OPERATOR. *** OQ-M2 resolved TTL_WORK_UNIT as "the EMA of share work over
//   the window", which is precisely the pool-internal, withholdable quantity
//   the later TTL review ruled broken. This build keeps the EMA and FLOORS it
//   at the exogenous anchor (UnitMode::AnchorFloored, the default): volume may
//   only RAISE the unit under load, never lower it below the anchor — the
//   synthesis §7 mandates. UnitMode::AnchorOnly drops the EMA entirely.
//   UnitMode::WindowEmaOnly reproduces OQ-M2's literal rule and is retained
//   ONLY as the KAT's negative control, where it is shown to be gameable.
//   If the anchor cannot be read at all, the unit FAILS CLOSED to UINT64_MAX,
//   which yields TTL_MIN — never TTL_MAX.
//
// TM-OQ2 — PER-EPOCH RANDOMNESS. Checking work against the CURRENT target stops
//   PAST precompute; it does not stop FUTURE precompute if the next epoch's
//   target is predictable. So every epoch carries a seed that is unpredictable
//   until the epoch begins:
//        epoch_seed(e) = sha256d( "V37R-EPOCH" || u64 LE e ||
//                                 finalized_hash(epoch_first_bin(e) - 1) )
//   and a sacrifice-share credit is MINTED only if it commits to the seed of
//   the current (or immediately preceding — the §11a boundary-tolerance fix)
//   epoch. Work ground ahead of time commits to a seed that does not exist yet,
//   so it cannot be minted. Credit is PERISHABLE: a lot is spendable for
//   CREDIT_TTL_EPOCHS epochs and then evaporates, closing rentier accumulation
//   and bounding the state.
//   The seed preimage cannot collide with a retention leaf: a leaf payload is
//   "V37R" || u8 kind in {1,2,3} (and is hashed as sha256d(0x00 || payload)),
//   while the seed preimage's fifth byte is '-' (0x2d) and it is hashed with no
//   0x00 prefix.
//   NEITHER prerequisite needs consensus canon: both are READS of mainchain
//   data the node already indexes, consumed by this view. No canon edit, no
//   seam owed.
//
// ═══════════════════════════════════════════════════════════════════════════
// THE CARRIAGE GAP — stated honestly, because it is the one real limitation
// ═══════════════════════════════════════════════════════════════════════════
// The frozen carrier wire (w3_wire_freeze.hpp, v0x01) has NO envelope field.
// Its only free-form field is `tag`, which is NOT in the PoW preimage
// (w2_receipt.hpp) and is therefore RELAY-MALLEABLE — unusable to carry
// anything a third party could grief a victim with. So this change does NOT
// invent a carriage: requests reach the view through the IRetentionFeed
// abstraction, bound to an already-admitted carrier. The production carriage is
// a signed ENVELOPE_MINER TLV in a LATER wire version (miner-messages §3.5
// binds the signature to the carrying share's prev_hash, which closes replay);
// until that wire version exists, the feed is driven by the node's local
// submission path and by the KAT. Everything downstream of the feed — pricing,
// tiers, the log, the GC, the prerequisites — is complete and tested.

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <c2pool/v37/retention_log.hpp>
#include <c2pool/v37/w2_admission.hpp>        // EmittedPush, RecordSink
#include <sharechain/v37/nr_ladder.hpp>       // PURE ladder functions only
#include <sharechain/v37/v37_fixed.hpp>       // u64, u128, FRAC_BITS
#include <sharechain/v37/v37_hash.hpp>        // bytes32, sha256d

namespace c2pool::v37n::retention {

namespace nr = ::v37::nr;
namespace dc = ::v37::decay_canonical;
using ::v37::bytes32;
using ::v37::u128;
using ::v37::u64;

// ═══════════════════════════════════════════════════════════════════════════
// RULED CONSTANTS — every one sourced, none invented
// ═══════════════════════════════════════════════════════════════════════════
inline constexpr u64 TTL_MIN_BINS = nr::ROLLUP;                 // R    = 8   (OQ-M2)
inline constexpr u64 TTL_MAX_BINS = dc::CANON_EPOCH_LEN;        // C0   = 4096(OQ-M2)
inline constexpr u64 H_PIN_BINS   = dc::CANON_EPOCH_LEN;        // C0   = 4096(ruling)
// "Permanent" still needs a finite horizon to be PRICED. The only principled
// finite horizon in this tree is the ladder domain: beyond nr::ladder_domain_
// bins() no work has any standing at all (lambda_pow throws past it), so it is
// the point past which every time-denominated quantity in V37 has ceased to
// exist. Permanence is billed at that horizon: 3 * C0 = 12288 bins.
inline constexpr u64 H_HASH_BINS  = nr::ladder_domain_bins();   // 3*C0 = 12288
inline constexpr u64 MSG_LIVE_CAP = 3;                          // OQ-M2

// Linear rent: c MWU per KiB per bin.
inline constexpr u64 RENT_C_MWU_PER_KIB_BIN = 2;
inline constexpr u64 RENT_KIB_BYTES         = 1024;
// What a HASH promotion actually retains, forever: one MMR leaf.
inline constexpr u64 RET_HASH_LEAF_BYTES    = 32;
// A-2: one sacrifice share buys this much carriage credit (SHARE_MESSAGING_
// DESIGN, cited by miner-messages §3.3).
inline constexpr u64 MWU_PER_SACRIFICE_SHARE = 256;

// TM-OQ1: the FIXED per-channel scale from mainchain block work down to a
// retention work unit, and the global floor. Both are protocol constants, not
// observations — that is the whole point (nothing a participant emits moves
// them).
inline constexpr unsigned RETENTION_UNIT_SHIFT = 20;
inline constexpr u64      RETENTION_UNIT_FLOOR = 1;

// TM-OQ2: credit perishability, in epochs.
inline constexpr u64 CREDIT_TTL_EPOCHS = 2;

// Anti-DoS bounds on the view itself (view-layer, never consensus).
inline constexpr std::uint32_t RET_MAX_RECORD_BYTES   = 65536;   // 64 KiB
inline constexpr std::size_t   RET_REQS_PER_CARRIER   = 4;       // mirrors W2_R_MAX
inline constexpr std::size_t   RET_MAX_STANDING_LOTS  = 4096;    // per identity
// A hard ceiling on FREE records held by this view, across all senders. The
// per-sender MSG_LIVE_CAP bounds one identity; identities are sybil-able (each
// still costs a mined share), so a view-level bound is still owed. Paid tiers
// are exempt: their bytes are already bounded by rent.
inline constexpr std::size_t   RET_MAX_FREE_RECORDS   = 4096;
// Schema version of the persisted promotion journal (view-layer only).
inline constexpr std::uint8_t  RETENTION_JOURNAL_VER  = 1;

// ═══════════════════════════════════════════════════════════════════════════
// TIERS — DERIVED, never a consensus-committed field
// ═══════════════════════════════════════════════════════════════════════════
enum class Tier : std::uint8_t { None = 0, Window = 1, Pinned = 2, Hash = 3 };

inline const char* tier_name(Tier t) {
    switch (t) {
        case Tier::None:   return "NONE";
        case Tier::Window: return "WINDOW";
        case Tier::Pinned: return "PINNED";
        case Tier::Hash:   return "HASH";
    }
    return "?";
}

// ceil(bytes / 1024), with a ONE-KiB MINIMUM CHARGE. The minimum is what stops
// a "many tiny records" amplification: a 1-byte record pays the same as a
// 1024-byte one, so splitting a body into n pieces costs n KiB-units, never
// less than keeping it whole.
inline u64 billed_kib(u64 bytes) {
    const u64 k = (bytes + RENT_KIB_BYTES - 1) / RENT_KIB_BYTES;
    return k ? k : 1;
}

// The horizon a tier is BILLED for. WINDOW is free, so its horizon is its ttl
// and its price is zero; the argument is ignored by every other tier.
inline u64 tier_horizon_bins(Tier t, u64 ttl_bins) {
    switch (t) {
        case Tier::Window: return ttl_bins;
        case Tier::Pinned: return H_PIN_BINS;
        case Tier::Hash:   return H_HASH_BINS;
        case Tier::None:   return 0;
    }
    return 0;
}

// The bytes a node actually RETAINS under a tier. HASH is the whole point: it
// retains the 32-byte leaf and NOT the body.
inline u64 tier_retained_bytes(Tier t, u64 body_bytes) {
    switch (t) {
        case Tier::Window:
        case Tier::Pinned: return body_bytes;
        case Tier::Hash:   return RET_HASH_LEAF_BYTES;
        case Tier::None:   return 0;
    }
    return 0;
}

// THE PRICE LAW:  c * ceil(bytes/1024) * H_tier.
// HASH is billed on what it retains (the leaf), because that is what it costs.
inline u64 price_mwu(Tier t, u64 body_bytes) {
    switch (t) {
        case Tier::Window:
        case Tier::None:   return 0;
        case Tier::Pinned:
            return RENT_C_MWU_PER_KIB_BIN * billed_kib(body_bytes) * H_PIN_BINS;
        case Tier::Hash:
            return RENT_C_MWU_PER_KIB_BIN * billed_kib(RET_HASH_LEAF_BYTES) * H_HASH_BINS;
    }
    return 0;
}

// THE BYTE BOUND, as a checkable predicate:
//      retained_bytes * horizon * c  <=  price * 1024
// "no paid tier hands out more than 1024/c byte-bins per MWU". A free tier is
// vacuously inside it (it is bounded by quota instead) and returns true.
inline bool rent_bound_holds(Tier t, u64 body_bytes) {
    const u64 p = price_mwu(t, body_bytes);
    if (p == 0) return true;
    const u128 byte_bins = u128(tier_retained_bytes(t, body_bytes)) *
                           u128(tier_horizon_bins(t, 0));
    return byte_bins * u128(RENT_C_MWU_PER_KIB_BIN) <= u128(p) * u128(RENT_KIB_BYTES);
}

// The rejected model, kept as the KAT's NEGATIVE CONTROL: a size-blind price
// (one flat charge per promotion, the "decay-floor" shape). It is a function,
// not a policy — nothing calls it outside the test.
inline u64 flat_price_mwu_REJECTED(Tier t, u64 /*body_bytes*/) {
    return t == Tier::None || t == Tier::Window ? 0 : RENT_C_MWU_PER_KIB_BIN * H_PIN_BINS;
}

// ═══════════════════════════════════════════════════════════════════════════
// THE TWO PREREQUISITE SEAMS (both are READS of mainchain data)
// ═══════════════════════════════════════════════════════════════════════════
// TM-OQ1. The COMMITTED mainchain work-per-block at a FINALIZED bin —
// 2^256/(T+1) narrowed with saturation, the same denomination
// w2_receipt.hpp::work_from_target produces. The daemon binds this to the coin
// backend's header index (nBits of the buried block at that height); the KAT
// binds a synthetic table. nullopt = "cannot read it", which FAILS CLOSED.
struct IExogenousDifficultyAnchor {
    virtual ~IExogenousDifficultyAnchor() = default;
    virtual std::optional<u64> block_work_at(u64 bin) const = 0;
};

// TM-OQ2. The FINALIZED mainchain block hash at a bin. Unpredictable before the
// block exists, immutable after it is buried — the only property the epoch seed
// needs. nullopt = not (yet) known.
struct IFinalizedHashSource {
    virtual ~IFinalizedHashSource() = default;
    virtual std::optional<bytes32> hash_at(u64 bin) const = 0;
};

// ═══════════════════════════════════════════════════════════════════════════
// REQUESTS AND OUTCOMES — every failure mode is an IGNORE
// ═══════════════════════════════════════════════════════════════════════════
struct RetentionRequest {
    bytes32       identity{};        // the payout-bound sender
    bytes32       record_hash{};     // what is retained
    std::uint32_t bytes = 0;         // body size, the rent base
    Tier          want = Tier::Window;
    u64           carrier_bin = 0;   // the admitted carrier this rides
    std::string   body;              // optional; NEVER retained for HASH
};

enum class Outcome : std::uint8_t {
    AdmittedWindow,      // free tier granted / re-granted
    Promoted,            // paid tier granted (first payment)
    Renewed,             // paid tier anchor RESET by a later payment
    IgnoredMalformed,    // zero-length / oversize / future carrier
    IgnoredOverQuota,    // MSG_LIVE_CAP (free tier only) — oldest already evicted
    IgnoredUnfunded,     // insufficient live sacrifice credit
    IgnoredNoEpochSeed,  // the exogenous clock is unreadable — FAIL CLOSED
    IgnoredAlreadyHashed,// a permanent leaf already exists; nothing to buy
};

inline const char* outcome_name(Outcome o) {
    switch (o) {
        case Outcome::AdmittedWindow:      return "AdmittedWindow";
        case Outcome::Promoted:            return "Promoted";
        case Outcome::Renewed:             return "Renewed";
        case Outcome::IgnoredMalformed:    return "IgnoredMalformed";
        case Outcome::IgnoredOverQuota:    return "IgnoredOverQuota";
        case Outcome::IgnoredUnfunded:     return "IgnoredUnfunded";
        case Outcome::IgnoredNoEpochSeed:  return "IgnoredNoEpochSeed";
        case Outcome::IgnoredAlreadyHashed:return "IgnoredAlreadyHashed";
    }
    return "?";
}
inline bool outcome_is_ignore(Outcome o) {
    return o != Outcome::AdmittedWindow && o != Outcome::Promoted &&
           o != Outcome::Renewed;
}

enum class CreditOutcome : std::uint8_t {
    Minted,
    RefusedStaleEpoch,   // outside [cur-1, cur]: precomputed or expired
    RefusedSeed,         // the commitment is not this epoch's seed
    RefusedNoSeed,       // seed unreadable -> FAIL CLOSED
};

// How requests reach the view. See "THE CARRIAGE GAP" at the top: this is an
// abstraction precisely BECAUSE the frozen wire has no envelope to carry them.
struct IRetentionFeed {
    virtual ~IRetentionFeed() = default;
    virtual std::vector<RetentionRequest> requests_for(const EmittedPush& p) = 0;
};

// TM-OQ1 unit denomination modes. See the header note; AnchorFloored is the
// shipped default, WindowEmaOnly exists to be shown broken.
enum class UnitMode : std::uint8_t { AnchorFloored = 0, AnchorOnly = 1, WindowEmaOnly = 2 };

// ═══════════════════════════════════════════════════════════════════════════
// RetentionView — the whole feature. Reads the push stream, owns no consensus.
// ═══════════════════════════════════════════════════════════════════════════
class RetentionView {
public:
    struct Record {
        bytes32       identity{};
        std::uint32_t bytes = 0;
        std::string   body;                 // dropped on HASH and on GC
        u64           window_expiry = 0;    // lattice-rounded, WINDOW tier
        bool          pinned = false;
        u64           pin_anchor = 0;       // PINNED while t < pin_anchor+H_pin
    };

    RetentionView(::v37::LaneKind lane,
                  const IExogenousDifficultyAnchor& anchor,
                  const IFinalizedHashSource& hashes,
                  UnitMode mode = UnitMode::AnchorFloored)
        : m_dim(nr::for_version(1, lane)), m_anchor(anchor), m_hashes(hashes),
          m_mode(mode) {}

    // ── the bin clock ────────────────────────────────────────────────────
    // The SAME rule Lane::advance_clock uses (monotone max of admitted carrier
    // bins), replicated here because the consumer tree cannot reach a Lane& —
    // LaneSnapshot does not carry t_now_bin and V37Engine never leaks the Lane.
    // on_tip() adds the burial tick from the block-event driver so a quiet lane
    // still ages out its records.
    u64 t_now() const { return m_t_now; }
    void on_tip(u64 bin) { if (bin > m_t_now) { m_t_now = bin; gc(); } }

    // ── the W2 push tee (post-admission, read-only) ──────────────────────
    // Attach with CarrierIngest::set_observer(). It advances the clock, accrues
    // standing, and pulls any requests bound to this carrier out of the feed.
    // It can return nothing and change nothing that W2 or the engine can see.
    void on_push(const EmittedPush& p) {
        bool advanced = false;
        if (p.carrier_bin > m_t_now) { m_t_now = p.carrier_bin; advanced = true; }
        accrue(p.identity, p.w_raw, p.origin_bin);
        m_ema_raw = m_ema_raw - (m_ema_raw >> 3) + (p.w_raw >> 3);
        ++m_pushes_seen;
        if (advanced) gc();          // nothing expires WITHIN a bin
        if (m_feed) {
            std::vector<RetentionRequest> reqs = m_feed->requests_for(p);
            if (reqs.size() > RET_REQS_PER_CARRIER) reqs.resize(RET_REQS_PER_CARRIER);
            for (RetentionRequest& r : reqs) (void)submit(r);
        }
    }
    void set_feed(IRetentionFeed* f) { m_feed = f; }
    RecordSink sink() { return [this](const EmittedPush& p) { this->on_push(p); }; }

    // ── standing: the PURE ladder, bin-denominated, read-only ────────────
    // standing(id, t) = sum over pushes of w_raw * lambda^(t - origin_bin),
    // evaluated in Q62 and brought back to raw work units. Lots whose age has
    // reached the ladder domain are DROPPED BEFORE lambda_pow is called — past
    // that edge the ratified golden has no entry and the function throws.
    u128 standing(const bytes32& id) const { return standing_at(id, m_t_now); }
    u128 standing_at(const bytes32& id, u64 t) const {
        auto it = m_standing.find(id);
        if (it == m_standing.end()) return 0;
        u128 acc = 0;
        for (const Lot& l : it->second) {
            const u64 age = t > l.origin_bin ? t - l.origin_bin : 0;
            if (age >= nr::ladder_domain_bins()) continue;
            acc += (u128(l.w_raw) * u128(nr::lambda_pow(age))) >> ::v37::FRAC_BITS;
        }
        return acc;
    }

    // ── TM-OQ1: the retention work unit ──────────────────────────────────
    u64 exogenous_unit(u64 t) const {
        const std::optional<u64> bw = m_anchor.block_work_at(t);
        if (!bw.has_value()) return 0;                  // "unreadable"
        const u64 u = *bw >> RETENTION_UNIT_SHIFT;
        return u > RETENTION_UNIT_FLOOR ? u : RETENTION_UNIT_FLOOR;
    }
    u64 ema_unit() const { return m_ema_raw ? m_ema_raw : 1; }
    u64 ttl_work_unit(u64 t) const {
        const u64 ex = exogenous_unit(t);
        switch (m_mode) {
            case UnitMode::WindowEmaOnly:                 // OQ-M2 literal: GAMEABLE
                return ema_unit();
            case UnitMode::AnchorOnly:
                return ex ? ex : UINT64_MAX;              // fail closed -> TTL_MIN
            case UnitMode::AnchorFloored:
            default:
                if (!ex) return UINT64_MAX;               // fail closed -> TTL_MIN
                return std::max(ex, ema_unit());          // volume may only RAISE
        }
    }

    // ── WINDOW: the ratified TTL, and its lattice-rounded expiry ─────────
    static u64 ttl_bins_of(u128 decayed_weight, u64 unit) {
        if (unit == 0) return TTL_MAX_BINS;
        const u128 n = decayed_weight / u128(unit);
        if (n <= u128(TTL_MIN_BINS)) return TTL_MIN_BINS;
        if (n >= u128(TTL_MAX_BINS)) return TTL_MAX_BINS;
        return static_cast<u64>(n);
    }
    u64 ttl_bins_for(const bytes32& id) const {
        return ttl_bins_of(standing(id), ttl_work_unit(m_t_now));
    }
    // Round UP to the next R^fold_cap lattice boundary so GC rides the fold.
    u64 window_expiry_of(u64 carrier_bin, u64 ttl_bins) const {
        return nr::group_hi(carrier_bin + ttl_bins, m_dim.fold_cap);
    }
    // Dropped when the expiry bin is SEALED under the open horizon — the same
    // predicate the lane folds on, so retention GC and the fold agree.
    bool window_dead(u64 expiry) const {
        return nr::sealed_bin(expiry, m_t_now, m_dim.open_horizon_bins);
    }

    // ── TM-OQ2: epochs and the per-epoch seed ────────────────────────────
    u64 epoch_bins() const { return m_dim.ckpt_bins; }      // 64 = R^2 (ratified)
    u64 epoch_of(u64 bin) const { return bin / epoch_bins(); }
    u64 epoch_first_bin(u64 e) const { return e * epoch_bins(); }
    std::optional<bytes32> epoch_seed(u64 e) const {
        const u64 first = epoch_first_bin(e);
        if (first == 0) return std::nullopt;                // no prior finalized block
        const std::optional<bytes32> h = m_hashes.hash_at(first - 1);
        if (!h.has_value()) return std::nullopt;
        static const char kTag[10] = {'V','3','7','R','-','E','P','O','C','H'};
        std::vector<std::uint8_t> b;
        b.reserve(10 + 8 + 32);
        b.insert(b.end(), kTag, kTag + 10);
        for (int i = 0; i < 8; ++i) b.push_back(std::uint8_t((e >> (8 * i)) & 0xff));
        b.insert(b.end(), h->begin(), h->end());
        return ::v37::sha256d(b);
    }

    // ── A-2 sacrifice credit: minted against the epoch seed, perishable ──
    CreditOutcome credit_sacrifice(const bytes32& id, u64 shares, u64 epoch,
                                   const bytes32& seed_commit) {
        const u64 cur = epoch_of(m_t_now);
        if (epoch > cur || cur - epoch >= CREDIT_TTL_EPOCHS)
            return CreditOutcome::RefusedStaleEpoch;
        const std::optional<bytes32> seed = epoch_seed(epoch);
        if (!seed.has_value()) return CreditOutcome::RefusedNoSeed;
        if (!(*seed == seed_commit)) return CreditOutcome::RefusedSeed;
        m_credit[id].push_back(Credit{epoch, shares * MWU_PER_SACRIFICE_SHARE});
        return CreditOutcome::Minted;
    }
    u128 credit_balance(const bytes32& id) const {
        auto it = m_credit.find(id);
        if (it == m_credit.end()) return 0;
        const u64 cur = epoch_of(m_t_now);
        u128 acc = 0;
        for (const Credit& c : it->second)
            if (c.epoch + CREDIT_TTL_EPOCHS > cur) acc += u128(c.mwu);
        return acc;
    }

    // ── the one entry point. NEVER rejects a share; only ever ignores. ───
    Outcome submit(const RetentionRequest& req) {
        if (req.bytes == 0 || req.bytes > RET_MAX_RECORD_BYTES ||
            req.carrier_bin > m_t_now)
            return Outcome::IgnoredMalformed;
        if (m_hashed.count(req.record_hash)) return Outcome::IgnoredAlreadyHashed;

        switch (req.want) {
            case Tier::None:
            case Tier::Window: return admit_window(req);
            case Tier::Pinned: return promote_pinned(req);
            case Tier::Hash:   return promote_hash(req);
        }
        return Outcome::IgnoredMalformed;
    }

    // ── the DERIVED tier: age + the promotion log, never a stored field ──
    Tier tier_of(const bytes32& rh) const {
        if (m_hashed.count(rh)) return Tier::Hash;          // permanent leaf
        auto it = m_records.find(rh);
        if (it == m_records.end()) return Tier::None;
        const Record& r = it->second;
        if (r.pinned && m_t_now < r.pin_anchor + H_PIN_BINS) return Tier::Pinned;
        if (!window_dead(r.window_expiry)) return Tier::Window;
        return Tier::None;
    }

    // ── reads ────────────────────────────────────────────────────────────
    const RetentionLog& log() const { return m_log; }
    bytes32 log_root() const { return m_log.root(); }
    const std::map<bytes32, Record>& records() const { return m_records; }
    const std::set<bytes32>& hashed() const { return m_hashed; }
    const ::v37::nr::RidgeDim& dim() const { return m_dim; }
    u64 pushes_seen() const { return m_pushes_seen; }
    std::size_t live_free_count(const bytes32& id) const {
        std::size_t n = 0;
        for (const auto& [rh, r] : m_records)
            if (r.identity == id && !r.pinned && !window_dead(r.window_expiry)) ++n;
        return n;
    }
    // The bytes this view is actually holding. The number linear rent bounds.
    u64 retained_body_bytes() const {
        u64 n = 0;
        for (const auto& [rh, r] : m_records) { (void)rh; n += r.body.size(); }
        return n;
    }
    // The permanent cost of the HASH tier: 32 bytes per leaf, and nothing else.
    u64 permanent_bytes() const { return RET_HASH_LEAF_BYTES * m_log.leaf_count(); }

    // ── VIEW-LAYER PERSISTENCE ───────────────────────────────────────────
    // What is persisted is the PROMOTION JOURNAL — the ordered leaf payloads —
    // not just the peaks: the MMR retains leaf HASHES, which re-derive the root
    // but cannot rebuild the DERIVED tier state, and the tier is the point.
    // Replaying the journal reproduces the SAME root by construction (the same
    // payloads in the same order through the same append), which the KAT pins.
    //
    // The free WINDOW tier is deliberately NOT persisted: it is funded by live
    // decayed work and rebuilds itself from the push stream within one window.
    // A pinned record's BODY is not persisted here either — bodies belong to
    // the node's blob store; what this restores is the TIER.
    //
    // Nothing about this is consensus. A missing record is not an error, a
    // corrupt one starts EMPTY, and neither can fail a settlement recovery.
    std::string serialize_promotions() const {
        std::string s;
        s.push_back(char(RETENTION_JOURNAL_VER));
        const u64 n = m_promotions.size();
        for (int i = 0; i < 8; ++i) s.push_back(char((n >> (8 * i)) & 0xff));
        for (const auto& p : m_promotions)
            s.append(reinterpret_cast<const char*>(p.data()), p.size());
        return s;
    }
    bool restore_promotions(const std::string& blob) {
        if (blob.size() < 9 || std::uint8_t(blob[0]) != RETENTION_JOURNAL_VER) return false;
        u64 n = 0;
        for (int i = 0; i < 8; ++i) n |= u64(std::uint8_t(blob[1 + i])) << (8 * i);
        if (blob.size() != 9 + n * RET_LEAF_BYTES) return false;       // fail closed
        RetentionLog fresh;
        std::vector<std::vector<std::uint8_t>> js;
        std::set<bytes32> hashed;
        std::map<bytes32, Record> recs;
        for (u64 i = 0; i < n; ++i) {
            const std::size_t off = 9 + std::size_t(i) * RET_LEAF_BYTES;
            std::vector<std::uint8_t> p(blob.begin() + off, blob.begin() + off + RET_LEAF_BYTES);
            if (!ret_leaf_valid(p)) return false;                      // fail closed
            fresh.append_payload(p);
            js.push_back(p);
            const bytes32 rh = ret_leaf_record_hash(p);
            if (ret_leaf_kind(p) == RET_HASH) { hashed.insert(rh); recs.erase(rh); continue; }
            Record r;
            r.identity = ret_leaf_sender(p);
            r.bytes = ret_leaf_bytes(p);
            r.pinned = true;
            r.pin_anchor = ret_leaf_anchor_bin(p);                     // later leaf wins
            r.window_expiry = 0;                                       // free TTL rebuilds live
            recs[rh] = std::move(r);
        }
        m_log = std::move(fresh);
        m_promotions = std::move(js);
        m_hashed = std::move(hashed);
        m_records = std::move(recs);
        return true;
    }
    void save(IRetentionStore& st, u64 chain) const {
        st.put(RetentionLog::store_key(chain), serialize_promotions());
    }
    bool load(IRetentionStore& st, u64 chain) {
        const std::optional<std::string> v = st.get(RetentionLog::store_key(chain));
        if (!v.has_value()) return false;              // absent is NOT an error
        return restore_promotions(*v);
    }
    const std::vector<std::vector<std::uint8_t>>& promotions() const { return m_promotions; }

    // ── garbage collection: expiry rides the fold ────────────────────────
    void gc() {
        for (auto it = m_records.begin(); it != m_records.end();) {
            const Record& r = it->second;
            const bool pin_live = r.pinned && m_t_now < r.pin_anchor + H_PIN_BINS;
            if (!pin_live && window_dead(r.window_expiry)) it = m_records.erase(it);
            else ++it;
        }
        for (auto it = m_standing.begin(); it != m_standing.end();) {
            std::vector<Lot>& v = it->second;
            v.erase(std::remove_if(v.begin(), v.end(), [&](const Lot& l) {
                        const u64 age = m_t_now > l.origin_bin ? m_t_now - l.origin_bin : 0;
                        return age >= nr::ladder_domain_bins();
                    }), v.end());
            if (v.empty()) it = m_standing.erase(it); else ++it;
        }
        const u64 cur = epoch_of(m_t_now);
        for (auto it = m_credit.begin(); it != m_credit.end();) {
            std::vector<Credit>& v = it->second;
            v.erase(std::remove_if(v.begin(), v.end(), [&](const Credit& c) {
                        return c.epoch + CREDIT_TTL_EPOCHS <= cur;
                    }), v.end());
            if (v.empty()) it = m_credit.erase(it); else ++it;
        }
    }

private:
    struct Lot    { u64 w_raw; u64 origin_bin; };
    struct Credit { u64 epoch; u64 mwu; };

    void accrue(const bytes32& id, u64 w_raw, u64 origin_bin) {
        if (w_raw == 0) return;
        std::vector<Lot>& v = m_standing[id];
        v.push_back(Lot{w_raw, origin_bin});
        // Bound the per-identity lot vector by dropping the OLDEST lots — the
        // ones contributing least. This can only LOWER a standing, never raise
        // one, so it cannot be used to buy TTL.
        if (v.size() > RET_MAX_STANDING_LOTS) {
            std::sort(v.begin(), v.end(),
                      [](const Lot& a, const Lot& b) { return a.origin_bin < b.origin_bin; });
            v.erase(v.begin(), v.begin() + (v.size() - RET_MAX_STANDING_LOTS));
        }
    }

    Outcome admit_window(const RetentionRequest& req) {
        const u64 ttl = ttl_bins_of(standing_at(req.identity, m_t_now),
                                    ttl_work_unit(m_t_now));
        const u64 exp = window_expiry_of(req.carrier_bin, ttl);
        auto it = m_records.find(req.record_hash);
        if (it != m_records.end()) {                     // RENEWAL by re-inclusion
            it->second.window_expiry = exp;
            it->second.bytes = req.bytes;
            it->second.body = req.body;
            return Outcome::Renewed;
        }
        // The view-level ceiling: a NEW free record past it is IGNORED. The
        // carrier still stands — this is a view refusing to grow, never a
        // share being refused.
        if (m_records.size() >= RET_MAX_FREE_RECORDS) return Outcome::IgnoredOverQuota;
        // MSG_LIVE_CAP: a new free record deterministically expires this
        // sender's OLDEST live free record. Ordering is (window_expiry,
        // record_hash) ascending — total and identical on every node.
        enforce_free_cap(req.identity);
        Record r;
        r.identity = req.identity;
        r.bytes = req.bytes;
        r.body = req.body;
        r.window_expiry = exp;
        m_records.emplace(req.record_hash, std::move(r));
        return Outcome::AdmittedWindow;
    }

    void enforce_free_cap(const bytes32& id) {
        std::vector<std::pair<std::pair<u64, bytes32>, bytes32>> live;
        for (const auto& [rh, r] : m_records)
            if (r.identity == id && !r.pinned && !window_dead(r.window_expiry))
                live.push_back({{r.window_expiry, rh}, rh});
        if (live.size() < MSG_LIVE_CAP) return;
        std::sort(live.begin(), live.end());
        const std::size_t drop = live.size() - (MSG_LIVE_CAP - 1);
        for (std::size_t i = 0; i < drop; ++i) m_records.erase(live[i].second);
    }

    // Both paid paths share the exogenous-clock gate and the debit.
    bool pay(const bytes32& id, u64 price) {
        if (credit_balance(id) < u128(price)) return false;
        u64 left = price;
        std::vector<Credit>& v = m_credit[id];
        std::sort(v.begin(), v.end(),
                  [](const Credit& a, const Credit& b) { return a.epoch < b.epoch; });
        const u64 cur = epoch_of(m_t_now);
        for (Credit& c : v) {                            // oldest live lot first
            if (left == 0) break;
            if (c.epoch + CREDIT_TTL_EPOCHS <= cur) continue;
            const u64 take = std::min(left, c.mwu);
            c.mwu -= take;
            left -= take;
        }
        v.erase(std::remove_if(v.begin(), v.end(),
                               [](const Credit& c) { return c.mwu == 0; }), v.end());
        return left == 0;
    }

    Outcome promote_pinned(const RetentionRequest& req) {
        if (!epoch_seed(epoch_of(m_t_now)).has_value()) return Outcome::IgnoredNoEpochSeed;
        const u64 price = price_mwu(Tier::Pinned, req.bytes);
        if (!pay(req.identity, price)) return Outcome::IgnoredUnfunded;

        auto it = m_records.find(req.record_hash);
        if (it == m_records.end()) {
            // A record can be pinned without ever having been in the window:
            // the payment is the admission. Give it a window expiry too, so the
            // fall-back after the pin lapses is a normal (already-expired) one.
            Record r;
            r.identity = req.identity;
            r.bytes = req.bytes;
            r.body = req.body;
            r.window_expiry = window_expiry_of(req.carrier_bin, TTL_MIN_BINS);
            it = m_records.emplace(req.record_hash, std::move(r)).first;
        }
        const bool was_pinned = it->second.pinned;
        it->second.bytes = req.bytes;
        if (!req.body.empty()) it->second.body = req.body;
        it->second.pinned = true;
        it->second.pin_anchor = m_t_now;                 // RESET, never chained
        append_promotion(ret_leaf_payload(was_pinned ? RET_RENEW : RET_PIN, req.identity,
                                          req.record_hash, m_t_now, req.bytes, price));
        return was_pinned ? Outcome::Renewed : Outcome::Promoted;
    }

    Outcome promote_hash(const RetentionRequest& req) {
        if (!epoch_seed(epoch_of(m_t_now)).has_value()) return Outcome::IgnoredNoEpochSeed;
        const u64 price = price_mwu(Tier::Hash, req.bytes);
        if (!pay(req.identity, price)) return Outcome::IgnoredUnfunded;
        append_promotion(ret_leaf_payload(RET_HASH, req.identity, req.record_hash,
                                          m_t_now, req.bytes, price));
        m_hashed.insert(req.record_hash);
        m_records.erase(req.record_hash);                // THE BODY IS DROPPED
        return Outcome::Promoted;
    }

    // Every promotion goes through here: one leaf in the log, one entry in the
    // journal. The journal is what a restore replays — the MMR retains leaf
    // HASHES, which are enough to re-derive the root but not to rebuild the
    // DERIVED tier state, and the tier is the whole point.
    void append_promotion(const std::vector<std::uint8_t>& payload) {
        m_log.append_payload(payload);
        m_promotions.push_back(payload);
    }

    ::v37::nr::RidgeDim              m_dim;
    const IExogenousDifficultyAnchor& m_anchor;
    const IFinalizedHashSource&       m_hashes;
    UnitMode                          m_mode;
    IRetentionFeed*                   m_feed = nullptr;

    u64 m_t_now = 0;
    u64 m_ema_raw = 0;
    u64 m_pushes_seen = 0;

    std::map<bytes32, std::vector<Lot>>    m_standing;   // read-only credit source
    std::map<bytes32, std::vector<Credit>> m_credit;     // A-2 MWU, perishable
    std::map<bytes32, Record>              m_records;    // WINDOW / PINNED bodies
    std::set<bytes32>                      m_hashed;     // derived from the journal
    RetentionLog                           m_log;        // the SECOND record log
    std::vector<std::vector<std::uint8_t>> m_promotions; // the replayable journal
};

} // namespace c2pool::v37n::retention
