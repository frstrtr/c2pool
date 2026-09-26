// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_drops_wiring.hpp — DROPS on the XMR lane: the live
// shell wiring (the XMR twin of main_v37_btc_dash.cpp's Step-2 block).
//
// WHAT WAS MISSING. XmrNode carries the four DROPS T3 seams (set_drop_harvester,
// set_enrollment_book, set_pre_harvest, set_drops_price_fn) and the finalize
// driver composes compose_credit_replace() at every FOUND, but main_v37_xmr.cpp
// never built a DropsWiring and never called a seam. After the operator flip
// every XMR node would be gate-ON and DORMANT: it converges and credits nobody.
// This header is what the shell holds instead; the shell makes the calls.
//
// FOUR XMR FACTS THE BTC WIRING DOES NOT HAVE TO FACE, AND HOW EACH IS MET:
//
// (1) THE CLOCK. An XMR work event's origin bin is its TEMPLATE height — the
//     height of the block it would become (relay Admitted::bin, the stratum
//     AcceptedShare::height) — which is the native tip + 1. The bin a payee is
//     drawing in RIGHT NOW is therefore tip + 1, so the ex-ante clock fed to the
//     TipBin is open_bin_of_tip(tip) = tip + 1, and an enrolment made now takes
//     effect at tip + 2: strictly after every draw the payee can have seen.
//     Under --arm-order p2p-first the tip is the NATIVE node's verified levin
//     tip (the shell's pump_tip height watch). It is never the burial frontier
//     (that enters only through pre_harvest -> declare_at_frontier) and never a
//     monerod poll.
//
// (2) THE TARGET GEOMETRY. The estimator is written for leading-zero-bit
//     targets (h_T = 2^(256-lz) - 1, T = 2^lz); a Monero share is a DIFFICULTY
//     test, H_le * share_diff < 2^256. normalized_hash() maps the RandomX hash
//     onto the fixed geometry lz = kXmrDropsLz EXACTLY:
//         N = floor(H_le * share_diff / 2^lz)      N < 2^(256-lz)  <=>  share
//     so a share is a hash at or below h_T, a raindrop is a hash above it, and
//     the estimator's work unit is 2^lz normalised attempts = ONE share.
//
// (3) THE DENOMINATION (DROPS-R1). A share enters the XMR lane as ONE push of
//     w_raw = receipt_weight (relay::kReceiptWeight = 1, or fee::kFeeReceipt
//     Weight with the fee model ON), not as 2^lz. The seam prices work as
//     floor(reward * (work << Q) / SUM weight), so the WorkPrice handed to the
//     node carries SUM weight re-expressed in the estimator's unit:
//         sum' = floor((SUM weight << lz) / receipt_weight)
//     so ONE share of estimated work prices exactly like ONE real share at the
//     cut. Same cut, same project(), one integer rescale, no new constant.
//
// (4) REPLICATION. The XMR arm composes on EVERY node for EVERY lane block
//     (FinalizeConnect -> XmrNode::on_network_block_won), from the node's OWN
//     harvest. A raindrop only one node saw would move only that node's
//     owed_digest. So raindrops travel the receipt relay exactly like shares
//     (RandomX-verified by every receiver, flooded, deduped), and every node's
//     harvester sees the same set; see XmrRelayNode::submit_own_drop.
//
// (5) THE ENROLMENT BOOK IS NODE-LOCAL (ENROL-REPL). Replicating the raindrops
//     is not enough: the EnrollmentBook is decided at each node's OWN tip, so
//     two nodes that enrolled the same payees at different tips (a late join, a
//     restart, a partition) credit different intervals and compose different
//     deltas for the same block -> owed_digest forks. The fix is the BTC/DASH
//     rule (DROPS-R3, w3 v0x03): THE WINNER'S VIEW IS AUTHORITATIVE. The winner
//     composes the delta ONCE, when it books its own win (compose_carry), and
//     carries it with its enrolment-book digest on the relay (FB_BLOCK_WON v0x02); EVERY
//     node -- the winner included -- books the CARRIED map for that block after
//     the same deterministic check (verify_carry), and only advances (discards)
//     its own buried harvest at the same frontier.
// (6) RAIN-BACKFILL: CONSUMPTION FOLLOWS THE CHAIN, NOT THE BOOKING ORDER.
//     DropHarvester::take_buried() RELEASES every interval below the frontier
//     for good. A node that books its own sibling Y at h, then (1-deep reorg)
//     the canonical X at h, composes X from an EMPTY harvest while every other
//     node composed it from the full one -- owed_digest forks. And a raindrop
//     that reaches a node after the release (partition, late join) is dropped
//     as "late" on that node alone. ChainOrderedHarvest below RETAINS the
//     raindrops + share counts (bounded) and composes the harvest of a lane
//     block won at h as a PURE function of the retained set over
//     [frontier(prev_lane(h)), h - D_conf), prev_lane(h) = the lane block the
//     CANONICAL chain carries nearest below h (RAIN-BACKFILL-2: never a mark
//     this node set or erased while booking, so an out-of-order booking -- h+1
//     before h in a reorg -- or a replaced sibling derives exactly the ranges of
//     a node that only ever booked the canonical chain, in order). The shell attaches it with
//     attach_chain_order(); the composition HOLDs on the relay's drops_sync()
//     over range_for(h) until the set is complete (xmr_relay_node.hpp).
//
// GATE OFF (the shipped default): make() returns nullptr, the shell constructs
// nothing, attaches nothing, and every path below is unreachable.
// ===========================================================================
#pragma once

#include <array>
#include <atomic>
#include <string>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <unistd.h>   // fsync (DROPS-RESTART journal)
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <vector>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <c2pool/v37/v37_drops_wiring.hpp>   // DropsWiring, TipBin, EnrollOutcome, kDropsWiringArmed
#include <c2pool/v37/w4_settlement.hpp>      // settle::WorkPrice, work_price_at

namespace c2pool::v37n::xmr::drops {

using ::v37::bytes32;

// The fixed leading-zero geometry every XMR raindrop and share-count row is
// expressed in. 32 bits of head-room keeps the normalisation exact for every
// share_diff < 2^32 (a product never saturates) and the estimator's h_T far
// from both ends of the u256 range.
inline constexpr unsigned kXmrDropsLz = 32;

// A raindrop must still be real work: at least share_diff / kDropsFloorDiv
// (and at least difficulty 1). The receiver RandomX-verifies it against this
// floor exactly as it verifies a share against share_diff, so a peer cannot
// flood the harvest with free hashes. A function of share_diff alone, and
// share_diff is HELLO-checked, so every node applies the same floor.
inline constexpr std::uint64_t kDropsFloorDiv = 64;
inline std::uint64_t drops_floor_diff(std::uint64_t share_diff) {
    const std::uint64_t f = share_diff / kDropsFloorDiv;
    return f ? f : 1;
}

// (1) the ex-ante clock: the bin a payee is drawing in at native tip `tip`.
inline std::uint64_t open_bin_of_tip(std::uint64_t tip_height) { return tip_height + 1; }

// (2) N = floor(H_le * share_diff / 2^kXmrDropsLz), saturated, as a big-endian
// bytes32 (the W2 / estimator convention: byte 0 most significant).
inline bytes32 normalized_hash(const bytes32& pow_le, std::uint64_t share_diff) {
    std::array<std::uint64_t, 5> p{0, 0, 0, 0, 0};
    unsigned __int128 carry = 0;
    for (int w = 0; w < 4; ++w) {
        std::uint64_t word = 0;
        for (int i = 0; i < 8; ++i)
            word |= static_cast<std::uint64_t>(pow_le[static_cast<std::size_t>(w * 8 + i)]) << (8 * i);
        const unsigned __int128 prod = static_cast<unsigned __int128>(word) * share_diff + carry;
        p[static_cast<std::size_t>(w)] = static_cast<std::uint64_t>(prod);
        carry = prod >> 64;
    }
    p[4] = static_cast<std::uint64_t>(carry);
    static_assert(kXmrDropsLz > 0 && kXmrDropsLz < 64, "single-limb shift");
    std::array<std::uint64_t, 4> n{};
    for (int i = 0; i < 4; ++i)
        n[static_cast<std::size_t>(i)] = (p[static_cast<std::size_t>(i)] >> kXmrDropsLz) |
                                         (p[static_cast<std::size_t>(i + 1)] << (64 - kXmrDropsLz));
    if (p[4] >> kXmrDropsLz) n = {~0ull, ~0ull, ~0ull, ~0ull};   // saturate (far above h_T)
    bytes32 out{};
    for (int i = 0; i < 4; ++i)                                     // limb 3 = most significant
        for (int b = 0; b < 8; ++b)
            out[static_cast<std::size_t>((3 - i) * 8 + (7 - b))] =
                static_cast<std::uint8_t>(n[static_cast<std::size_t>(i)] >> (8 * b));
    return out;
}

// (3) the WorkPrice at a cut, re-expressed in the estimator's unit.
inline ::c2pool::v37n::settle::WorkPrice rescale_price(::c2pool::v37n::settle::WorkPrice wp,
                                                       std::uint64_t receipt_weight) {
    if (!wp.valid || receipt_weight == 0) { wp.valid = false; return wp; }
    // (sum << lz): a 5-limb value; then floor-divide by receipt_weight.
    std::array<std::uint64_t, 5> s{0, 0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        s[static_cast<std::size_t>(i)] |= wp.sum_weight.v[static_cast<std::size_t>(i)] << kXmrDropsLz;
        s[static_cast<std::size_t>(i + 1)] |= wp.sum_weight.v[static_cast<std::size_t>(i)] >> (64 - kXmrDropsLz);
    }
    unsigned __int128 rem = 0;
    std::array<std::uint64_t, 5> q{0, 0, 0, 0, 0};
    for (int i = 4; i >= 0; --i) {
        const unsigned __int128 cur = (rem << 64) | s[static_cast<std::size_t>(i)];
        q[static_cast<std::size_t>(i)] = static_cast<std::uint64_t>(cur / receipt_weight);
        rem = cur % receipt_weight;
    }
    if (q[4]) { wp.valid = false; return wp; }   // beyond U256: no conversion expressible (fail closed)
    for (int i = 0; i < 4; ++i) wp.sum_weight.v[static_cast<std::size_t>(i)] = q[static_cast<std::size_t>(i)];
    wp.valid = !wp.sum_weight.is_zero();
    return wp;
}

// The price at the SAME cut, through the SAME view, the fold reads.
template <class View>
inline ::c2pool::v37n::settle::WorkPrice drops_price_at(std::uint64_t reward, const View& v,
                                                        std::uint64_t receipt_weight) {
    return rescale_price(::c2pool::v37n::settle::work_price_at(reward, v), receipt_weight);
}

// ── (5) ENROL-REPL: the carried delta ────────────────────────────────────────
// Feature marker (the KAT switches on it: absent on the base tree).
#define C2POOL_XMR_DROPS_CARRY 1

// The winner's composed DROPS delta + the digest of the book it composed under,
// as carried by FB_BLOCK_WON v0x02 (xmr_relay_wire.hpp BlockWon::Drops).
struct DropsCarry {
    std::map<bytes32, long long> delta;   // no zero rows
    bytes32 enrollment_digest{};
    bool operator==(const DropsCarry&) const = default;
};
inline constexpr std::size_t kDropsCarryMaxRows = 256;   // == relay::kBlockWonDropsMaxRows

// The winner's composition, ONCE: the SAME pure function the finalize driver
// composes with (subthreshold_credit), zero rows dropped, plus the book digest.
inline DropsCarry compose_carry(const ::v37::LaneParams& p,
                                const std::vector<::c2pool::v37n::settle::HarvestedReceipt>& harvest,
                                const ::c2pool::v37n::settle::DropsCompose& ctx) {
    DropsCarry c;
    for (const auto& [k, v] : ::c2pool::v37n::settle::subthreshold_credit(p, harvest, ctx))
        if (v != 0) c.delta.emplace(k, v);
    c.enrollment_digest = ctx.enrollment_digest();
    return c;
}

// What every node can check about a carried delta, deterministically, from the
// frame and the chain alone ("" = book it). `binds` = the frame's (bid, h_b,
// cut, reward, owed_digest_at_win) equal the ON-CHAIN commitment of the block
// being booked. A refused delta books as EMPTY -- what a DROPS-dormant winner
// credits -- on every node alike, the winner included, so a refusal never forks.
inline std::string verify_carry(const DropsCarry& c, bool binds) {
    if (!binds) return "the carrying frame does not bind to the on-chain commitment (bid/h/cut/reward/owed_digest)";
    if (c.delta.size() > kDropsCarryMaxRows) return "more rows than the carriage bound";
    for (const auto& [k, v] : c.delta) if (v == 0) return "a zero delta row (non-canonical)";
    if (!c.delta.empty() && c.enrollment_digest == ::c2pool::v37n::empty_enrollment_digest())
        return "a non-empty delta composed under an EMPTY enrolment book (nobody enrolled => no delta)";
    return "";
}
// ── (6) RAIN-BACKFILL: the retained, chain-ordered harvest ───────────────────
// Feature marker (the harvest-order KAT switches on it: absent on the base).
#define C2POOL_XMR_HARVEST_CHAIN_PURE 1

// THE HARVEST RANGE IS A PURE FUNCTION OF THE CANONICAL CHAIN (RAIN-BACKFILL-2).
// The lane block won at h settles the intervals
//
//     range(h) = [ frontier(prev_lane(h)), frontier(h) ),  frontier(x) = x - D_conf
//
// where prev_lane(h) is the height of the lane block the CANONICAL chain carries
// nearest below h (a PrevLaneFn the shell answers from the chain itself: the
// block id at each height and whether its coinbase is a lane block). Nothing on
// this path reads what THIS node booked, in which order, or what it booked and
// then replaced: an out-of-order booking (h+1 before h during a reorg) or a
// sibling booked and replaced composes exactly the ranges of a node that booked
// the canonical chain in order, so consecutive canonical lane blocks tile the
// intervals once each -- never an interval twice, never a gap.
class ChainOrderedHarvest {
public:
    using Rows = std::vector<::c2pool::v37n::settle::HarvestedReceipt>;
    using CoversFn = std::function<bool(std::uint64_t)>;
    // prev_lane(h): the canonical lane block below h; kNoPrevLane = none on the
    // chain below h (the first lane block: everything retained below its
    // frontier); nullopt = UNDECIDABLE now (the shell HOLDs the composition).
    using PrevLaneFn = std::function<std::optional<std::uint64_t>(std::uint64_t)>;
    static constexpr std::uint64_t kNoPrevLane = 0;        // chain heights are >= 1
    static constexpr std::uint64_t kReorgMargin = 64;      // intervals kept below the top range (>> any reorg depth)
    static constexpr std::size_t   kBookedKept = 256;      // diagnostic range log

    ChainOrderedHarvest(std::uint32_t K, unsigned lz, std::uint64_t d_conf) : m_K(K), m_lz(lz), m_d_conf(d_conf) {}
    void set_d_conf(std::uint64_t d) { m_d_conf = d; }
    std::uint64_t d_conf() const { return m_d_conf; }

    // idempotent: the same (payee, normalised hash) at the same interval counts once
    void observe_drop(const bytes32& payee, std::uint64_t interval, const bytes32& nhash) {
        if (interval < m_floor) { ++m_late; return; }
        if (m_drops[interval].insert(std::make_pair(payee, nhash)).second) ++m_observed;
    }
    void observe_share(const bytes32& payee, std::uint64_t interval) {
        if (interval < m_floor) return;
        ++m_shares[std::make_pair(payee, interval)];
    }

    std::uint64_t frontier_of(std::uint64_t won_height) const {
        return won_height > m_d_conf ? won_height - m_d_conf : 0;
    }
    // THE range: a pure function of (h, the canonical prev_lane(h)). nullopt = undecidable.
    std::optional<std::pair<std::uint64_t, std::uint64_t>> range_with(std::uint64_t won_height,
                                                                      std::optional<std::uint64_t> prev_lane) const {
        if (!prev_lane) return std::nullopt;
        const std::uint64_t hi = frontier_of(won_height);
        const std::uint64_t lo = (*prev_lane == kNoPrevLane || *prev_lane >= won_height) ? 0 : frontier_of(*prev_lane);
        return std::make_pair(std::min(lo, hi), hi);
    }

    // The rows over [lo, hi) from the retained set (pure; `withheld` counts the
    // rows whose share count S is not covered here -- never credited).
    Rows rows_over(std::uint64_t lo, std::uint64_t hi, const CoversFn& covers,
                   const ::c2pool::v37n::EnrollmentBook* enrollment, std::uint64_t* withheld = nullptr) const {
        std::map<std::pair<bytes32, std::uint64_t>, std::vector<bytes32>> keys;   // (payee, interval) -> hashes
        for (auto it = m_drops.lower_bound(lo); it != m_drops.end() && it->first < hi; ++it)
            for (const auto& [payee, h] : it->second) keys[std::make_pair(payee, it->first)].push_back(h);
        for (auto it = m_shares.begin(); it != m_shares.end(); ++it) {
            const auto iv = it->first.second;
            if (iv < lo || iv >= hi) continue;
            if (keys.count(it->first)) continue;
            if (!enrollment || !enrollment->enrolled(it->first.first, iv)) continue;   // share-only rows: enrolled payees
            keys[it->first];
        }
        Rows out;
        for (auto& [k, hashes] : keys) {
            if (!covers || !covers(k.second)) { if (withheld) ++*withheld; continue; }   // S UNKNOWN here: withheld
            ::c2pool::v37::subthreshold::ReceiptCollector rc(m_K, ::c2pool::v37n::drops_detail::h_t_of_lz(m_lz));
            std::sort(hashes.begin(), hashes.end());
            for (const auto& h : hashes) rc.observe(::c2pool::v37n::drops_detail::u256_of(h));
            auto si = m_shares.find(k);
            rc.set_shares(si == m_shares.end() ? 0 : si->second);
            out.push_back(::c2pool::v37n::settle::HarvestedReceipt{k.first, k.second, rc});
        }
        return out;
    }
    // A short digest of the retained inputs of [lo, hi) (payee, interval, hashes,
    // S): what the rig compares across nodes per canonical block. Diagnostic.
    std::uint64_t inputs_digest(std::uint64_t lo, std::uint64_t hi) const {
        std::uint64_t x = 1469598103934665603ULL;
        auto mix = [&x](const unsigned char* p, std::size_t n) { for (std::size_t i = 0; i < n; ++i) { x ^= p[i]; x *= 1099511628211ULL; } };
        for (auto it = m_drops.lower_bound(lo); it != m_drops.end() && it->first < hi; ++it) {
            mix(reinterpret_cast<const unsigned char*>(&it->first), sizeof(it->first));
            for (const auto& [payee, h] : it->second) { mix(payee.data(), payee.size()); mix(h.data(), h.size()); }
        }
        for (const auto& [k, s] : m_shares) {
            if (k.second < lo || k.second >= hi) continue;
            mix(k.first.data(), k.first.size());
            mix(reinterpret_cast<const unsigned char*>(&k.second), sizeof(k.second));
            mix(reinterpret_cast<const unsigned char*>(&s), sizeof(s));
        }
        return x;
    }

    // Book a lane block won at `won_height` whose canonical predecessor lane
    // block is `prev_lane`: the rows of range_with(won_height, prev_lane). The
    // retained set is NOT consumed (a later booking at the same or a lower
    // height -- a reorg -- re-derives from it); it is pruned only below the top
    // range minus kReorgMargin.
    Rows take(std::uint64_t won_height, std::optional<std::uint64_t> prev_lane, const CoversFn& covers,
              const ::c2pool::v37n::EnrollmentBook* enrollment) {
        const auto rg = range_with(won_height, prev_lane);
        if (!rg) { ++m_undecided; return {}; }
        const auto [lo, hi] = *rg;
        m_last_lo = lo; m_last_hi = hi;
        m_booked[won_height] = *rg;
        while (m_booked.size() > kBookedKept) m_booked.erase(m_booked.begin());
        Rows out = rows_over(lo, hi, covers, enrollment, &m_withheld);
        if (won_height >= m_top) {   // bounded retention: keep kReorgMargin intervals below the top range
            m_top = won_height;
            if (lo > kReorgMargin) m_floor = std::max(m_floor, lo - kReorgMargin);
        }
        m_drops.erase(m_drops.begin(), m_drops.lower_bound(m_floor));
        for (auto it = m_shares.begin(); it != m_shares.end();) it = it->first.second < m_floor ? m_shares.erase(it) : std::next(it);
        return out;
    }

    // ★ DROPS-RESTART (defect 1): prev_lane(h) from the canonical chain, as a
    // pure walk. Only a block whose BYTES were read and whose coinbase carries
    // no 03-21-00 lane tag is a deterministic "not lane"; a block that carries
    // the tag is a lane block whether or not its root matched this node's ring
    // yet (the candidate match is node state: a restarted node's ring is short).
    // A chain row that is not readable, or bytes that are not readable, is
    // UNDECIDABLE now: nullopt (the booking HOLDs) and NOTHING is memoised.
    // kNoPrevLane only after walking down to height 1 or past max_walk.
    enum class LaneProbe { Lane, NotLane, Undecidable };
    static LaneProbe probe_of(bool bytes_read, bool is_lane, bool has_lane_tag) {
        if (!bytes_read) return LaneProbe::Undecidable;
        return (is_lane || has_lane_tag) ? LaneProbe::Lane : LaneProbe::NotLane;
    }
    struct WalkStats { std::uint64_t decoded = 0, none = 0, undecided = 0, row_missing = 0; };
    using RowFn = std::function<std::optional<std::string>(std::uint64_t height)>;
    using ProbeFn = std::function<LaneProbe(const std::string& bid)>;
    static std::optional<std::uint64_t> walk_prev_lane(std::uint64_t won_height, std::uint64_t max_walk,
                                                       const RowFn& row, const ProbeFn& probe,
                                                       std::map<std::string, bool>& memo, WalkStats* st = nullptr) {
        for (std::uint64_t x = won_height; x-- > 1 && won_height - x <= max_walk;) {
            const auto b = row(x);
            if (!b) { if (st) { ++st->undecided; ++st->row_missing; } return std::nullopt; }   // HOLD, never "none below"
            auto it = memo.find(*b);
            if (it == memo.end()) {
                const LaneProbe p = probe(*b);
                if (p == LaneProbe::Undecidable) { if (st) ++st->undecided; return std::nullopt; }   // HOLD, not memoised
                if (st) ++st->decoded;
                it = memo.emplace(*b, p == LaneProbe::Lane).first;
            }
            if (it->second) return x;
        }
        if (st) ++st->none;
        return kNoPrevLane;
    }

    std::uint64_t observed() const { return m_observed; }
    std::uint64_t late() const { return m_late; }
    std::uint64_t withheld() const { return m_withheld; }
    std::uint64_t undecided() const { return m_undecided; }
    std::uint64_t floor() const { return m_floor; }
    std::size_t marks() const { return m_booked.size(); }
    std::size_t retained_intervals() const { return m_drops.size(); }
    std::pair<std::uint64_t, std::uint64_t> last_range() const { return {m_last_lo, m_last_hi}; }

private:
    std::uint32_t m_K;
    unsigned m_lz;
    std::uint64_t m_d_conf;
    std::map<std::uint64_t, std::set<std::pair<bytes32, bytes32>>> m_drops;          // interval -> {(payee, N)}
    std::map<std::pair<bytes32, std::uint64_t>, std::uint64_t> m_shares;            // (payee, interval) -> S
    std::map<std::uint64_t, std::pair<std::uint64_t, std::uint64_t>> m_booked;       // diagnostic: h -> the range it composed
    std::uint64_t m_floor = 0, m_top = 0, m_observed = 0, m_late = 0, m_withheld = 0, m_undecided = 0, m_last_lo = 0, m_last_hi = 0;
};

// ── ★ DROPS-RESTART (defects 2 + 3): the carried-delta journal ─────────────
// Append-only, fsync'd, one record per line, next to the settlement store:
//   W <bid> <hex FB_BLOCK_WON v0x01>   our own win, written when the win is
//                                      registered (before its delta exists)
//   F <bid> <hex FB_BLOCK_WON v0x02>   a carried frame: our composition,
//                                      written BEFORE it is sent or booked, or
//                                      a peer's frame once it booked CARRIED
//   B <bid> <n> [<payee hex> <delta>]  the delta this node BOOKED for bid,
//                                      written BEFORE the node books it
//   P <bid> <h>                        our own block, written in the exact
//                                      network gate BEFORE it is published
//                                      (WRITE-AHEAD: a crash between the
//                                      publish and the FOUND callback, where
//                                      W is written, cannot lose the win)
// After a restart the shell re-announces and serves every F frame, composes
// every W without an F at its booking, and a boot / converge re-drive of a
// pending FOUND books B (never a fresh local composition); a P without a W is
// our own win all the same and is composed at its booking. The last record of
// a kind for a bid wins. Only ever constructed under the flip.
#define C2POOL_XMR_DROPS_RESTART 1
#define C2POOL_XMR_DROPS_WRITEAHEAD 1
class DropsCarryStore {
public:
    using Delta = std::map<bytes32, long long>;
    explicit DropsCarryStore(std::string path) : m_path(std::move(path)) {}
    struct Loaded { std::size_t own = 0, frames = 0, booked = 0, malformed = 0, published = 0; };
    Loaded load() {
        Loaded l;
        std::FILE* f = std::fopen(m_path.c_str(), "r");
        if (!f) return l;
        std::string line;
        auto take = [&](const std::string& ln) {
            std::vector<std::string> t;
            std::size_t i = 0;
            while (i < ln.size()) {
                while (i < ln.size() && ln[i] == ' ') ++i;
                std::size_t j = i;
                while (j < ln.size() && ln[j] != ' ') ++j;
                if (j > i) t.push_back(ln.substr(i, j - i));
                i = j;
            }
            if (t.size() < 3 || t[1].size() != 64) { ++l.malformed; return; }
            if (t[0] == "P") {   // WRITE-AHEAD: our own block, journalled before it was published
                std::uint64_t h = 0;
                try { h = static_cast<std::uint64_t>(std::stoull(t[2])); } catch (...) { ++l.malformed; return; }
                if (t.size() != 3) { ++l.malformed; return; }
                { std::lock_guard<std::mutex> lk(m_pub_mu); m_pub[t[1]] = h; }
                ++l.published;
                return;
            }
            if (t[0] == "W" || t[0] == "F") {
                std::vector<std::uint8_t> raw;
                if (!unhex(t[2], raw)) { ++l.malformed; return; }
                if (t[0] == "W") { m_own[t[1]] = std::move(raw); ++l.own; }
                else             { m_frames[t[1]] = std::move(raw); ++l.frames; }
                return;
            }
            if (t[0] == "B") {
                std::size_t n = 0;
                try { n = static_cast<std::size_t>(std::stoull(t[2])); } catch (...) { ++l.malformed; return; }
                if (t.size() != 3 + 2 * n) { ++l.malformed; return; }
                Delta d;
                for (std::size_t k = 0; k < n; ++k) {
                    std::vector<std::uint8_t> p;
                    if (!unhex(t[3 + 2 * k], p) || p.size() != 32) { ++l.malformed; return; }
                    bytes32 key{}; std::copy(p.begin(), p.end(), key.begin());
                    try { d[key] = std::stoll(t[4 + 2 * k]); } catch (...) { ++l.malformed; return; }
                }
                m_booked[t[1]] = std::move(d);
                ++l.booked;
                return;
            }
            ++l.malformed;
        };
        int c;
        while ((c = std::fgetc(f)) != EOF) {
            if (c == '\n') { if (!line.empty()) take(line); line.clear(); }
            else line.push_back(static_cast<char>(c));
        }
        if (!line.empty()) ++l.malformed;   // a torn last line (crash mid-append): ignored
        std::fclose(f);
        return l;
    }
    bool put_own(const std::string& bid, const std::vector<std::uint8_t>& frame) {
        m_own[bid] = frame;
        return append("W " + bid + " " + hex(frame));
    }
    bool put_frame(const std::string& bid, const std::vector<std::uint8_t>& frame) {
        m_frames[bid] = frame;
        return append("F " + bid + " " + hex(frame));
    }
    bool put_booked(const std::string& bid, const Delta& d) {
        m_booked[bid] = d;
        std::string s = "B " + bid + " " + std::to_string(d.size());
        for (const auto& [k, v] : d) s += " " + hex(std::vector<std::uint8_t>(k.begin(), k.end())) + " " + std::to_string(v);
        return append(s);
    }
    // WRITE-AHEAD: our own block (monerod/levin block id, 64 hex) at height h,
    // journalled BEFORE it is published. Called on the stratum listener thread
    // (the exact network gate) as well as the main thread: locked.
    bool put_published(const std::string& bid, std::uint64_t h) {
        { std::lock_guard<std::mutex> lk(m_pub_mu); m_pub[bid] = h; }
        return append("P " + bid + " " + std::to_string(h));
    }
    bool published(const std::string& bid) const {
        std::lock_guard<std::mutex> lk(m_pub_mu);
        return m_pub.count(bid) != 0;
    }
    std::size_t published_size() const {
        std::lock_guard<std::mutex> lk(m_pub_mu);
        return m_pub.size();
    }
    // THE decision the booking takes for a lane block: is it OUR win whose carried
    // delta is still to be composed (registered W, or published P), with no
    // composed frame (F) yet? A P alone (crash between the publish and the FOUND
    // callback) answers yes: the win survives, so the delta is still carried.
    bool own_to_compose(const std::string& bid) const {
        return (m_own.count(bid) != 0 || published(bid)) && m_frames.count(bid) == 0;
    }
    std::optional<Delta> booked(const std::string& bid) const {
        auto it = m_booked.find(bid);
        if (it == m_booked.end()) return std::nullopt;
        return it->second;
    }
    bool has_frame(const std::string& bid) const { return m_frames.count(bid) != 0; }
    const std::map<std::string, std::vector<std::uint8_t>>& own() const { return m_own; }
    const std::map<std::string, std::vector<std::uint8_t>>& frames() const { return m_frames; }
    std::size_t booked_size() const { return m_booked.size(); }
    std::uint64_t write_failures() const { return m_write_fail.load(); }
    const std::string& path() const { return m_path; }

private:
    static std::string hex(const std::vector<std::uint8_t>& b) {
        static const char* d = "0123456789abcdef";
        std::string s; s.reserve(b.size() * 2);
        for (std::uint8_t x : b) { s.push_back(d[x >> 4]); s.push_back(d[x & 15]); }
        return s;
    }
    static bool unhex(const std::string& s, std::vector<std::uint8_t>& out) {
        if (s.size() % 2) return false;
        auto nib = [](char c) -> int { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
        out.clear(); out.reserve(s.size() / 2);
        for (std::size_t i = 0; i < s.size(); i += 2) {
            const int a = nib(s[i]), b = nib(s[i + 1]);
            if (a < 0 || b < 0) return false;
            out.push_back(static_cast<std::uint8_t>(a * 16 + b));
        }
        return true;
    }
    bool append(const std::string& line) {
        if (m_path.empty()) return true;   // in-memory (a KAT)
        std::lock_guard<std::mutex> lk(m_io_mu);   // the gate (listener thread) appends P concurrently
        std::FILE* f = std::fopen(m_path.c_str(), "a");
        if (!f) { ++m_write_fail; return false; }
        const std::string l = line + "\n";
        bool ok = std::fwrite(l.data(), 1, l.size(), f) == l.size() && std::fflush(f) == 0 && ::fsync(::fileno(f)) == 0;
        ok = (std::fclose(f) == 0) && ok;
        if (!ok) ++m_write_fail;
        return ok;
    }
    std::string m_path;
    std::map<std::string, std::vector<std::uint8_t>> m_own, m_frames;
    std::map<std::string, Delta> m_booked;
    mutable std::mutex m_pub_mu;
    std::map<std::string, std::uint64_t> m_pub;   // WRITE-AHEAD: bid -> h, our own published blocks
    std::mutex m_io_mu;
    std::atomic<std::uint64_t> m_write_fail{0};
};

// ── THE XMR BUNDLE: one per lane, owned by the shell ────────────────────────
class XmrDropsWiring {
public:
    // ★ THE DORMANCY GATE. nullptr unless the build took the consensus
    // activation AND the lane geometry carries the gate AND there is a share
    // difficulty to normalise against — the XMR twin of make_drops_wiring().
    static std::unique_ptr<XmrDropsWiring> make(const ::v37::LaneParams& p,
                                                std::uint64_t share_diff,
                                                std::uint64_t receipt_weight) {
        if constexpr (!::c2pool::v37n::kDropsWiringArmed) {
            (void)p; (void)share_diff; (void)receipt_weight;
            return nullptr;
        } else {
            if (!p.subthreshold.enabled || share_diff == 0 || receipt_weight == 0) return nullptr;
            return std::unique_ptr<XmrDropsWiring>(
                new XmrDropsWiring(p.subthreshold.K, share_diff, receipt_weight));
        }
    }
    // The same construction without the build gate, for a KAT that must drive
    // the gate-ON object inside a default (flip 0) build.
    static std::unique_ptr<XmrDropsWiring> make_for_test(std::uint32_t K, std::uint64_t share_diff,
                                                         std::uint64_t receipt_weight) {
        return std::unique_ptr<XmrDropsWiring>(new XmrDropsWiring(K, share_diff, receipt_weight));
    }

    XmrDropsWiring(const XmrDropsWiring&) = delete;
    XmrDropsWiring& operator=(const XmrDropsWiring&) = delete;

    std::uint64_t share_diff() const { return m_share_diff; }
    std::uint64_t floor_diff() const { return drops_floor_diff(m_share_diff); }
    std::uint64_t receipt_weight() const { return m_receipt_weight; }

    // ── (1) the clock: fed ONLY from the native tip ─────────────────────────
    void observe_native_tip(std::uint64_t tip_height) { m_core.observe_tip(open_bin_of_tip(tip_height)); }
    std::optional<std::uint64_t> now_interval() const { return m_core.now_interval(); }
    ::c2pool::v37n::EnrollOutcome enroll_at_tip(const bytes32& payee) { return m_core.enroll_at_tip(payee); }
    bool arm_at_tip() { return m_core.arm_at_tip(); }

    // ── the node seams ─────────────────────────────────────────────────────
    template <class Node>
    void attach(Node& node) {
        node.set_drop_harvester(&m_core.harvester());
        node.set_enrollment_book(&m_core.enrollment());
        node.set_pre_harvest(m_core.pre_harvest());
        node.set_drops_price_fn([this]() { return take_cut_price(); });
        if constexpr (requires { node.set_drops_carried_fn({}); })
            node.set_drops_carried_fn([this]() { return take_carried(); });   // ENROL-REPL
    }
    // ★ RAIN-BACKFILL: compose from the retained, chain-ordered harvest (6)
    // instead of the destructive take_buried(). Called by the shell right after
    // attach(); a node without it keeps the take_buried() body.
    template <class Node>
    void attach_chain_order(Node& node, std::uint64_t d_conf) {
        {
            std::lock_guard<std::mutex> lk(m_hmtx);
            m_chain_order = true;
            m_coh.set_d_conf(d_conf);
        }
        node.set_harvest_range_fn([this](std::uint64_t won_height) { return take_chain_ordered(won_height); });
    }
    bool chain_ordered() const { std::lock_guard<std::mutex> lk(m_hmtx); return m_chain_order; }
    // ★ RAIN-BACKFILL-2: the canonical chain's answer to "which lane block is
    // nearest below h" (ChainOrderedHarvest::PrevLaneFn). Unset => every height
    // is taken to be a lane block (prev_lane(h) = h - 1).
    void set_prev_lane_fn(ChainOrderedHarvest::PrevLaneFn f) {
        std::lock_guard<std::mutex> lk(m_hmtx);
        m_prev_lane = std::move(f);
    }
    std::optional<std::uint64_t> prev_lane(std::uint64_t won_height) const {
        ChainOrderedHarvest::PrevLaneFn f;
        { std::lock_guard<std::mutex> lk(m_hmtx); f = m_prev_lane; }   // asked OUTSIDE the lock (it may read the chain)
        if (f) return f(won_height);
        return won_height > 1 ? won_height - 1 : ChainOrderedHarvest::kNoPrevLane;
    }
    // the interval range the composition of a lane block won at h settles (the
    // HOLD's range); nullopt = the canonical predecessor is undecidable now
    std::optional<std::pair<std::uint64_t, std::uint64_t>> range_for(std::uint64_t won_height) const {
        const auto pl = prev_lane(won_height);
        std::lock_guard<std::mutex> lk(m_hmtx);
        return m_coh.range_with(won_height, pl);
    }
    ChainOrderedHarvest::Rows take_chain_ordered(std::uint64_t won_height) {
        const auto pl = prev_lane(won_height);
        std::lock_guard<std::mutex> lk(m_hmtx);
        const auto& book = m_core.shares();
        return m_coh.take(won_height, pl, [&book](std::uint64_t iv) { return book.covers(iv); }, &m_core.enrollment());
    }
    // diagnostic: (rows, inputs digest) of [lo, hi) as the retained set stands now (pure)
    std::pair<std::size_t, std::uint64_t> peek_rows(std::uint64_t lo, std::uint64_t hi) const {
        std::lock_guard<std::mutex> lk(m_hmtx);
        const auto& book = m_core.shares();
        const auto rows = m_coh.rows_over(lo, hi, [&book](std::uint64_t iv) { return book.covers(iv); }, &m_core.enrollment());
        return {rows.size(), m_coh.inputs_digest(lo, hi)};
    }
    struct ChainStats { std::uint64_t observed = 0, late = 0, withheld = 0, undecided = 0, floor = 0; std::size_t marks = 0, intervals = 0; std::uint64_t lo = 0, hi = 0; };
    ChainStats chain_stats() const {
        std::lock_guard<std::mutex> lk(m_hmtx);
        ChainStats c;
        c.observed = m_coh.observed(); c.late = m_coh.late(); c.withheld = m_coh.withheld();
        c.undecided = m_coh.undecided(); c.floor = m_coh.floor();
        c.marks = m_coh.marks(); c.intervals = m_coh.retained_intervals();
        c.lo = m_coh.last_range().first; c.hi = m_coh.last_range().second;
        return c;
    }

    template <class Node>
    static void detach(Node& node) {
        node.set_drop_harvester(nullptr);
        node.set_enrollment_book(nullptr);
        node.set_pre_harvest({});
        node.set_drops_price_fn({});
        if constexpr (requires { node.set_drops_carried_fn({}); }) node.set_drops_carried_fn({});
    }

    // ── ENROL-REPL: the carried delta the NEXT on_network_block_won books ──
    // Set by the shell's booking callback (the verified carried map, or {} for a
    // refused one); taken one-shot by the node, like the cut price. nullopt =>
    // the node composes locally (the pre-ENROL-REPL path; no carriage available).
    void set_carried(const std::map<bytes32, long long>& delta) {
        std::lock_guard<std::mutex> lk(m_pmtx);
        m_carried = delta;
    }
    void clear_carried() {
        std::lock_guard<std::mutex> lk(m_pmtx);
        m_carried.reset();
    }
    std::optional<std::map<bytes32, long long>> take_carried() {
        std::lock_guard<std::mutex> lk(m_pmtx);
        auto c = std::move(m_carried);
        m_carried.reset();
        return c;
    }

    // ── the price at the cut the NEXT on_network_block_won settles ──────────
    // Set by the shell's booking callback from the view it folded E_b from;
    // taken (one-shot) by the node inside on_network_block_won, so a win that
    // was not booked through a fold can never reuse a neighbour's price.
    void set_cut_price(const ::c2pool::v37n::settle::WorkPrice& wp) {
        std::lock_guard<std::mutex> lk(m_pmtx);
        m_price = rescale_price(wp, m_receipt_weight);
    }
    void clear_cut_price() {
        std::lock_guard<std::mutex> lk(m_pmtx);
        m_price = {};
    }
    ::c2pool::v37n::settle::WorkPrice take_cut_price() {
        std::lock_guard<std::mutex> lk(m_pmtx);
        auto p = m_price;
        m_price = {};
        if (p.valid) ++m_priced; else ++m_unpriced;
        return p;
    }

    // ── the two producers ──────────────────────────────────────────────────
    // A relay-admitted RAINDROP (own or peer): a RandomX hash that met the
    // floor but not share_diff. Returns false (and harvests nothing) for a hash
    // that is actually a share or is below the floor: never both, never twice.
    bool on_raindrop(const bytes32& payee_identity, std::uint64_t bin, const bytes32& pow_le) {
        const bytes32 n = normalized_hash(pow_le, m_share_diff);
        const unsigned lz = ::c2pool::v37n::leading_zero_bits(n);
        if (lz >= kXmrDropsLz) { ++m_refused_share; return false; }   // a SHARE: the lane path owns it
        ::c2pool::v37n::HarvestedDrop d;
        d.payee = payee_identity;
        d.interval = bin;
        d.hash = n;
        d.consensus_lz = kXmrDropsLz;
        d.own_lz = lz;
        {
            std::lock_guard<std::mutex> lk(m_hmtx);
            if (m_chain_order) { m_coh.observe_drop(payee_identity, bin, n); return true; }   // ★ RAIN-BACKFILL
        }
        m_drop_sink(d);
        return true;
    }
    // A relay receipt the lane just pushed: ONE share at (identity, origin bin).
    void on_share_pushed(const bytes32& payee_identity, std::uint64_t bin) {
        ::c2pool::v37n::EmittedPush p;
        p.identity = payee_identity;
        p.origin_bin = bin;
        p.carrier_bin = bin;
        p.w_raw = m_receipt_weight;
        {
            std::lock_guard<std::mutex> lk(m_hmtx);
            if (m_chain_order) { m_coh.observe_share(payee_identity, bin); return; }   // ★ RAIN-BACKFILL
        }
        m_share_tee(p);
    }

    // ── diagnostics (never consensus) ──────────────────────────────────────
    ::c2pool::v37n::DropsWiring& core() { return m_core; }
    const ::c2pool::v37n::DropsWiring& core() const { return m_core; }
    std::uint64_t priced() const { return m_priced; }
    std::uint64_t unpriced() const { return m_unpriced; }
    std::uint64_t refused_share() const { return m_refused_share; }

private:
    XmrDropsWiring(std::uint32_t K, std::uint64_t share_diff, std::uint64_t receipt_weight)
        : m_core(K, [](std::uint64_t) { return kXmrDropsLz; }),
          m_share_diff(share_diff), m_receipt_weight(receipt_weight), m_coh(K, kXmrDropsLz, 0) {
        m_drop_sink = m_core.drop_sink();
        m_share_tee = m_core.sink_filter()(::c2pool::v37n::RecordSink{});
    }

    ::c2pool::v37n::DropsWiring m_core;
    std::uint64_t m_share_diff = 0;
    std::uint64_t m_receipt_weight = 0;
    ::c2pool::v37n::DropSink   m_drop_sink;
    ::c2pool::v37n::RecordSink m_share_tee;
    mutable std::mutex m_pmtx;
    ::c2pool::v37n::settle::WorkPrice m_price{};
    std::optional<std::map<bytes32, long long>> m_carried{};   // ENROL-REPL one-shot
    std::uint64_t m_priced = 0, m_unpriced = 0, m_refused_share = 0;
    mutable std::mutex m_hmtx;          // ★ RAIN-BACKFILL
    bool m_chain_order = false;
    ChainOrderedHarvest m_coh;
    ChainOrderedHarvest::PrevLaneFn m_prev_lane{};   // ★ RAIN-BACKFILL-2
};

}  // namespace c2pool::v37n::xmr::drops
