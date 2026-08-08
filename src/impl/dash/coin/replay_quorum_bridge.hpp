// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ── THE FINAL SEAM: W4's derived quorum membership feeds W1's DML fold ─────
//
// W1 (replay_fold_engine.hpp) folds the deterministic masternode list and
// self-checks its merkleRootMNList against every block's own committed cbTx
// root. Its ONE unresolved input is `MembersFn`: when a mined qfcommit marks
// members invalid, dashd's punish loop
// (specialtxman.cpp:159-174 → HandleQuorumCommitment) needs the ORDERED
// member list of that quorum to attribute `PoSePunish` by bitset index. W1
// fails closed without a resolver, by design.
//
// W4 (replay_quorum_engine.hpp) derives exactly that list from replayed chain
// bytes — including the DIP-0024 quarter-rotation port and the CQuorumSnapshot
// PRODUCER that makes the qrinfo P2P port unnecessary. Its ONE unresolved
// input is `MnListAtFn`: the masternode list at a quorum's WORK block
// (cycle base − 8).
//
// The two holes are each other's answer. This class closes the loop:
//
//        DmlFoldEngine ──(MN list at work blocks)──▶ QuorumReplayEngine
//              ▲                                             │
//              └────────────(ordered member sets)────────────┘
//
// and nothing else is supplied. Membership stops being an anchor-fed input
// and becomes a function of the same replayed blocks the fold consumes.
//
// ── The measured seam this exists to close ────────────────────────────────
//
// The first live daemonless replay (2026-08-05, LAN archival peer VM210)
// folded 129 consecutive byte-exact roots from anchor 2513000 and then failed
// closed, loudly, at h=2513130 — the first mined commitment on mainnet in
// that window that actually marks members invalid (llmqType=5, the rotated
// llmq_60_75). Its stop height had been PREDICTED by a static scan before the
// run. That commitment is the seam's acceptance test: it must now resolve
// through DERIVED membership.
//
// ── Ordering (load-bearing) ───────────────────────────────────────────────
//
// Per delivered block H, in this order:
//
//   1. quorum.observe_block(H)  — registers H's hash, derives any cycle whose
//      base is H (consuming the retained MN list at H−8), folds
//      merkleRootQuorums, ingests H's own commitments.
//   2. dml.fold_block(H)        — the punish pass calls members_for(), which
//      is now answered from (1)'s derivations.
//   3. retain the MN list at H iff H is a work block for some enabled type.
//
// A commitment mined at H always names a base < H (the DKG mining window
// starts at base + dkgMiningWindowStart ≥ 10), so (1) has always already run
// for that base by the time (2) needs it.
//
// ── What is still seeded, stated plainly ──────────────────────────────────
//
// Rotated membership at cycle base B is a function of the new quarter built
// at B plus the THREE PREVIOUS cycles' snapshots (B−C, B−2C, B−3C). Those
// snapshots are produced by the replay itself from B onward — but the first
// three cycles after an anchor have no produced predecessor, so a Phase-1 run
// seeds them (design doc §3 "seeded at the Phase-1 anchor, self-produced
// thereafter"; §4.5 Phase 1). A CQuorumSnapshot is a skip-list mode + an
// active-member bitset — it is NOT a member set: the member lists themselves,
// including the h=2513130 one, are computed here from the replayed DML.
// Phase 2 (genesis replay) retires even the snapshot seed.
//
// The seed is bounded and self-limiting: seeding cycles that the replay could
// itself produce is refused (see seed_snapshots()), so a seed can never mask
// a derivation that stopped working.

#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/replay_quorum_engine.hpp>
#include <impl/dash/coin/dkg_commitments.hpp>
#include <impl/dash/coin/vendor/quorum_rotation_info.hpp>
#include <impl/dash/coin/vendor/quorum_members.hpp>   // compute_quorum_modifier

#include <core/log.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {
namespace replay {

// ═══════════════════════════════════════════════════════════════════════════
// Pre-anchor snapshot seed (Phase-1 only)
// ═══════════════════════════════════════════════════════════════════════════

inline constexpr const char* kQSnapshotSeedMagic =
    "c2pool-dash-replay-qsnapshot/1";

/// One seeded per-cycle snapshot: (llmqType, cycle base) → CQuorumSnapshot.
struct QSnapshotSeedEntry {
    uint8_t                 llmq_type{0};
    uint32_t                cycle_base{0};
    vendor::CQuorumSnapshot snapshot;
};

struct QSnapshotSeed {
    bool                            ok{false};
    std::string                     error;      // populated iff !ok
    std::string                     network;
    std::vector<QSnapshotSeedEntry> entries;
};

/// Parse the seed text emitted by `tools/dash/gen_replay_kat.py qsnapshot`
/// (from a dashd `quorum rotationinfo` capture). Fail-closed and NAMED: a
/// half-read snapshot would silently produce wrong members, and wrong members
/// silently mis-attribute PoSe punishes.
///
///     c2pool-dash-replay-qsnapshot/1
///     network mainnet
///     snapshot <llmqType> <cycleBase> <mode> <activeBits 0/1 string> <nSkip> [skip…]
inline QSnapshotSeed parse_qsnapshot_seed_text(const std::string& text)
{
    QSnapshotSeed seed;
    auto fail = [&](const std::string& why) -> QSnapshotSeed& {
        seed.ok = false;
        seed.error = why;
        seed.entries.clear();
        return seed;
    };

    std::istringstream is(text);
    std::string line;
    if (!std::getline(is, line)) return fail("qsnapshot seed is empty");
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.pop_back();
    if (line != kQSnapshotSeedMagic)
        return fail("qsnapshot seed format tag is '" + line + "', expected '"
                    + kQSnapshotSeedMagic + "'");

    size_t lineno = 1;
    while (std::getline(is, line)) {
        ++lineno;
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ls(line);
        std::string kw;
        ls >> kw;
        if (kw == "network") {
            ls >> seed.network;
            continue;
        }
        if (kw != "snapshot")
            return fail("qsnapshot seed line " + std::to_string(lineno)
                        + ": unknown keyword '" + kw + "'");

        QSnapshotSeedEntry e;
        int      type = -1;
        uint32_t base = 0;
        int      mode = -1;
        std::string bits;
        long long   nskip = -1;
        ls >> type >> base >> mode >> bits >> nskip;
        if (!ls || type < 0 || type > 255 || base == 0 || nskip < 0)
            return fail("qsnapshot seed line " + std::to_string(lineno)
                        + ": malformed snapshot record");
        e.llmq_type  = static_cast<uint8_t>(type);
        e.cycle_base = base;
        e.snapshot.mnSkipListMode = mode;
        if (bits != "-") {
            e.snapshot.activeQuorumMembers.reserve(bits.size());
            for (char c : bits) {
                if (c != '0' && c != '1')
                    return fail("qsnapshot seed line " + std::to_string(lineno)
                                + ": activeQuorumMembers bitset carries '"
                                + std::string(1, c) + "' (expected 0/1)");
                e.snapshot.activeQuorumMembers.push_back(c == '1');
            }
        }
        for (long long i = 0; i < nskip; ++i) {
            long long v = 0;
            ls >> v;
            if (!ls)
                return fail("qsnapshot seed line " + std::to_string(lineno)
                            + ": declared " + std::to_string(nskip)
                            + " skip entries but only "
                            + std::to_string(i) + " are present");
            e.snapshot.mnSkipList.push_back(static_cast<int32_t>(v));
        }
        {
            long long extra = 0;
            if (ls >> extra)
                return fail("qsnapshot seed line " + std::to_string(lineno)
                            + ": trailing token after the declared skip list");
        }
        if (!e.snapshot.sane())
            return fail("qsnapshot seed line " + std::to_string(lineno)
                        + ": CQuorumSnapshot fails its own sanity bounds "
                          "(mode/size)");
        seed.entries.push_back(std::move(e));
    }
    if (seed.entries.empty())
        return fail("qsnapshot seed carries no snapshot records");
    seed.ok = true;
    return seed;
}

inline QSnapshotSeed load_qsnapshot_seed_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        QSnapshotSeed s;
        s.error = "cannot open qsnapshot seed file '" + path + "'";
        return s;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return parse_qsnapshot_seed_text(ss.str());
}

// ═══════════════════════════════════════════════════════════════════════════
// Pre-anchor WORK-BLOCK list seed (Phase-1 only)
// ═══════════════════════════════════════════════════════════════════════════
//
// Why this exists, stated exactly, because it bounds the honesty of the whole
// claim:
//
// A rotated cycle at base B is derivable from (snapshots at B−C, B−2C, B−3C)
// + (MN lists at B−8, B−C−8, B−2C−8, B−3C−8). Snapshots may be seeded; lists
// come from the replayed DML. With an anchor at X, the FIRST cycle whose
// members a replay is asked for is the first batch mined after X — whose base
// B0 satisfies B0 − X < C. Deriving it needs lists reaching back to
// B0 − 3C − 8, i.e. ~3 cycles BEFORE the anchor. No choice of X escapes that:
// moving X back moves B0 back with it. So a Phase-1 rotated lane needs, once,
// the MN list at three pre-anchor work heights — after which the recurrence
// closes and every later cycle is self-produced.
//
// These lists are the SAME trust class as the anchor prestate (a full MN list
// at a height), and strictly less than an anchor-supplied member set: they are
// an input to the quarter-rotation, not its output. From the first fully
// self-contained cycle onward (see ReplayQuorumBridge::self_contained_from())
// nothing seeded is read at all.

inline constexpr const char* kWorkListSeedMagic =
    "c2pool-dash-replay-seam-workblocks/1";

struct WorkListSeedEntry {
    uint32_t                   work_height{0};
    uint32_t                   cycle_base{0};
    uint256                    block_hash;      // display-hex in the file
    bool                       has_cl{false};
    std::array<uint8_t, vendor::CCbTx::BLS_SIG_SIZE> cl_sig{};
    std::vector<QuorumMnEntry> entries;
};

struct WorkListSeed {
    bool        ok{false};
    std::string error;
    std::string network;
    uint8_t     llmq_type{0};
    uint32_t    cycle_base{0};
    uint32_t    interval{0};
    std::vector<WorkListSeedEntry> works;
};

namespace bridgedetail {

inline bool hex_bytes(const std::string& h, std::vector<uint8_t>& out)
{
    if (h.empty() || h.size() % 2 != 0) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    out.reserve(h.size() / 2);
    for (size_t i = 0; i < h.size(); i += 2) {
        const int hi = nib(h[i]), lo = nib(h[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

inline bool u256_wire(const std::string& h, uint256& out)
{
    std::vector<uint8_t> b;
    if (!hex_bytes(h, b) || b.size() != 32) return false;
    std::memcpy(out.data(), b.data(), 32);
    return true;
}

} // namespace bridgedetail

/// Parse the fixture `tools/dash/gen_replay_kat.py seamwork` emits. The `mn`
/// records come from `protx diff 1 <workHeight>` — a DIP-4 SML, which carries
/// no collateral outpoint, so `has_collateral` stays false and an upstream
/// score TIE fails the derivation closed rather than guessing (same posture as
/// the W4 KATs; the replay-fed lists the live path uses DO carry it).
inline WorkListSeed parse_work_list_seed_text(const std::string& text)
{
    WorkListSeed seed;
    auto fail = [&](const std::string& why) -> WorkListSeed& {
        seed.ok = false;
        seed.error = why;
        seed.works.clear();
        return seed;
    };
    std::istringstream is(text);
    std::string line;
    if (!std::getline(is, line)) return fail("work-list seed is empty");
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.pop_back();
    if (line != kWorkListSeedMagic)
        return fail("work-list seed format tag is '" + line + "', expected '"
                    + kWorkListSeedMagic + "'");

    size_t lineno = 1;
    long long want = -1;   // remaining mn records for the open `work` section
    while (std::getline(is, line)) {
        ++lineno;
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ls(line);
        std::string kw;
        ls >> kw;
        if (kw == "network")   { ls >> seed.network;  continue; }
        if (kw == "llmqType")  { int t = 0; ls >> t;
                                 seed.llmq_type = static_cast<uint8_t>(t);
                                 continue; }
        if (kw == "cycleBase") { ls >> seed.cycle_base; continue; }
        if (kw == "interval")  { ls >> seed.interval;   continue; }
        if (kw == "work") {
            if (want > 0)
                return fail("work-list seed line " + std::to_string(lineno)
                            + ": previous work section is short by "
                            + std::to_string(want) + " mn record(s)");
            WorkListSeedEntry w;
            std::string bh, cl;
            long long count = -1;
            ls >> w.cycle_base >> w.work_height >> bh >> cl >> count;
            if (!ls || count < 0 || w.work_height == 0)
                return fail("work-list seed line " + std::to_string(lineno)
                            + ": malformed work header");
            {
                std::vector<uint8_t> hb;
                if (!bridgedetail::hex_bytes(bh, hb) || hb.size() != 32)
                    return fail("work-list seed line "
                                + std::to_string(lineno)
                                + ": work block hash is not 32-byte hex");
                w.block_hash.SetHex(bh);   // display hex, as the file states
            }
            if (cl != "-") {
                std::vector<uint8_t> b;
                if (!bridgedetail::hex_bytes(cl, b)
                        || b.size() != vendor::CCbTx::BLS_SIG_SIZE)
                    return fail("work-list seed line "
                                + std::to_string(lineno)
                                + ": bestCLSignature is not a "
                                + std::to_string(vendor::CCbTx::BLS_SIG_SIZE)
                                + "-byte hex blob");
                std::memcpy(w.cl_sig.data(), b.data(), b.size());
                w.has_cl = true;
            }
            w.entries.reserve(static_cast<size_t>(count));
            seed.works.push_back(std::move(w));
            want = count;
            continue;
        }
        if (kw != "mn")
            return fail("work-list seed line " + std::to_string(lineno)
                        + ": unknown keyword '" + kw + "'");
        if (seed.works.empty() || want <= 0)
            return fail("work-list seed line " + std::to_string(lineno)
                        + ": mn record outside a declared work section");
        std::string protx, chash;
        int valid = -1, ntype = -1;
        ls >> protx >> chash >> valid >> ntype;
        if (!ls || (valid != 0 && valid != 1) || ntype < 0)
            return fail("work-list seed line " + std::to_string(lineno)
                        + ": malformed mn record");
        QuorumMnEntry e;
        if (!bridgedetail::u256_wire(protx, e.proTxHash)
                || !bridgedetail::u256_wire(chash, e.confirmedHash))
            return fail("work-list seed line " + std::to_string(lineno)
                        + ": proTxHash/confirmedHash are not 32-byte wire hex");
        e.is_valid       = (valid == 1);
        e.n_type         = static_cast<uint16_t>(ntype);
        e.has_collateral = false;   // SML-fed: tie is undecidable, fail closed
        seed.works.back().entries.push_back(std::move(e));
        --want;
    }
    if (want > 0)
        return fail("work-list seed ends with the last work section short by "
                    + std::to_string(want) + " mn record(s)");
    if (seed.works.empty())
        return fail("work-list seed carries no work sections");
    seed.ok = true;
    return seed;
}

inline WorkListSeed load_work_list_seed_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        WorkListSeed s;
        s.error = "cannot open work-list seed file '" + path + "'";
        return s;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return parse_work_list_seed_text(ss.str());
}

// ═══════════════════════════════════════════════════════════════════════════
// The bridge
// ═══════════════════════════════════════════════════════════════════════════

struct QuorumBridgeConfig {
    /// Which chainparams llmq table the snapshot-seed guard reads.
    LlmqNetwork network{LlmqNetwork::Mainnet};
    /// Stride at which the replayed MN list is retained for work-block
    /// lookups. Every enabled mainnet dkgInterval (24, 288, 576) is a
    /// multiple of 24, so retaining at `(H + kWorkDiffDepth) % 24 == 0`
    /// covers every work block of every type with no per-type table.
    uint32_t work_stride{24};
    /// How far back retained lists are kept. Rotated derivation reaches
    /// 3 cycles (3 × 288 = 864) plus the work offset; the default keeps a
    /// comfortable multiple of that and is bounded, so a genesis-length run
    /// cannot grow without limit.
    uint32_t keep_blocks{2048};
    bool     debug_logs{false};
};

/// Closes the W1↔W4 loop. Holds no consensus state of its own: it owns the
/// bounded work-block list cache and the two lambdas the engines exchange.
class ReplayQuorumBridge
{
public:
    ReplayQuorumBridge(DmlFoldEngine& dml, QuorumReplayEngine& quorum,
                       QuorumBridgeConfig cfg = {})
        : m_dml(dml), m_quorum(quorum), m_cfg(cfg)
    {
        if (m_cfg.work_stride == 0) m_cfg.work_stride = 24;
        // The engines' seams, installed both ways. From here on neither
        // engine has an unresolved input.
        m_quorum.set_mn_list_at_fn(
            [this](uint32_t h) { return this->mn_list_at(h); });
        m_dml.set_members_fn(
            [this](uint8_t type, const uint256& qh) {
                return this->members_for(type, qh);
            });
    }

    ReplayQuorumBridge(const ReplayQuorumBridge&) = delete;
    ReplayQuorumBridge& operator=(const ReplayQuorumBridge&) = delete;

    // ── Counters (report surface; never a gate) ──────────────────────────
    struct Stats {
        uint64_t blocks_observed{0};
        uint64_t member_cycles_derived{0};
        uint64_t member_cycles_skipped{0};
        uint64_t members_answered{0};     // resolver hits the fold consumed
        uint64_t members_missing{0};      // resolver misses (fold fails closed)
        uint64_t lists_retained{0};
        uint64_t quorum_roots_matched{0}; // informational: folded == committed
        uint64_t quorum_roots_differed{0};
        /// Height at which the root self-check ARMED (0 = never). Issue #90:
        /// while this is 0 the matched/differed pair is a warm-up artefact and
        /// must not be read as divergence; from this height on it is a real
        /// consensus comparison and a differ POISONS the lane.
        uint32_t self_check_armed_at{0};
        std::string last_skip_reason;
        std::string first_member_miss;    // the named first miss, verbatim
    };
    const Stats& stats() const { return m_stats; }

    /// Issue #90, the reporting half: WHY the self-check is still unarmed.
    /// Never a bare bool — the counter that gates it reads 0/N forever on
    /// mainnet and the reason (24 frozen LLMQ_50_60 commitments no forward
    /// replay can observe) is not inferable from the number.
    std::string active_set_shortfall_text() const
    {
        return m_quorum.active_set_shortfall_text();
    }

    /// Seed per-cycle rotated snapshots (Phase-1 only).
    ///
    /// The guard is the whole point of this function. A rotated cycle at base
    /// B is PRODUCIBLE by the replay exactly when its three predecessors
    /// (B−C, B−2C, B−3C) are themselves at or after the anchor — i.e. when
    /// B ≥ anchor + 3C. Seeding such a cycle would let trusted input stand in
    /// for a derivation the replay owes, hiding a broken quarter-rotation
    /// behind an answer key. That is refused, by name.
    ///
    /// Below that line the replay genuinely cannot produce the snapshot (its
    /// inputs predate the anchor), which is what "Phase-1 anchor-class seed"
    /// means in the design doc. Non-rotated types need no snapshot at all and
    /// are refused outright.
    bool seed_snapshots(const QSnapshotSeed& seed, uint32_t anchor_height,
                        std::string& err)
    {
        if (!seed.ok) { err = seed.error; return false; }
        for (const auto& e : seed.entries) {
            const LlmqParamsView* p =
                replay_llmq_params(m_cfg.network, e.llmq_type);
            if (p == nullptr) {
                err = "qsnapshot seed names llmqType "
                    + std::to_string(int(e.llmq_type))
                    + " which is not in this network's chainparams llmq list";
                return false;
            }
            if (!p->use_rotation) {
                err = "qsnapshot seed names llmqType "
                    + std::to_string(int(e.llmq_type))
                    + " which is NOT rotated — non-rotated membership is "
                      "computed from the replayed list alone and needs no "
                      "snapshot; seeding one could only mislead";
                return false;
            }
            const uint32_t producible_from =
                anchor_height + 3u * p->dkg_interval;
            if (e.cycle_base >= producible_from) {
                err = "qsnapshot seed names cycle base h="
                    + std::to_string(e.cycle_base) + " (type "
                    + std::to_string(int(e.llmq_type))
                    + "), but with anchor h=" + std::to_string(anchor_height)
                    + " and dkgInterval " + std::to_string(p->dkg_interval)
                    + " every cycle from h=" + std::to_string(producible_from)
                    + " onward has all three predecessors inside the replay "
                      "and is the replay's to PRODUCE — seeding it would hide "
                      "a broken derivation behind trusted input";
                return false;
            }
            m_quorum.seed_snapshot(e.llmq_type, e.cycle_base, e.snapshot);
            ++m_seeded_snapshots;
        }
        return true;
    }
    size_t seeded_snapshot_count() const { return m_seeded_snapshots; }

    /// Seed the MN list at PRE-ANCHOR work heights (see the header note).
    /// REFUSES any height at or after the anchor — those the replay folds
    /// itself, and a seed winning there would mask a broken fold.
    bool seed_work_lists(const WorkListSeed& seed, uint32_t anchor_height,
                         std::string& err)
    {
        if (!seed.ok) { err = seed.error; return false; }
        for (const auto& w : seed.works) {
            if (w.work_height >= anchor_height) {
                // Not an error: the file legitimately carries the whole cycle
                // set, and the post-anchor members of it are the REPLAY's.
                ++m_skipped_post_anchor_work_lists;
                continue;
            }
            m_lists[w.work_height] = w.entries;
            m_seeded_work_heights.push_back(w.work_height);
            // The modifier at this cycle base reads the work block's own hash
            // and cbTx CL — chain data, registered the same way an observed
            // block would register it.
            m_quorum.seed_block_hash(w.work_height, w.block_hash);
            std::optional<std::array<uint8_t, vendor::CCbTx::BLS_SIG_SIZE>> cl;
            if (w.has_cl) cl = w.cl_sig;
            m_quorum.seed_work_block_cl(w.work_height, cl);
            // The cycle's hash modifier is COMPUTED here from those two chain
            // fields (GetHashModifier, llmq/utils.cpp:88-111) — not seeded.
            // Without it the pre-anchor cycle would be skipped by name and
            // the first post-anchor cycle would stay underivable.
            m_quorum.seed_modifier(
                seed.llmq_type, w.cycle_base,
                vendor::compute_quorum_modifier(seed.llmq_type, w.work_height,
                                                cl, w.block_hash));
            ++m_seeded_work_lists;
        }
        if (m_seeded_work_lists == 0) {
            err = "work-list seed carries no PRE-anchor work section (anchor h="
                + std::to_string(anchor_height)
                + ") — nothing to seed, and the first rotated cycle after the "
                  "anchor would stay underivable";
            return false;
        }
        return true;
    }
    size_t seeded_work_list_count() const { return m_seeded_work_lists; }

    /// The height from which the rotated lane reads NOTHING seeded: the
    /// earliest cycle base whose own three predecessors are all at or after
    /// the anchor. Reported so a run states, in one number, where its
    /// membership becomes fully self-contained.
    uint32_t self_contained_from(uint8_t llmq_type, uint32_t anchor_height) const
    {
        const LlmqParamsView* p =
            replay_llmq_params(m_cfg.network, llmq_type);
        if (p == nullptr || !p->use_rotation) return anchor_height;
        const uint32_t C = p->dkg_interval;
        uint32_t base = ((anchor_height + 3u * C + C - 1u) / C) * C;
        return base;
    }

    /// Retain the MN list AT the anchor (the fold is seeded there, so the
    /// list exists before any block is observed) and register the anchor in
    /// the quorum engine's height window. Call once, right after seeding.
    void prime_at_anchor()
    {
        retain_list_at(m_dml.height());
    }

    /// Register a historical height→hash mapping so a commitment mined just
    /// after the anchor, whose quorum BASE predates it, still resolves. Fed
    /// from the (PoW-verified) header chain, never from a peer's say-so.
    void seed_block_hash(uint32_t height, const uint256& hash)
    {
        m_quorum.seed_block_hash(height, hash);
    }

    /// Step 1 of the per-block order. Returns a named error on refusal; the
    /// caller decides whether that stops the run (it does not have to: a
    /// quorum-lane miss only costs the fold its member sets, and the fold
    /// then fails closed on its own terms at the block that needs them).
    std::string observe(uint32_t height, const uint256& hash,
                        const BlockType& block)
    {
        std::string err;
        auto in = QuorumReplayEngine::input_from_block(block, height, hash,
                                                       &err);
        if (!in)
            return "quorum input build failed at h=" + std::to_string(height)
                 + ": " + err;

        const auto r = m_quorum.observe_block(*in);
        ++m_stats.blocks_observed;
        m_stats.member_cycles_derived += r.member_cycles_derived;
        m_stats.member_cycles_skipped += r.member_cycles_skipped;
        if (!r.member_skip_reasons.empty())
            m_stats.last_skip_reason = r.member_skip_reasons.back();
        if (r.self_checked || !r.committed_root.IsNull()) {
            if (r.computed_root == r.committed_root)
                ++m_stats.quorum_roots_matched;
            else
                ++m_stats.quorum_roots_differed;
        }
        // ── ISSUE #90: the arming criterion finally has a caller ──────────
        // replay_quorum_engine.hpp documented "callers arm it once the
        // commitment store is complete (… a warm-from-scan harness — once
        // every type has reached its active quota)". Nothing ever did, so
        // fold_root_vs_committed ran UNARMED for the life of every run and
        // reported 0/N — a counter that could not disagree with anything.
        //
        // Arm it the moment the reconstructed active set IS dashd's set. From
        // that block on the comparison is a real consensus check and a
        // mismatch poisons the lane, which is the whole point.
        //
        // On MAINNET this will not fire, and that is a FACT about the chain,
        // not a bug here: LLMQ_50_60's last 24 commitments were mined before
        // DIP0024 and stay in dashd's active set forever, so a forward replay
        // from a modern anchor is permanently short by 24. The shortfall is
        // now NAMED (active_set_shortfall_text()) instead of being an
        // unexplained zero.
        if (!m_quorum.self_check_armed() && m_quorum.active_sets_complete()) {
            m_quorum.arm_self_check();
            m_stats.self_check_armed_at = height;
            LOG_INFO << "[REPLAY-SEAM] quorum-root SELF-CHECK ARMED at h="
                     << height
                     << ": every chainparams llmq type has reached its full"
                        " active quota, so the reconstructed active set IS"
                        " dashd's set. fold_root_vs_committed is a consensus"
                        " comparison from here on; a differ now POISONS the"
                        " lane. Warm-up counts before this height: matched="
                     << m_stats.quorum_roots_matched << " differed="
                     << m_stats.quorum_roots_differed;
            m_stats.quorum_roots_matched  = 0;
            m_stats.quorum_roots_differed = 0;
        }
        if (m_cfg.debug_logs && r.member_cycles_derived > 0)
            LOG_INFO << "[REPLAY-SEAM] h=" << height << " derived "
                     << r.member_cycles_derived << " member cycle(s)";
        if (!r.ok) return r.error;
        return {};
    }

    /// Whether the engine's root SELF-CHECK is armed. Diagnostics only, and
    /// it is the difference between two opposite readings of the SAME
    /// counters: armed, quorum_roots_differed is a real divergence count;
    /// UNARMED (no production caller has ever invoked arm_self_check(), and a
    /// Tier-A anchor seeds no active quorum set) the computed root is a
    /// warm-up artefact that differs at essentially every height by
    /// construction — which is how a `0/4684` line came to read as a
    /// 4684-block divergence when the SERVED root was correct at 154/154
    /// shadow matches. The reporting site MUST say which of the two it is.
    bool self_check_armed() const { return m_quorum.self_check_armed(); }

    /// Step 3 of the per-block order. Retains the replayed list at H when H
    /// is a work block for some enabled type, and prunes the cache.
    void after_fold(uint32_t height)
    {
        if ((height + kWorkDiffDepth) % m_cfg.work_stride == 0)
            retain_list_at(height);
        prune(height);
    }

    /// Exposed for tests and for callers that want the seam without the
    /// consumer plumbing.
    std::optional<std::vector<QuorumMnEntry>> mn_list_at(uint32_t height) const
    {
        auto it = m_lists.find(height);
        if (it == m_lists.end()) return std::nullopt;
        return it->second;
    }

    std::optional<std::vector<uint256>> members_for(uint8_t llmq_type,
                                                    const uint256& quorum_hash)
    {
        auto m = m_quorum.members_for(llmq_type, quorum_hash);
        if (m) {
            ++m_stats.members_answered;
            return m;
        }
        ++m_stats.members_missing;
        if (m_stats.first_member_miss.empty())
            m_stats.first_member_miss =
                "llmqType=" + std::to_string(int(llmq_type)) + " quorumHash="
                + quorum_hash.GetHex().substr(0, 16)
                + " has no DERIVED member set (the quorum lane never "
                  "reached that cycle base)";
        return std::nullopt;
    }

    size_t retained_lists() const { return m_lists.size(); }

    /// dashd CDeterministicMN → the member-computation view. Carries the
    /// collateral outpoint, so the upstream score TIEBREAK
    /// (llmq/utils.cpp CalculateQuorum) is decidable — an SML-fed list
    /// cannot do this and must fail closed on a tie.
    static QuorumMnEntry to_quorum_entry(const uint256& protx,
                                         const ReplayMNState& st)
    {
        QuorumMnEntry e;
        e.proTxHash        = protx;
        e.confirmedHash    = st.confirmedHash;
        e.is_valid         = !st.IsBanned();
        e.n_type           = st.nType;
        e.pub_key_operator = st.pubKeyOperator;
        e.has_collateral   = true;
        e.collateral_hash  = st.collateralOutpoint.hash;
        e.collateral_index = st.collateralOutpoint.index;
        return e;
    }

private:
    void retain_list_at(uint32_t height)
    {
        std::vector<QuorumMnEntry> list;
        list.reserve(m_dml.entries().size());
        for (const auto& [protx, st] : m_dml.entries())
            list.push_back(to_quorum_entry(protx, st));
        m_lists[height] = std::move(list);
        ++m_stats.lists_retained;
    }

    void prune(uint32_t height)
    {
        if (height <= m_cfg.keep_blocks) return;
        const uint32_t floor = height - m_cfg.keep_blocks;
        for (auto it = m_lists.begin(); it != m_lists.end();) {
            if (it->first >= floor) break;   // std::map is ordered
            // A seeded pre-anchor work list is not replaceable — it can never
            // be re-derived — so it is pinned for the life of the run.
            if (std::find(m_seeded_work_heights.begin(),
                          m_seeded_work_heights.end(), it->first)
                    != m_seeded_work_heights.end()) { ++it; continue; }
            it = m_lists.erase(it);
        }
    }

    DmlFoldEngine&      m_dml;
    QuorumReplayEngine& m_quorum;
    QuorumBridgeConfig  m_cfg;
    std::map<uint32_t, std::vector<QuorumMnEntry>> m_lists;
    std::vector<uint32_t> m_seeded_work_heights;
    Stats  m_stats;
    size_t m_seeded_snapshots{0};
    size_t m_seeded_work_lists{0};
    size_t m_skipped_post_anchor_work_lists{0};
};

} // namespace replay
} // namespace coin
} // namespace dash
