// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// THE PoSe PENALTY ORACLE, LIVE (design PR-B §4.2): the bridge DML fold
/// engine driven to the chain tip and KEPT there, so the serve-time PoSe pass
/// (sml_pose_fold.hpp, PR-A) can ask it for certainty bounds on
/// nPoSePenalty(H-1) of the members a template's real commitments punish.
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHY A FEEDER (the three production caps this closes)
/// ─────────────────────────────────────────────────────────────────────────
///  1. STRADDLE. The engine is seeded at a cursor S (the release anchor, or
///     a resumed snapshot). Quorums whose base or work block predate S but
///     whose commitments are mined after S have no derivable member set, so
///     the first PUNISHING such commitment failed the fold closed — the
///     production store capped at h=2549417 (anchor 2549400 + type-4 window).
///  2. NO TIP FEED. The engine was fed only by the MN-CKPT lane's
///     on_block_applied, which stops the moment the lane publishes: the
///     engine could never STAY at tip even had it reached it.
///  3. NO RESUME. Every restart re-seeded from the anchor (and a lane that
///     resumed its own cursor never re-ran the anchor fold at all, leaving
///     the engine unseeded for the whole run).
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHAT IT DOES
/// ─────────────────────────────────────────────────────────────────────────
///  * INTAKE: every connected block (Node::block_connected — the lane's
///    bridge bodies AND the live tip), hash-checked against our PoW header
///    chain at its height (a fork body is dropped), buffered (bounded) and
///    folded strictly in order from the engine cursor. Heights nobody else
///    fetches are requested here (bounded window, refetch on timeout).
///  * HOLD, NEVER POISON FOR I/O: before folding block h the commitments in
///    h that punish (non-null, a member marked invalid) must have a
///    resolvable member set (bridge: derived, else the serve path's
///    authenticated member source via the fallback, which is kicked on a
///    miss — request-on-miss). Unresolved => the block WAITS; the oracle is
///    then simply not at tip (the PoSe pass refuses, today's fail-closed).
///  * STRADDLE BOOTSTRAP at S (deferred, live, no release artifact):
///      - rotated (DIP-24): cyc1 = first cycle base whose work block is after
///        S, cyc0 = cyc1 - C. getqrinfo(cyc0, extraShare) is DIP-4-authenticated
///        (every leg bound to its height and our PoW headers) and seeds the
///        three predecessor snapshots + the four work lists; cyc0 is then
///        derived by the engine's OWN quarter-rotation (out of band if
///        cyc0 <= S, at observe otherwise), which also PRODUCES cyc0's snapshot,
///        so cyc1, cyc1+C, ... derive by the ordinary recurrence.
///      - non-rotated: for every base B with B - 8 <= S whose mining window
///        reaches past S, the work-block list at B - 8 (getmnlistd(ZERO,
///        hash(B-8)), DIP-4-authenticated); cyc0's own work list comes from
///        the qrinfo H leg.
///      - pre-S block hashes from the header chain (seeded once the chain
///        holds them), so the quorum engine can resolve a commitment's base.
///      - headers BELOW the fast-start anchor (anchor straddle only) come
///        from the pre-anchor backfill: a getheaders whose locator is a
///        qrinfo reply's H-4C leg, installed DOWNWARD from the trusted anchor
///        (HeaderChain::install_preanchor_span — prev-link + PoW). When cyc0's
///        own hash is below the anchor, getqrinfo(cyc1) supplies the first
///        locator; cyc0's reply then supplies the deeper one its H-3C leg needs.
///  * PERSIST + RESUME (operator Q5): a v4 snapshot under the data dir every
///    persist_every_tip blocks at tip (persist_every_catchup while catching
///    up); at start it is resumed iff its (height, hash) is on our header
///    chain, else discarded for an anchor re-seed. The straddle bootstrap
///    then re-runs at the resumed cursor.
///  * REORG: in-memory snapshots of the last few tip folds; a cursor whose
///    hash left the best chain rolls back to the newest one still on it
///    (else the file, else an anchor re-seed).
///  * ANCHOR SEED: the lane's anchor fold (DIP-4-authenticated SML) when the
///    lane runs cold; otherwise (lane resumed its own cursor) the feeder's
///    own getmnlistd(ZERO, anchor) after a grace period.
///
/// ─────────────────────────────────────────────────────────────────────────
/// THE ORACLE CONTRACT
/// ─────────────────────────────────────────────────────────────────────────
/// oracle_bounds(prev_h, prev_hash, proTx) answers ONLY when the engine is
/// seeded, unpoisoned and its cursor IS (prev_h, prev_hash) — the post-state
/// of the block the template builds on. Every fold that advanced the cursor
/// passed the per-block merkleRootMNList self-check, so the held list is
/// dashd's on every committed field and lo <= nPoSePenalty <= hi.
///
/// THREADING: confined to the single io_context thread main_dash runs (the
/// same thread as the MN-CKPT lane, NodeCoinState and the template build), so
/// no lock exists and none is needed; an oracle read can never interleave a
/// fold. A long catch-up never blocks that thread for long: at most
/// fold_budget folds per turn, the rest re-posted.

#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/replay_quorum_engine.hpp>
#include <impl/dash/coin/replay_quorum_bridge.hpp>
#include <impl/dash/coin/historical_sml.hpp>
#include <impl/dash/coin/dkg_commitments.hpp>
#include <impl/dash/coin/vendor/quorum_rotation_info.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/vendor/smldiff.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>

#include <core/log.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {
namespace replay {

struct PoseOracleConfig
{
    LlmqNetwork network{LlmqNetwork::Mainnet};
    std::string net_name{"mainnet"};
    uint32_t    anchor_height{0};
    uint256     anchor_hash;
    /// v4 snapshot file; empty => no persistence (and no resume).
    std::string snapshot_path;

    uint32_t fetch_window{128};          // heights requested ahead of the cursor
    uint32_t fetch_grace_ms{10000};      // first-request delay while another
                                         // lane is fetching the same bodies
    uint32_t refetch_ms{30000};          // re-request an unanswered height
    size_t   buffer_cap{256};            // out-of-order bodies held at most
    uint32_t fold_budget{16};            // folds per io turn, then re-post
    uint32_t persist_every_tip{24};      // blocks between writes at tip
    uint32_t persist_every_catchup{500}; // ... while catching up
    uint32_t near_tip{12};               // "at tip" = within this many blocks
    size_t   ring_size{6};               // reorg rollback snapshots kept
    uint32_t request_retry_ms{60000};    // getmnlistd / getheaders
    /// getqrinfo re-ask interval. Much longer than the others on purpose: an
    /// empty-base getqrinfo makes the serving dashd build five FULL lists
    /// from genesis, it answers a peer's messages strictly in order, and
    /// under load a reply takes minutes — measured live (2026-10-28): a
    /// one-minute re-ask buried everything else we sent that peer (the
    /// backfill getheaders included) behind our own growing backlog.
    uint32_t qrinfo_retry_ms{600000};
    uint32_t bootstrap_give_up_ms{900000};// stop gating folds on an input that
                                         // never arrives (fallback covers)
    uint32_t anchor_grace_ms{120000};    // wait for the lane's anchor SML first
    uint32_t hash_back{3 * 576 + 64};    // pre-cursor hash window seeded
    uint32_t ingest_back{64};            // pre-cursor hashes REQUIRED to fold
                                         // (>= every type's window end)
    /// Run the straddle bootstrap at every seed cursor. Off only for KATs
    /// whose synthetic heights sit below every LLMQ floor.
    bool     straddle_bootstrap{true};
};

struct PoseOracleIo
{
    /// Best-chain header hash at a height (PoW header chain), nullopt if not held.
    std::function<std::optional<uint256>(uint32_t)> hash_at;
    std::function<uint32_t()> tip_height;
    /// Header hashMerkleRoot for a held block hash (the DIP-4 trust anchor).
    MerkleRootOfHashFn merkle_root_of;
    /// getdata for one block body; true when a peer heard it.
    std::function<bool(const uint256&)> request_block;
    std::function<void(const uint256& base, const uint256& target)> send_getmnlistd;
    /// getqrinfo with EMPTY base hashes and extraShare=true for a cycle base.
    std::function<void(const uint256& cycle_base_hash)> send_getqrinfo;
    /// One-shot backward getheaders, locator -> stop=anchor. `attempt`
    /// lets the caller rotate peers (preferring one that is not busy
    /// answering our getqrinfo).
    std::function<bool(const uint256& locator, uint32_t attempt)>
        send_backfill_getheaders;
    /// Install a pre-anchor header batch downward from the anchor; returns
    /// how many headers it linked (newly installed OR re-indexed by height).
    std::function<size_t(const std::vector<BlockHeaderType>&)> install_preanchor_span;
    /// Run `fn` on a LATER io turn (long catch-up yields between batches).
    std::function<void(std::function<void()>)> post;
    std::function<uint64_t()> now_ms;
    /// True while another lane is replaying the same bodies (first requests
    /// are then delayed by fetch_grace_ms so the wire carries one getdata).
    std::function<bool()> other_lane_fetching;
    /// Anchor seed: the DIP-4 anchor SML merged with the checkpoint's
    /// forward-fold facets (payee fields) — main_dash's merge.
    std::function<std::vector<std::pair<uint256, ReplayMNState>>(
        const vendor::CSimplifiedMNList&, size_t& with_facets,
        size_t& without_facets)> anchor_entries;
    /// The engine's state was replaced wholesale (seed / resume / rollback).
    std::function<void()> on_reseeded;
    /// A block folded cleanly (root self-check passed).
    std::function<void(uint32_t, const uint256&, const BlockType&,
                       const FoldResult&)> on_folded;
};

class PoseOracleFeeder
{
public:
    struct Stats {
        uint64_t folded{0};             // folds that passed the root self-check
        uint64_t root_mismatches{0};    // folds that poisoned
        uint64_t root_resolved_bans{0};
        uint64_t root_resolved_nobans{0};
        uint64_t holds{0};              // distinct (height) holds for members
        uint64_t requested{0};          // block getdata issued
        uint64_t dropped_fork_bodies{0};
        uint64_t dropped_over_cap{0};
        uint64_t persisted{0};
        uint64_t rollbacks{0};
        uint32_t seeded_at{0};
        std::string seed_source;        // "anchor" / "anchor-own" / "snapshot" / "ring" / ""
        uint32_t first_fold_h{0};
        uint32_t last_fold_h{0};
    };

    PoseOracleFeeder(DmlFoldEngine& eng, QuorumReplayEngine& q,
                     ReplayQuorumBridge& br, PoseOracleConfig cfg,
                     PoseOracleIo io)
        : m_eng(eng), m_q(q), m_br(br), m_cfg(std::move(cfg)), m_io(std::move(io))
    {}

    PoseOracleFeeder(const PoseOracleFeeder&) = delete;
    PoseOracleFeeder& operator=(const PoseOracleFeeder&) = delete;

    // ── THE ORACLE ────────────────────────────────────────────────────────
    std::optional<PoSeBounds> oracle_bounds(uint32_t prev_height,
                                            const uint256& prev_hash,
                                            const uint256& protx) const
    {
        return m_eng.pose_bounds_at(prev_height, prev_hash, protx);
    }
    /// (height, hash) the oracle describes, when it describes anything.
    std::optional<std::pair<uint32_t, uint256>> cursor() const
    {
        if (!seeded() || m_eng.poisoned()) return std::nullopt;
        return std::make_pair(m_eng.height(), m_eng.block_hash());
    }

    bool seeded() const { return m_eng.size() != 0; }

    /// The caller seeded the engine itself (a replay prestate, a KAT): adopt
    /// its cursor exactly as a resumed snapshot would be adopted (quorum
    /// cursor, retained list, straddle bootstrap, writer re-ground).
    void adopt_current_state(const char* source)
    {
        m_resume_settled = true;
        if (seeded()) on_seeded(source);
        pump();
    }

    /// The straddle bootstrap plan (diagnostics + KATs).
    struct BootPlan {
        uint32_t cursor{0}, cyc0{0}, cyc1{0};
        std::vector<uint32_t> work_heights;
        std::vector<uint32_t> derive_bases;
        bool rot_landed{false}, complete{false}, hashes_ready{false};
    };
    BootPlan boot_plan() const
    {
        BootPlan p;
        p.cursor = m_boot.S;
        p.cyc0 = m_boot.cyc0;
        p.cyc1 = m_boot.cyc1;
        for (const auto& [h, w] : m_boot.work) p.work_heights.push_back(h);
        p.derive_bases.assign(m_boot.derive_pending.begin(), m_boot.derive_pending.end());
        p.derive_bases.insert(p.derive_bases.end(), m_boot.derived.begin(), m_boot.derived.end());
        std::sort(p.derive_bases.begin(), p.derive_bases.end());
        p.rot_landed = m_boot.rot_landed;
        p.complete = m_boot.complete;
        p.hashes_ready = m_boot.hashes_ready;
        return p;
    }
    const Stats& stats() const { return m_stats; }
    bool bootstrap_complete() const { return m_boot.active && m_boot.complete; }
    bool hashes_ready() const { return m_boot.hashes_ready; }
    size_t buffered() const { return m_buf.size(); }

    // ── wire intake (io thread) ───────────────────────────────────────────

    /// The MN-CKPT lane's anchor fold delivered the DIP-4-authenticated SML.
    void on_anchor_sml(const vendor::CSimplifiedMNList& asml)
    {
        m_anchor_sml = asml;
        pump();
    }

    /// Node::block_connected.
    void on_block(const BlockType& block, uint32_t height)
    {
        if (height == 0) return;
        if (seeded() && height <= m_eng.height()) return;
        if (!seeded() && height <= m_cfg.anchor_height) return;
        const uint256 bh = DmlFoldEngine::block_header_hash(block);
        auto want = m_io.hash_at(height);
        if (!want || *want != bh) { ++m_stats.dropped_fork_bodies; return; }
        m_buf[height] = block;
        m_requested.erase(height);
        enforce_buffer_cap();
        pump();
    }

    /// Historical getmnlistd filter. TRUE = this reply answered one of OUR
    /// requests (it then must not reach the tip SML); a claim stands even
    /// when authentication then fails.
    bool on_historical_mnlistdiff(const vendor::CSimplifiedMNListDiff& d)
    {
        if (!d.baseBlockHash.IsNull()) return false;
        auto it = m_hist_req.find(d.blockHash);
        if (it == m_hist_req.end()) return false;
        const uint32_t h = it->second.height;
        const bool live = !it->second.done;
        it->second.done = true;   // later duplicates are still CLAIMED
        if (!live) return true;
        vendor::CCbTx cbtx;
        auto sml = authenticate_historical_snapshot(d, h, m_io.merkle_root_of,
                                                    cbtx, "POSE-ORACLE");
        if (!sml) {
            it->second.done = false;   // retry after request_retry_ms
            return true;
        }
        if (h == m_cfg.anchor_height && d.blockHash == m_cfg.anchor_hash) {
            LOG_INFO << "[POSE-ORACLE] own anchor SML arrived (h=" << h
                     << ", " << sml->mnList.size() << " entries, DIP-4 OK)";
            m_anchor_sml = std::move(*sml);
            m_anchor_own = true;
        } else {
            land_work_list(h, d.blockHash, cbtx, *sml);
        }
        pump();
        return true;
    }

    /// Additive qrinfo consumer: only the replies bound to OUR cycle bases.
    void on_qrinfo(const vendor::CQuorumRotationInfo& info)
    {
        if (!m_boot.active || m_boot.rot_type == 0) return;
        vendor::CCbTx hcb;
        if (info.mnListDiffH.cbTx.type != 5
            || !vendor::parse_cbtx(info.mnListDiffH.cbTx.extra_payload, hcb)
            || hcb.nHeight < 0) return;
        const uint32_t cycle = static_cast<uint32_t>(hcb.nHeight) + kWorkDiffDepth;
        if (cycle == m_boot.cyc0 && !m_boot.rot_landed) {
            land_qrinfo_b0(info);
        } else if (cycle == m_boot.cyc1 && !m_io.hash_at(m_boot.cyc0)) {
            // Stage 1: cyc0 is below the anchor and its header is not held.
            // cyc1's H-4C leg (cyc0 - 3C - 8) is the deepest locator available.
            if (info.extraShare && info.mnListDiffAtHMinus4C)
                maybe_backfill(info.mnListDiffAtHMinus4C->blockHash);
        }
        pump();
    }

    /// Node::new_headers: the pre-anchor backfill batch lands here.
    void on_headers(const std::vector<BlockHeaderType>& batch)
    {
        if (!m_backfill_pending || batch.empty() || !m_io.install_preanchor_span)
            return;
        const size_t n = m_io.install_preanchor_span(batch);
        if (n == 0) return;
        m_backfill_pending = false;
        LOG_INFO << "[POSE-ORACLE] pre-anchor header backfill linked " << n
                 << " headers below the anchor (installed or re-indexed)";
        // The work-block headers the qrinfo legs need may now be held:
        // re-ask immediately instead of after the retry interval.
        m_boot.qr_ms = 0;
        m_boot.qr1_ms = 0;
        for (auto& [h, w] : m_boot.work) w.sent_ms = 0;
        pump();
    }

    /// Tip change / periodic tick.
    void on_tick() { pump(); }

    /// Write the v4 snapshot now (e.g. at shutdown). No-op when unseeded,
    /// poisoned or not configured.
    bool persist_now()
    {
        if (m_cfg.snapshot_path.empty() || !seeded() || m_eng.poisoned())
            return false;
        std::string err;
        if (!m_eng.save_snapshot_file(m_cfg.snapshot_path, err)) {
            LOG_WARNING << "[POSE-ORACLE] snapshot write FAILED: " << err;
            return false;
        }
        m_last_persist_h = m_eng.height();
        ++m_stats.persisted;
        return true;
    }

    /// One-line state for logs.
    std::string status_line() const
    {
        const PoSeExactness x = m_eng.pose_exactness();
        const uint32_t tip = m_io.tip_height ? m_io.tip_height() : 0;
        std::string s = "seeded=" + std::string(seeded() ? m_stats.seed_source : "no");
        s += " h=" + std::to_string(seeded() ? m_eng.height() : 0);
        s += " tip=" + std::to_string(tip);
        s += " poisoned=" + std::to_string(m_eng.poisoned() ? 1 : 0);
        s += " folded=" + std::to_string(m_stats.folded);
        s += " root_mismatch=" + std::to_string(m_stats.root_mismatches);
        s += " root_resolved=" + std::to_string(m_stats.root_resolved_bans)
           + "/" + std::to_string(m_stats.root_resolved_nobans);
        s += " exact=" + std::to_string(x.valid_exact);
        s += " inexact=" + std::to_string(x.valid_inexact);
        s += " nonzero=" + std::to_string(x.valid_nonzero);
        s += " banned=" + std::to_string(x.banned);
        s += " max_gap=" + std::to_string(x.max_gap);
        s += " held=" + std::to_string(m_stats.holds);
        s += " buf=" + std::to_string(m_buf.size());
        s += " boot=" + std::string(!m_boot.active ? "-"
                                     : m_boot.complete ? "complete" : "pending");
        s += " fallback=" + std::to_string(m_br.stats().members_from_fallback);
        return s;
    }

private:
    // ── state ────────────────────────────────────────────────────────────
    struct WorkReq {
        uint64_t sent_ms{0};
        bool     landed{false};
    };

    struct Boot {
        bool     active{false};
        bool     complete{false};
        bool     hashes_ready{false};
        uint32_t S{0};
        uint8_t  rot_type{0};
        uint32_t C{0};
        uint32_t cyc0{0}, cyc1{0};
        bool     rot_landed{false};
        bool     rot_settled{false};   // cyc0 seeded AND (derived, or cyc0 > S)
        bool     given_up{false};      // inputs never arrived: stop gating
        uint64_t started_ms{0};
        uint64_t qr_ms{0};       // last getqrinfo(cyc0)
        uint64_t qr1_ms{0};      // last getqrinfo(cyc1) (stage-1 locator)
        std::map<uint32_t, WorkReq> work;      // pre-cursor work heights
        std::set<uint32_t> derive_pending;     // bases <= S to derive
        std::set<uint32_t> derived;
    };
    struct HistReq {
        uint32_t height{0};
        uint64_t sent_ms{0};
        bool     done{false};
    };
    struct RingEntry {
        uint32_t             height{0};
        uint256              hash;
        std::vector<uint8_t> bytes;
    };

    DmlFoldEngine&       m_eng;
    QuorumReplayEngine&  m_q;
    ReplayQuorumBridge&  m_br;
    PoseOracleConfig     m_cfg;
    PoseOracleIo         m_io;

    std::map<uint32_t, BlockType>  m_buf;
    std::map<uint32_t, uint64_t>   m_requested;   // height -> when (0: noted only)
    std::map<uint256, HistReq>     m_hist_req;
    std::optional<vendor::CSimplifiedMNList> m_anchor_sml;
    bool     m_anchor_own{false};
    uint64_t m_unseeded_since{0};
    bool     m_resume_settled{false};
    bool     m_resumed_from_file{false};
    bool     m_reseed_after_poison_tried{false};
    bool     m_poison_logged{false};
    bool     m_quorum_err_logged{false};
    uint32_t m_last_persist_h{0};
    std::deque<RingEntry> m_ring;
    bool     m_backfill_pending{false};
    uint32_t m_backfill_attempts{0};
    uint64_t m_backfill_ms{0};
    uint32_t m_last_hold_logged{0};
    bool     m_in_pump{false};
    bool     m_repump{false};
    bool     m_post_scheduled{false};
    Boot     m_boot;
    Stats    m_stats;

    uint64_t now() const { return m_io.now_ms ? m_io.now_ms() : 0; }

    // ── the pump ─────────────────────────────────────────────────────────
    void pump()
    {
        if (m_in_pump) { m_repump = true; return; }
        m_in_pump = true;
        do {
            m_repump = false;
            pump_once();
        } while (m_repump);
        m_in_pump = false;
    }

    void pump_once()
    {
        const uint32_t tip = m_io.tip_height();
        if (!seeded()) {
            seed_step(tip);
            if (!seeded()) return;
        }
        if (m_eng.poisoned()) { on_poisoned(); return; }
        if (check_reorg(tip) && !seeded()) return;
        bootstrap_step(tip);
        fold_loop(tip);
        request_window(tip);
    }

    // ── seeding ──────────────────────────────────────────────────────────
    void seed_step(uint32_t tip)
    {
        if (!m_resume_settled) {
            try_resume(tip);
            if (seeded() || !m_resume_settled) return;
        }
        if (m_anchor_sml) {
            seed_from_anchor(*m_anchor_sml, m_anchor_own ? "anchor-own" : "anchor");
            return;
        }
        // No lane anchor yet: after a grace period, fetch it ourselves (the
        // lane resumed its own cursor and will never run its anchor fold).
        const uint64_t t = now();
        if (m_unseeded_since == 0) m_unseeded_since = t;
        if (t - m_unseeded_since < m_cfg.anchor_grace_ms) return;
        if (!m_io.merkle_root_of(m_cfg.anchor_hash)) return;   // header not held yet
        auto& rq = m_hist_req[m_cfg.anchor_hash];
        rq.height = m_cfg.anchor_height;
        if (rq.done && m_anchor_sml) return;
        if (rq.sent_ms != 0 && t - rq.sent_ms < m_cfg.request_retry_ms) return;
        rq.sent_ms = t;
        rq.done = false;
        m_io.send_getmnlistd(uint256::ZERO, m_cfg.anchor_hash);
        LOG_INFO << "[POSE-ORACLE] no anchor SML from the MN-CKPT lane after "
                 << (m_cfg.anchor_grace_ms / 1000) << "s (it resumed its own"
                    " cursor) — requesting getmnlistd(ZERO, anchor h="
                 << m_cfg.anchor_height << ") for the oracle's own seed";
    }

    void try_resume(uint32_t tip)
    {
        if (m_cfg.snapshot_path.empty()) { m_resume_settled = true; return; }
        std::ifstream f(m_cfg.snapshot_path, std::ios::binary);
        if (!f) {
            m_resume_settled = true;
            LOG_INFO << "[POSE-ORACLE] no oracle snapshot at "
                     << m_cfg.snapshot_path << " — anchor seed";
            return;
        }
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),
                                   std::istreambuf_iterator<char>());
        DmlFoldEngine probe{FoldConfig{}};
        std::string err;
        if (!probe.load_snapshot(bytes, err)) {
            m_resume_settled = true;
            LOG_WARNING << "[POSE-ORACLE] oracle snapshot REFUSED (" << err
                        << ") — anchor re-seed";
            return;
        }
        if (probe.network() != m_cfg.net_name || probe.height() < m_cfg.anchor_height) {
            m_resume_settled = true;
            LOG_WARNING << "[POSE-ORACLE] oracle snapshot is for network '"
                        << probe.network() << "' h=" << probe.height()
                        << " (want '" << m_cfg.net_name << "', >= anchor "
                        << m_cfg.anchor_height << ") — anchor re-seed";
            return;
        }
        if (tip < probe.height()) return;   // header chain not there yet: wait
        auto on_chain = m_io.hash_at(probe.height());
        if (!on_chain || *on_chain != probe.block_hash()) {
            m_resume_settled = true;
            LOG_WARNING << "[POSE-ORACLE] oracle snapshot h=" << probe.height()
                        << " block " << probe.block_hash().GetHex().substr(0, 16)
                        << " is NOT on our header chain — discarded, anchor re-seed";
            return;
        }
        if (!m_eng.load_snapshot(bytes, err)) {   // cannot differ from probe
            m_resume_settled = true;
            return;
        }
        m_resume_settled   = true;
        m_resumed_from_file = true;
        LOG_INFO << "[POSE-ORACLE] RESUMED from v" << m_eng.loaded_snapshot_version()
                 << " snapshot at h=" << m_eng.height() << " block "
                 << m_eng.block_hash().GetHex().substr(0, 16)
                 << " (on our header chain) — no anchor re-seed; "
                 << (tip - m_eng.height()) << " blocks to the tip";
        on_seeded("snapshot");
    }

    bool seed_from_anchor(const vendor::CSimplifiedMNList& asml, const char* source)
    {
        size_t with = 0, without = 0;
        auto entries = m_io.anchor_entries(asml, with, without);
        const uint64_t trc = entries.size();
        m_eng.seed(std::move(entries), trc, m_cfg.anchor_height,
                   m_cfg.anchor_hash, m_cfg.net_name, SeedPenalties::Unknown);
        const uint256 got  = m_eng.compute_sml_root();
        const uint256 want = asml.CalcMerkleRoot();
        if (got != want) {
            LOG_ERROR << "[POSE-ORACLE] anchor seed SELF-CHECK FAILED at h="
                      << m_cfg.anchor_height << " (" << with << " with facets, "
                      << without << " without): " << got.GetHex().substr(0, 16)
                      << " != " << want.GetHex().substr(0, 16)
                      << " — oracle stays unseeded (fail closed)";
            m_eng.seed({}, 0, 0, uint256::ZERO, m_cfg.net_name);
            m_anchor_sml.reset();
            return false;
        }
        LOG_INFO << "[POSE-ORACLE] seeded from the DIP-4 anchor SML at h="
                 << m_cfg.anchor_height << " (" << with << " MNs with checkpoint"
                    " facets, " << without << " without); penalties UNKNOWN:"
                    " lo=0, hi=" << m_eng.seed_penalty_ceiling()
                 << " (2 x CalcMaxPoSePenalty)";
        on_seeded(source);
        return true;
    }

    void on_seeded(const char* source)
    {
        const uint32_t S = m_eng.height();
        m_q.seed_cursor(S, m_eng.block_hash());
        m_br.forget_lists_above(S);
        m_br.prime_at_anchor();
        m_stats.seeded_at   = S;
        m_stats.seed_source = source;
        m_last_persist_h    = S;
        m_ring.clear();
        m_poison_logged = false;
        for (auto it = m_buf.begin(); it != m_buf.end();)
            it = (it->first <= S) ? m_buf.erase(it) : std::next(it);
        start_bootstrap(S);
        if (m_io.on_reseeded) m_io.on_reseeded();
    }

    void on_poisoned()
    {
        if (!m_poison_logged) {
            m_poison_logged = true;
            ++m_stats.root_mismatches;
            LOG_ERROR << "[POSE-ORACLE] oracle engine POISONED: "
                      << m_eng.poison_reason()
                      << " — the oracle answers nothing (the PoSe pass refuses"
                         " as before). " << status_line();
        }
        // A state resumed from disk may predate a fix or carry a stale
        // bound: drop it ONCE and re-seed from the anchor.
        if (m_resumed_from_file && !m_reseed_after_poison_tried) {
            m_reseed_after_poison_tried = true;
            m_resumed_from_file = false;
            if (!m_cfg.snapshot_path.empty())
                std::remove(m_cfg.snapshot_path.c_str());
            LOG_WARNING << "[POSE-ORACLE] poisoned on a RESUMED state — snapshot"
                           " discarded, re-seeding from the anchor once";
            m_eng.seed({}, 0, 0, uint256::ZERO, m_cfg.net_name);
            m_unseeded_since = 0;
            m_repump = true;
        }
    }

    // ── reorg ────────────────────────────────────────────────────────────
    bool check_reorg(uint32_t tip)
    {
        const uint32_t h = m_eng.height();
        if (h > tip) return false;   // header chain behind us: wait
        auto on_chain = m_io.hash_at(h);
        if (!on_chain || *on_chain == m_eng.block_hash()) return false;
        ++m_stats.rollbacks;
        LOG_WARNING << "[POSE-ORACLE] REORG: cursor h=" << h << " block "
                    << m_eng.block_hash().GetHex().substr(0, 16)
                    << " left the best chain";
        for (auto it = m_ring.rbegin(); it != m_ring.rend(); ++it) {
            auto c = m_io.hash_at(it->height);
            if (!c || *c != it->hash) continue;
            std::string err;
            if (m_eng.load_snapshot(it->bytes, err)) {
                LOG_INFO << "[POSE-ORACLE] rolled back to h=" << it->height
                         << " (in-memory snapshot)";
                const uint32_t to = it->height;
                m_ring.erase(it.base(), m_ring.end());   // keep *it, drop later
                rollback_tail(to, "ring");
                return true;
            }
        }
        // Not in the ring: the file, else the anchor.
        m_eng.seed({}, 0, 0, uint256::ZERO, m_cfg.net_name);
        m_resume_settled = false;
        m_resumed_from_file = false;
        m_unseeded_since = 0;
        m_repump = true;
        return true;
    }

    void rollback_tail(uint32_t to, const char* source)
    {
        m_q.seed_cursor(to, m_eng.block_hash());
        m_br.forget_lists_above(to);
        for (auto it = m_buf.begin(); it != m_buf.end();) {
            auto c = m_io.hash_at(it->first);
            const bool keep = it->first > to && c
                && *c == DmlFoldEngine::block_header_hash(it->second);
            it = keep ? std::next(it) : m_buf.erase(it);
        }
        m_requested.clear();
        m_stats.seed_source = source;
        if (m_io.on_reseeded) m_io.on_reseeded();
    }

    // ── straddle bootstrap ───────────────────────────────────────────────
    void start_bootstrap(uint32_t S)
    {
        m_boot = Boot{};
        m_boot.active = true;
        m_boot.S = S;
        m_boot.started_ms = now();
        if (!m_cfg.straddle_bootstrap) {
            m_boot.hashes_ready = true;
            m_boot.complete = true;
            return;
        }
        for (const auto& p : enabled_llmqs(m_cfg.network)) {
            if (p.dkg_interval == 0) continue;
            if (p.use_rotation) {
                m_boot.rot_type = p.type;
                m_boot.C  = p.dkg_interval;
                m_boot.cyc1 = ((S + kWorkDiffDepth) / p.dkg_interval + 1)
                          * p.dkg_interval;
                m_boot.cyc0 = m_boot.cyc1 - p.dkg_interval;
                // Derived out of band as soon as it is seeded — before or
                // after observe(cyc0): derive_at() reads only the work-block
                // inputs, never cyc0's own hash.
                m_boot.derive_pending.insert(m_boot.cyc0);
                continue;
            }
            // Non-rotated bases whose work block is at/before S and whose
            // mining window still reaches past S.
            const uint32_t I = p.dkg_interval;
            for (uint32_t B = ((S + kWorkDiffDepth) / I) * I;
                 B >= I && B + p.mining_window_end > S; B -= I) {
                if (B < kWorkDiffDepth) break;
                m_boot.work[B - kWorkDiffDepth];
                // Out of band once its list lands, whether or not observe(B)
                // has run yet (a punishing commitment HOLDS until then).
                m_boot.derive_pending.insert(B);
            }
        }
        // A rotated cyc0 shares its work block with any non-rotated base at cyc0:
        // the qrinfo H leg supplies it. (Work entries keyed cyc0-8 are dropped.)
        // A work height == S keeps the engine's own list (prime_at_anchor,
        // with collateral outpoints); its fetch still seeds the cbTx CL the
        // modifier reads, which no snapshot carries.
        if (m_boot.rot_type != 0) m_boot.work.erase(m_boot.cyc0 - kWorkDiffDepth);
        LOG_INFO << "[POSE-ORACLE] straddle bootstrap at cursor h=" << S
                 << ": rotated cyc0=" << m_boot.cyc0 << " cyc1=" << m_boot.cyc1
                 << " (C=" << m_boot.C << "), " << m_boot.work.size()
                 << " pre-cursor non-rotated work list(s), "
                 << m_boot.derive_pending.size() << " base(s) to derive out of band";
    }

    void bootstrap_step(uint32_t tip)
    {
        if (!m_boot.active || m_boot.complete) return;
        const uint64_t t = now();
        const uint32_t S = m_boot.S;
        if (!m_boot.given_up && m_boot.started_ms != 0
            && t - m_boot.started_ms >= m_cfg.bootstrap_give_up_ms
            && m_boot.hashes_ready) {
            m_boot.given_up = true;
            LOG_WARNING << "[POSE-ORACLE] straddle bootstrap inputs did not all"
                           " arrive in " << (m_cfg.bootstrap_give_up_ms / 1000)
                        << "s — folds are no longer gated on them; a punishing"
                           " commitment that still lacks a member set HOLDS"
                           " until the member source answers";
        }

        // (1) pre-cursor block hashes, once the header chain holds them.
        if (!m_boot.hashes_ready) {
            const uint32_t lo_req = S > m_cfg.ingest_back ? S - m_cfg.ingest_back : 1;
            bool all = true;
            for (uint32_t h = lo_req; h <= S; ++h)
                if (!m_io.hash_at(h)) { all = false; break; }
            const uint32_t lo = S > m_cfg.hash_back ? S - m_cfg.hash_back : 1;
            m_br.seed_block_hashes(lo, S, m_io.hash_at);
            if (all) {
                m_boot.hashes_ready = true;
                LOG_INFO << "[POSE-ORACLE] pre-cursor block hashes seeded from"
                            " the header chain (h>=" << lo << "..." << S << ")";
            }
        }

        // (2) rotated: getqrinfo(cyc0), or cyc1 first when cyc0's header is not held.
        if (m_boot.rot_type != 0 && !m_boot.rot_landed && tip >= m_boot.cyc0) {
            if (auto hb0 = m_io.hash_at(m_boot.cyc0)) {
                if (m_boot.qr_ms == 0 || t - m_boot.qr_ms >= m_cfg.qrinfo_retry_ms) {
                    m_boot.qr_ms = t;
                    m_io.send_getqrinfo(*hb0);
                    LOG_INFO << "[POSE-ORACLE] getqrinfo(cycle base h="
                             << m_boot.cyc0 << ", extraShare) for the straddle cycle";
                }
            } else if (tip >= m_boot.cyc1 && !m_backfill_pending) {
                // (A pending backfill already holds the locator this would
                // fetch: wait for it rather than queue another qrinfo.)
                if (auto hb1 = m_io.hash_at(m_boot.cyc1)) {
                    if (m_boot.qr1_ms == 0
                        || t - m_boot.qr1_ms >= m_cfg.qrinfo_retry_ms) {
                        m_boot.qr1_ms = t;
                        m_io.send_getqrinfo(*hb1);
                        LOG_INFO << "[POSE-ORACLE] straddle cycle h=" << m_boot.cyc0
                                 << " is below the header chain; getqrinfo(h="
                                 << m_boot.cyc1 << ") for a backfill locator";
                    }
                }
            }
        }

        // (3) non-rotated pre-cursor work lists.
        for (auto& [wh, w] : m_boot.work) {
            if (w.landed) continue;
            auto hh = m_io.hash_at(wh);
            if (!hh || !m_io.merkle_root_of(*hh)) continue;   // header not held
            if (w.sent_ms != 0 && t - w.sent_ms < m_cfg.request_retry_ms) continue;
            w.sent_ms = t;
            auto& rq = m_hist_req[*hh];
            rq.height  = wh;
            rq.sent_ms = t;
            rq.done    = false;
            m_io.send_getmnlistd(uint256::ZERO, *hh);
        }

        try_derive();
    }

    void land_work_list(uint32_t h, const uint256& hash, const vendor::CCbTx& cbtx,
                        const vendor::CSimplifiedMNList& sml)
    {
        auto it = m_boot.work.find(h);
        if (it == m_boot.work.end() || it->second.landed) return;
        std::string err;
        if (!m_br.seed_pre_cursor_work_list(h, hash, cl_of(cbtx), entries_of(sml),
                                            m_boot.S, err)) {
            LOG_WARNING << "[POSE-ORACLE] work list h=" << h << " refused: " << err;
            return;
        }
        it->second.landed = true;
        LOG_INFO << "[POSE-ORACLE] pre-cursor work list h=" << h << " seeded ("
                 << sml.mnList.size() << " MNs, DIP-4 OK)";
        try_derive();
    }

    void land_qrinfo_b0(const vendor::CQuorumRotationInfo& info)
    {
        const uint32_t cyc0 = m_boot.cyc0, C = m_boot.C, S = m_boot.S;
        const vendor::CSimplifiedMNListDiff* legs[4] = {
            &info.mnListDiffH, &info.mnListDiffAtHMinusC,
            &info.mnListDiffAtHMinus2C, &info.mnListDiffAtHMinus3C};
        for (const auto* d : legs) {
            if (!m_io.merkle_root_of(d->blockHash)) {
                // A work-block header is below what we hold: backfill from
                // this reply's own deepest leg, then re-ask.
                if (info.extraShare && info.mnListDiffAtHMinus4C)
                    maybe_backfill(info.mnListDiffAtHMinus4C->blockHash);
                return;
            }
        }
        std::array<vendor::CSimplifiedMNList, 4> sml;
        std::array<vendor::CCbTx, 4> cb;
        for (size_t i = 0; i < 4; ++i) {
            if (!legs[i]->deletedMNs.empty()) {
                LOG_WARNING << "[POSE-ORACLE] qrinfo leg " << i
                            << " is not a full list — retry";
                return;
            }
            const uint32_t wh = cyc0 - kWorkDiffDepth - static_cast<uint32_t>(i) * C;
            auto s = authenticate_historical_snapshot(*legs[i], wh, m_io.merkle_root_of,
                                                      cb[i], "POSE-ORACLE-QR");
            if (!s) return;   // named by the helper; retry later
            sml[i] = std::move(*s);
        }
        // Three predecessor snapshots (cyc0-C, cyc0-2C, cyc0-3C).
        QSnapshotSeed qs;
        qs.ok = true;
        qs.network = m_cfg.net_name;
        const vendor::CQuorumSnapshot* snaps[3] = {
            &info.quorumSnapshotAtHMinusC, &info.quorumSnapshotAtHMinus2C,
            &info.quorumSnapshotAtHMinus3C};
        for (size_t i = 0; i < 3; ++i) {
            QSnapshotSeedEntry e;
            e.llmq_type  = m_boot.rot_type;
            e.cycle_base = cyc0 - static_cast<uint32_t>(i + 1) * C;
            e.snapshot   = *snaps[i];
            qs.entries.push_back(std::move(e));
        }
        // Their three work lists (+ hash, CL, modifier).
        WorkListSeed wl;
        wl.ok = true;
        wl.network    = m_cfg.net_name;
        wl.llmq_type  = m_boot.rot_type;
        wl.cycle_base = cyc0;
        wl.interval   = C;
        for (size_t i = 1; i < 4; ++i) {
            WorkListSeedEntry w;
            w.cycle_base  = cyc0 - static_cast<uint32_t>(i) * C;
            w.work_height = w.cycle_base - kWorkDiffDepth;
            w.block_hash  = legs[i]->blockHash;
            if (auto cl = cl_of(cb[i])) { w.has_cl = true; w.cl_sig = *cl; }
            w.entries = entries_of(sml[i]);
            wl.works.push_back(std::move(w));
        }
        std::string e1, e2, e3;
        if (!m_br.seed_snapshots(qs, S, e1) || !m_br.seed_work_lists(wl, S, e2)) {
            LOG_ERROR << "[POSE-ORACLE] qrinfo(cyc0=" << cyc0 << ") seed REJECTED ("
                      << (e1.empty() ? e2 : e1) << ") — retry";
            return;
        }
        // cyc0's own work list (the H leg). At cyc0-8 == S the engine's own list
        // (with collateral outpoints) is kept; only hash + CL are seeded.
        if (!m_br.seed_pre_cursor_work_list(cyc0 - kWorkDiffDepth, legs[0]->blockHash,
                                            cl_of(cb[0]), entries_of(sml[0]),
                                            S, e3)) {
            LOG_ERROR << "[POSE-ORACLE] qrinfo(cyc0=" << cyc0 << ") H leg refused: "
                      << e3;
            return;
        }
        m_boot.rot_landed = true;
        LOG_INFO << "[POSE-ORACLE] qrinfo(cyc0=" << cyc0 << ") DIP-4 authenticated:"
                    " 3 predecessor snapshots + 4 work lists seeded";
        try_derive();
    }

    void try_derive()
    {
        if (!m_boot.active) return;
        for (auto it = m_boot.derive_pending.begin(); it != m_boot.derive_pending.end();) {
            const uint32_t B = *it;
            const uint32_t wh = B - kWorkDiffDepth;
            const bool rot_base = m_boot.rot_type != 0 && B == m_boot.cyc0;
            bool inputs = m_br.has_work_list(wh) && m_boot.hashes_ready;
            if (m_boot.rot_type != 0 && wh == m_boot.cyc0 - kWorkDiffDepth)
                inputs = inputs && m_boot.rot_landed;
            if (auto w = m_boot.work.find(wh); w != m_boot.work.end())
                inputs = inputs && w->second.landed;
            if (!inputs) { ++it; continue; }
            auto r = m_br.derive_at(B);
            bool ok = true;
            if (rot_base) {
                const LlmqParamsView* p = replay_llmq_params(m_cfg.network, m_boot.rot_type);
                for (uint32_t i = 0; p && i < p->signing_active_quorum_count; ++i)
                    if (!m_q.has_members_at(m_boot.rot_type, B + i)) ok = false;
            }
            for (const auto& p : enabled_llmqs(m_cfg.network)) {
                if (p.use_rotation || p.dkg_interval == 0 || B % p.dkg_interval) continue;
                if (B + p.mining_window_end <= m_boot.S) continue;   // not needed
                if (!m_q.has_members_at(p.type, B)) ok = false;
            }
            if (!ok) {
                LOG_WARNING << "[POSE-ORACLE] out-of-band derive at base h=" << B
                            << " INCOMPLETE (" << r.derived << " derived, "
                            << r.skipped << " skipped"
                            << (r.reasons.empty() ? std::string()
                                                  : ": " + r.reasons.back())
                            << ") — commitments needing it hold; fallback asked";
                if (rot_base) m_boot.rot_settled = true;   // nothing to wait for
                m_boot.derive_pending.erase(it++);   // do not spin; fallback covers
                continue;
            }
            LOG_INFO << "[POSE-ORACLE] straddle base h=" << B
                     << " member sets DERIVED (" << r.derived << " type cycle(s))";
            m_boot.derived.insert(B);
            if (rot_base) m_boot.rot_settled = true;
            it = m_boot.derive_pending.erase(it);
        }

        bool works_done = true;
        for (const auto& [h, w] : m_boot.work) if (!w.landed) works_done = false;
        const bool rot_done = m_boot.rot_type == 0 || m_boot.rot_landed;
        if (!m_boot.complete && m_boot.hashes_ready && works_done && rot_done
            && m_boot.derive_pending.empty()) {
            m_boot.complete = true;
            LOG_INFO << "[POSE-ORACLE] straddle bootstrap COMPLETE at cursor h="
                     << m_boot.S;
        }
    }

    void maybe_backfill(const uint256& locator)
    {
        const uint64_t t = now();
        if (m_backfill_pending && t - m_backfill_ms < m_cfg.request_retry_ms) return;
        if (!m_io.send_backfill_getheaders) return;
        if (m_io.send_backfill_getheaders(locator, m_backfill_attempts)) {
            m_backfill_pending = true;
            m_backfill_ms = t;
            LOG_INFO << "[POSE-ORACLE] pre-anchor header BACKFILL issued (attempt "
                     << m_backfill_attempts << "): locator "
                     << locator.GetHex() << " -> anchor h="
                     << m_cfg.anchor_height;
            ++m_backfill_attempts;
        }
    }

    // ── folding ──────────────────────────────────────────────────────────
    void fold_loop(uint32_t tip)
    {
        uint32_t budget = m_cfg.fold_budget;
        while (budget > 0 && !m_eng.poisoned()) {
            const uint32_t h = m_eng.height() + 1;
            if (h > tip) return;
            auto it = m_buf.find(h);
            if (it == m_buf.end()) return;
            const BlockType& blk = it->second;
            const uint256 bh = DmlFoldEngine::block_header_hash(blk);
            auto want = m_io.hash_at(h);
            if (!want || *want != bh) { m_buf.erase(it); return; }   // reorged away
            if (!boot_gate_open(h)) return;
            auto miss = m_br.unresolved_member_sets(blk, /*kick=*/true);
            if (!miss.empty()) {
                if (m_last_hold_logged != h) {
                    m_last_hold_logged = h;
                    ++m_stats.holds;
                    LOG_INFO << "[POSE-ORACLE] HOLD h=" << h << ": "
                             << miss.size() << " punishing commitment(s) without a"
                                " resolvable member set (first: type="
                             << int(miss.front().first) << " quorum=..."
                             // the DISCRIMINATING tail: a mainnet block hash
                             // starts with ~14 zero nibbles
                             << miss.front().second.GetHex().substr(52)
                             << ") — waiting for the straddle bootstrap /"
                                " member source";
                }
                return;
            }
            // A quorum-lane refusal only costs member DERIVATION (the fold
            // then holds on a missing set, or the member source answers);
            // it is named once, never a reason to stop folding.
            const std::string qerr = m_br.observe(h, bh, blk);
            if (!qerr.empty() && !m_quorum_err_logged) {
                m_quorum_err_logged = true;
                LOG_WARNING << "[POSE-ORACLE] quorum lane refused h=" << h
                            << " (" << qerr << ") — member sets now come from"
                               " the member source; the fold itself continues";
            }
            const FoldResult r = m_eng.fold_block(blk, h);
            m_br.after_fold(h);
            if (!r.ok) {
                on_poisoned();
                return;
            }
            ++m_stats.folded;
            m_stats.root_resolved_bans   += r.root_resolved_bans;
            m_stats.root_resolved_nobans += r.root_resolved_nobans;
            if (m_stats.first_fold_h == 0) m_stats.first_fold_h = h;
            m_stats.last_fold_h = h;
            if (m_io.on_folded) m_io.on_folded(h, bh, blk, r);
            m_buf.erase(it);
            after_fold_bookkeeping(h, bh, tip, r);
            --budget;
        }
        // Budget spent and more is foldable: continue on a later io turn.
        if (budget == 0 && m_io.post && !m_post_scheduled
            && m_buf.count(m_eng.height() + 1)) {
            m_post_scheduled = true;
            m_io.post([this] { m_post_scheduled = false; pump(); });
        }
    }

    /// Folds above the cursor wait only for the straddle inputs that cannot
    /// be supplied after the fact:
    ///  * every block: the pre-cursor block hashes (the quorum engine's
    ///    ingest resolves each commitment's base by hash, and an unknown base
    ///    poisons that lane);
    ///  * h >= cyc1: the rotated cycle cyc0 derived — observe(cyc1) runs the
    ///    quarter-rotation on cyc0's PRODUCED snapshot, and a cycle derived
    ///    without it is lost to the recurrence for good.
    /// Everything else (cyc0's own sets, non-rotated straddle sets) is derived
    /// out of band whenever its inputs land; a block that NEEDS such a set
    /// holds on unresolved_member_sets instead. After bootstrap_give_up_ms
    /// only the hashes still gate (the member source covers the rest).
    bool boot_gate_open(uint32_t h) const
    {
        if (!m_boot.active) return true;
        if (!m_boot.hashes_ready) return false;
        if (m_boot.given_up) return true;
        if (m_boot.rot_type != 0 && !m_boot.rot_settled && h >= m_boot.cyc1)
            return false;
        return true;
    }

    void after_fold_bookkeeping(uint32_t h, const uint256& bh, uint32_t tip,
                                const FoldResult& r)
    {
        const bool at_tip = tip - h <= m_cfg.near_tip;
        if (at_tip) {
            RingEntry e;
            e.height = h;
            e.hash   = bh;
            e.bytes  = m_eng.save_snapshot();
            m_ring.push_back(std::move(e));
            while (m_ring.size() > m_cfg.ring_size) m_ring.pop_front();
        }
        const uint32_t every = at_tip ? m_cfg.persist_every_tip
                                      : m_cfg.persist_every_catchup;
        if (!m_cfg.snapshot_path.empty() && h - m_last_persist_h >= every)
            persist_now();
        // Progress: every block near the tip, every 500 while catching up.
        if (at_tip || (m_stats.folded % 500) == 0
            || r.root_resolved_bans + r.root_resolved_nobans > 0) {
            LOG_INFO << "[POSE-ORACLE] fold h=" << h << " root OK ("
                     << r.committed_root.GetHex().substr(0, 16) << ") punished="
                     << r.punished << " banned=" << r.banned
                     << " | " << status_line();
        }
    }

    void request_window(uint32_t tip)
    {
        if (!m_io.request_block) return;
        const uint64_t t = now();
        const uint32_t from = m_eng.height() + 1;
        const uint32_t to = std::min<uint32_t>(tip, from + m_cfg.fetch_window - 1);
        const bool other = m_io.other_lane_fetching && m_io.other_lane_fetching();
        for (uint32_t h = from; h <= to && h >= from; ++h) {
            if (m_buf.count(h)) continue;
            auto hh = m_io.hash_at(h);
            if (!hh) break;
            auto [it, fresh] = m_requested.emplace(h, 0);
            if (fresh && other) { it->second = t; continue; }   // grace first
            if (!fresh && it->second != 0) {
                const uint64_t wait = other ? std::max(m_cfg.fetch_grace_ms, m_cfg.refetch_ms)
                                            : m_cfg.refetch_ms;
                if (t - it->second < wait) continue;
            }
            m_io.request_block(*hh);
            it->second = t == 0 ? 1 : t;
            ++m_stats.requested;
        }
        for (auto it = m_requested.begin(); it != m_requested.end();)
            it = (it->first < from) ? m_requested.erase(it) : std::next(it);
    }

    void enforce_buffer_cap()
    {
        while (m_buf.size() > m_cfg.buffer_cap) {
            m_buf.erase(std::prev(m_buf.end()));   // the highest: refetched later
            ++m_stats.dropped_over_cap;
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────
    static std::optional<std::array<uint8_t, vendor::CCbTx::BLS_SIG_SIZE>>
    cl_of(const vendor::CCbTx& cb)
    {
        if (cb.nVersion >= vendor::CCbTx::VERSION_CLSIG_AND_BALANCE
            && cb.has_best_cl_signature())
            return cb.bestCLSignature;
        return std::nullopt;
    }

    static std::vector<QuorumMnEntry> entries_of(const vendor::CSimplifiedMNList& sml)
    {
        std::vector<QuorumMnEntry> v;
        v.reserve(sml.mnList.size());
        for (const auto& e : sml.mnList) {
            QuorumMnEntry q;
            q.proTxHash        = e.proRegTxHash;
            q.confirmedHash    = e.confirmedHash;
            q.is_valid         = e.isValid;
            q.n_type           = e.nType;
            // Canonical BASIC, like the replay-fed lists (to_quorum_entry): the
            // operator key is a uniqueness property in the quarter-rotation's
            // used-member accounting, compared as a point.
            q.pub_key_operator = vendor::opkey_to_basic(
                e.pubKeyOperator, e.nVersion < vendor::ProTxVersion::BASIC_BLS);
            q.has_collateral   = false;   // SML-fed: a score tie fails closed
            v.push_back(std::move(q));
        }
        return v;
    }
};

} // namespace replay
} // namespace coin
} // namespace dash
