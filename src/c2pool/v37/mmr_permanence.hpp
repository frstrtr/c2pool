#pragma once
// V37 MRR PERMANENCE PEAKS — the permanent work record (the "V37P" layer),
// authored as a SHADOW over the shipped consensus lane.
//
// CONSUMER-tree code (src/c2pool/v37/). Header-only, stdlib-only, so it links
// into every v37 unit suite (and, later, the daemon) exactly like
// w2_receipt.hpp / w3_relay.hpp / v37_subthreshold_estimator.hpp. It does NOT
// touch src/sharechain/v37 canon: it holds only a `const v37::Lane&`, reads the
// lane's PUBLIC accessors, and re-serializes the lane's OWN "V37B" bucket leaves
// byte-for-byte. The consensus lane digest (V37H/V37A/V37B Merkle root) is left
// byte-identical by construction — the shadow appends NOTHING into
// v37::Lane::build_leaves().
//
// WHAT THIS FILE IS
//   An append-only Merkle Mountain Range (MMR) over the leaves of the buckets
//   the lane EVICTS once they leave the quantized window. Each carried eviction
//   contributes exactly one leaf: the evicted bucket's live "V37B" digest leaf
//   (level, pos_lo, pos_hi, raw_work, epoch_tag, comp_hash) — the very bytes the
//   bucket committed while it was live in the lane digest. The MMR keeps one
//   peak per set bit of the leaf count (tallest first), so the peaks are O(log n)
//   state that never rewrites an already-sealed sub-forest: a permanent record of
//   work that has aged out of the payout window. The bagged peak-root is a single
//   32-byte commitment; archival nodes keep the full leaf log and serve inclusion
//   proofs (mmr_proof) that any lite client verifies statelessly (mmr_verify)
//   against the committed root.
//
//   This mirrors the decision-complete proto (proto/mrr-retrofit I-2, namespace
//   v37retro) — the SEAL rule, the binary-counter append, and the right-fold bag
//   — but expressed against the REAL canon read surface (v37::Lane). Because the
//   proto is a byte-faithful fork-copy of src/sharechain/v37/v37_lane.hpp, the
//   peaks this shadow computes from canon's public buckets are bit-identical to
//   the proto's (KAT reproduces the I-2 golden MMR roots).
//
// WHY A SHADOW (and how it stays byte-inert)
//   The lane exposes no eviction hook, so the shadow SNAPSHOTS lane.levels()
//   before each push and diffs after: a bucket present-before / absent-after,
//   whose positions are no longer covered by any live bucket (i.e. evicted, not
//   folded up a level), with pos_lo >= the shadow's own activation_pos, was a
//   carried eviction — the shadow forms its "V37B" leaf from the pre-push
//   snapshot (the bucket's immutable epoch frame) and appends it. A lane rewind
//   is reconciled from a next_pos-indexed history of the log length (the same
//   thing the proto's undo_evict does with op.mmr_pre). Epoch rebuilds never
//   touch the peaks: the leaf payload lives in the bucket's own immutable epoch
//   frame, so the range is rebuild-invariant.
//
// THE GATE IS OFF BY DEFAULT AND DECOUPLED FROM shipped()
//   MmrShadowGate::activation_pos defaults to UINT64_MAX (never activates): the
//   shadow seals nothing and shadow_digest() returns lane.digest() VERBATIM, so a
//   node running this file is byte-identical to one without it. The gate is a
//   STANDALONE constant, deliberately NOT keyed off LaneParams::shipped() /
//   SHIPPED_CONSENSUS_VERSION (v37_lane.hpp): a canon consensus-version bump must
//   NOT silently turn the permanence peaks on. Wiring the peak-root INTO the live
//   canon lane digest (the "V37P" leaf under build_leaves, plus the settlement
//   owed_digest fold and a gate-ON golden) is the one-time position-gated
//   activation — an atomic consensus change, out of scope for this shadow.
//
// HASH DISCIPLINE (identical to the lane digest, OQ-M5):
//   leaf     = sha256d(0x00 || payload)
//   interior = sha256d(0x01 || left || right)     (domain-separated)
//   a perfect subtree root folds pairwise; the bagged root is a right fold with
//   the tallest peak outermost (single peak = itself; empty range = all-zero).

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <utility>
#include <vector>

#include <sharechain/v37/v37_lane.hpp>   // v37::Lane (READ-ONLY), Bucket, CompEntry, MinerId, LaneParams
#include <sharechain/v37/v37_fixed.hpp>  // v37::U256, u64, u128
#include <sharechain/v37/v37_hash.hpp>   // v37::bytes32, v37::sha256d

namespace c2pool::v37n {

// Canon types, read-only — the shadow never constructs or mutates a lane.
using v37::bytes32;
using v37::u64;
using v37::u128;
using v37::MinerId;

// ── PeakSet (mirror of v37retro::PeakSet) ─────────────────────────────────────
// One peak per set bit of leaf_count, tallest first; size() == popcount(count).
struct PeakSet {
    std::vector<bytes32> peaks;
    std::uint64_t leaf_count = 0;
    bool operator==(const PeakSet&) const = default;
};

// ── OFF gate (default UINT64_MAX == never activates) ──────────────────────────
// DELIBERATELY not keyed off LaneParams::shipped()/SHIPPED_CONSENSUS_VERSION —
// this guards the silent-flip landmine: a canon version bump must not turn the
// peaks on. A finite activation_pos is the position-gated consensus activation
// (an epoch-aligned share position); it is a pure function of chain position, so
// every conforming node would flip at the identical share. active() reads
// lane.next_pos() exactly as the proto's mrr_active() (next_pos > activation_pos).
struct MmrShadowGate {
    std::uint64_t activation_pos = UINT64_MAX;   // ★ DEFAULT OFF (never activates)
    bool active(const v37::Lane& l) const { return l.next_pos() > activation_pos; }
};

// ── MMR permanence shadow ─────────────────────────────────────────────────────
class MmrPermanenceShadow {
public:
    // Format bounds: leaf_count is a u64, so at most 64 peaks and an MMR path of
    // at most 63 siblings; the "V37P" side-commitment payload is fixed-width.
    static constexpr std::size_t MRR_MMR_MAX_PEAKS = 64;
    static constexpr std::size_t MRR_MMR_MAX_PATH = 63;
    static constexpr std::size_t V37P_PAYLOAD_BYTES = 4 + 8 + 32;   // tag||leaf_count||root
    // How many front buckets per level the pre-push snapshot retains. A push
    // grows cover by exactly one, so at most one whole bucket (>= rollup
    // positions) leaves the window per push; the front of each level holds the
    // globally-oldest candidates. 8 is generous head-room (the KAT asserts the
    // detection window is never exhausted).
    static constexpr std::size_t SNAP_FRONT = 8;

    explicit MmrPermanenceShadow(MmrShadowGate gate = {}) : m_gate(gate) {}

    // ── read-only accessors ──────────────────────────────────────────────────
    const PeakSet& mmr() const { return m_mmr; }
    bytes32 mmr_root() const { return mmr_bag(m_mmr.peaks); }
    const MmrShadowGate& gate() const { return m_gate; }
    const std::vector<bytes32>& leaf_log() const { return m_log; }
    const std::vector<std::vector<std::uint8_t>>& leaf_payload_log() const { return m_log_payloads; }
    bool active(const v37::Lane& l) const { return m_gate.active(l); }

    // ── observation (mirror of the proto's evict_oldest_bucket seal + rewind) ─
    // The lane exposes no eviction hook, so observation brackets each mutation:
    //   before_push(lane);  lane.push(...);  after_push(lane, id_key);
    //   lane.rewind(d);     after_rewind(lane);
    // id_key MUST be the SAME canonical identity resolver the lane's digest()
    // uses, so the sealed "V37B" leaf is byte-equal to the lane's own bucket leaf.

    // Snapshot the front buckets of each level (immutable content while live).
    void before_push(const v37::Lane& lane) {
        m_snapshot.clear();
        const auto& levels = lane.levels();
        for (std::size_t k = 0; k < levels.size(); ++k) {
            const auto& lvl = levels[k];
            const std::size_t take = lvl.size() < SNAP_FRONT ? lvl.size() : SNAP_FRONT;
            for (std::size_t i = 0; i < take; ++i) m_snapshot.push_back(Snap{k, lvl[i]});
        }
    }

    // Detect carried evictions since before_push and append their leaves.
    template <typename Resolver>
    void after_push(const v37::Lane& lane, Resolver&& id_key) {
        const auto& levels = lane.levels();
        const bool gate_on = m_gate.active(lane);
        std::vector<const Snap*> evicted;
        // Detection-window tripwire (generalizes the KAT-P1 harness's
        // `gone < pre.size() || pre.size() < 4`): a snapshot bucket that left the
        // live set counts as "gone" for its level. The window is complete unless a
        // single level shed every one of its SNAP_FRONT snapshotted front buckets
        // in this one mutation — then an evicted bucket beyond the snapshot could
        // have been missed. A push grows cover by exactly one, so it sheds at most
        // one whole bucket: this is a mis-sizing guard, never expected to trip.
        std::vector<std::size_t> snapped(levels.size(), 0), gone(levels.size(), 0);
        for (const auto& s : m_snapshot) {
            if (s.level < snapped.size()) ++snapped[s.level];
            if (still_live(levels, s.level, s.b.pos_lo)) continue;   // present after: not gone
            if (s.level < gone.size()) ++gone[s.level];
            if (covered(levels, s.b.pos_lo)) continue;               // folded up a level: parent seals
            if (!gate_on) continue;                                  // shadow gate inactive
            if (s.b.pos_lo < m_gate.activation_pos) continue;        // straddling / pre-activation bucket
            evicted.push_back(&s);
        }
        m_snapshot_full = true;
        for (std::size_t k = 0; k < levels.size(); ++k)
            if (snapped[k] == SNAP_FRONT && gone[k] == SNAP_FRONT) m_snapshot_full = false;
        // Eviction is globally-oldest-first, i.e. ascending pos_lo — the exact
        // order the proto appends in. Sorting reproduces it even if a single push
        // shed more than one bucket.
        std::sort(evicted.begin(), evicted.end(),
                  [](const Snap* a, const Snap* b) { return a->b.pos_lo < b->b.pos_lo; });
        for (const Snap* s : evicted) {
            std::vector<std::uint8_t> payload = bucket_leaf_payload(s->level, s->b, id_key);
            bytes32 lf = leaf_hash(payload);
            m_log_meta.push_back(SealMeta{s->level, s->b.pos_lo, s->b.pos_hi});
            m_log.push_back(lf);
            m_log_payloads.push_back(std::move(payload));
            mmr_append(m_mmr, lf);
        }
        set_hist(lane.next_pos(), m_log.size());
        m_snapshot.clear();
    }

    // Reconcile after lane.rewind(): un-evicted buckets re-enter the window, so
    // the log truncates to the length recorded at the rewound next_pos (a prefix,
    // since eviction is oldest-first and un-eviction newest-first) and the peaks
    // are rebuilt from that prefix (bit-identical to the incremental append).
    void after_rewind(const v37::Lane& lane) {
        const u64 np = lane.next_pos();
        std::size_t keep = (np < m_hist.size()) ? m_hist[np] : m_log.size();
        if (keep > m_log.size()) keep = m_log.size();
        if (keep == m_log.size()) return;
        m_log.resize(keep);
        m_log_payloads.resize(keep);
        m_log_meta.resize(keep);
        rebuild_peaks_from_prefix(keep);
    }

    // Drop all observation state (for a fresh rebuild over a reorged path; the
    // permanent record is redriven from the new canonical history).
    void reset(MmrShadowGate gate) {
        m_gate = gate;
        m_mmr = PeakSet{};
        m_log.clear();
        m_log_payloads.clear();
        m_log_meta.clear();
        m_snapshot.clear();
        m_hist.clear();
    }
    void reset() { reset(m_gate); }

    // ── the OFF-guarded side commitment ──────────────────────────────────────
    // shadow_digest == lane.digest() VERBATIM when the gate is inactive (byte-
    // identity is STRUCTURAL, not merely tested: the OFF branch never touches the
    // peak-root). When active it mixes the "V37P" peak-root leaf into the SHADOW
    // value only — never into v37::Lane::build_leaves(), so canon's consensus
    // merkle root is untouched regardless of gate state.
    template <typename Resolver>
    bytes32 shadow_digest(const v37::Lane& lane, Resolver&& id_key) const {
        bytes32 d = lane.digest(id_key);
        if (!m_gate.active(lane)) return d;
        std::vector<std::uint8_t> pl = mmr_root_payload(m_mmr.leaf_count, mmr_root());
        return interior_hash(d, leaf_hash(pl));
    }

    // ── MMR primitives (ported verbatim from v37retro; canon hash discipline) ─
    // Binary-counter append: merge the new leaf upward while the low bit is set.
    static void mmr_append(PeakSet& ps, const bytes32& leaf) {
        bytes32 h = leaf;
        u64 n = ps.leaf_count;
        while (n & 1) {
            h = interior_hash(ps.peaks.back(), h);
            ps.peaks.pop_back();
            n >>= 1;
        }
        ps.peaks.push_back(h);
        ps.leaf_count += 1;
    }
    // Bag the peaks to one root: right fold, tallest peak outermost. A single
    // peak is its own bag; the empty range bags to all-zero bytes.
    static bytes32 mmr_bag(const std::vector<bytes32>& peaks) {
        bytes32 r{};
        if (peaks.empty()) return r;
        r = peaks.back();
        for (std::size_t i = peaks.size() - 1; i-- > 0;)
            r = interior_hash(peaks[i], r);
        return r;
    }
    // The "V37P" side-commitment payload: tag || leaf_count || bagged root.
    static std::vector<std::uint8_t> mmr_root_payload(u64 leaf_count, const bytes32& root) {
        std::vector<std::uint8_t> b;
        b.reserve(V37P_PAYLOAD_BYTES);
        append_bytes(b, "V37P", 4);
        append_u64(b, leaf_count);
        b.insert(b.end(), root.begin(), root.end());
        return b;
    }

    // ── inclusion proofs (archival build + stateless verify) ──────────────────
    struct MmrProof {
        u64 leaf_count = 0;
        u64 index = 0;
        std::vector<bytes32> path;    // siblings bottom-up inside the leaf's peak
        std::vector<bytes32> peaks;   // every peak, tallest first (verifier re-bags)
    };
    // Build the proof from the full leaf log (leaves.size() must equal the
    // leaf_count the root was committed at).
    static MmrProof mmr_proof(const std::vector<bytes32>& leaves, u64 idx) {
        MmrProof p;
        p.leaf_count = static_cast<u64>(leaves.size());
        p.index = idx;
        if (idx >= p.leaf_count) return p;
        const u64 n = p.leaf_count;
        u64 offset = 0;
        for (int h = 63; h >= 0; --h) {
            if (!((n >> h) & 1)) continue;
            const u64 span = u64(1) << h;
            std::vector<bytes32> level(leaves.begin() + static_cast<long>(offset),
                                       leaves.begin() + static_cast<long>(offset + span));
            if (idx >= offset && idx < offset + span) {
                u64 j = idx - offset;
                std::vector<bytes32> lv = level;
                while (lv.size() > 1) {
                    p.path.push_back(lv[j ^ 1]);
                    std::vector<bytes32> next;
                    next.reserve(lv.size() / 2);
                    for (std::size_t i = 0; i + 1 < lv.size(); i += 2)
                        next.push_back(interior_hash(lv[i], lv[i + 1]));
                    lv = std::move(next);
                    j >>= 1;
                }
            }
            p.peaks.push_back(perfect_root(std::move(level)));
            offset += span;
        }
        return p;
    }
    // Stateless verifier (lite client): climb the path to the peak the index
    // falls in, check it against the supplied peak, re-bag all peaks to the
    // committed root. Structure comes from leaf_count only.
    static bool mmr_verify(const bytes32& bagged_root, const bytes32& leaf,
                           const MmrProof& p) {
        const u64 n = p.leaf_count;
        if (n == 0 || p.index >= n) return false;
        if (p.peaks.size() != popcount64(n)) return false;
        u64 offset = 0;
        std::size_t peak_idx = 0;
        int height = -1;
        for (int h = 63; h >= 0; --h) {
            if (!((n >> h) & 1)) continue;
            const u64 span = u64(1) << h;
            if (p.index >= offset && p.index < offset + span) { height = h; break; }
            offset += span;
            ++peak_idx;
        }
        if (height < 0 || p.path.size() != static_cast<std::size_t>(height)) return false;
        bytes32 hh = leaf;
        u64 j = p.index - offset;
        for (const bytes32& sib : p.path) {
            hh = (j & 1) ? interior_hash(sib, hh) : interior_hash(hh, sib);
            j >>= 1;
        }
        if (hh != p.peaks[peak_idx]) return false;
        return mmr_bag(p.peaks) == bagged_root;
    }

    // ── the evicted-bucket "V37B" leaf (byte-equal to the lane's live leaf) ───
    // A verbatim mirror of v37::Lane::build_leaves()'s bucket leaf: canon's
    // Bucket carries no provenance mix, so the payload is canon's 84 bytes.
    template <typename Resolver>
    static bytes32 bucket_leaf(std::size_t level, const v37::Bucket& b, Resolver&& id_key) {
        return leaf_hash(bucket_leaf_payload(level, b, id_key));
    }
    template <typename Resolver>
    static std::vector<std::uint8_t> bucket_leaf_payload(std::size_t k, const v37::Bucket& bkt,
                                                         Resolver&& id_key) {
        std::vector<std::uint8_t> b;
        append_bytes(b, "V37B", 4);
        append_u64(b, static_cast<u64>(k));
        append_u64(b, bkt.pos_lo);
        append_u64(b, bkt.pos_hi);
        append_u128(b, bkt.raw_work);
        append_u64(b, bkt.epoch_tag);
        bytes32 ch = comp_hash(bkt, id_key);
        b.insert(b.end(), ch.begin(), ch.end());
        return b;
    }
    // Composition hash, canonical-identity order — identical to canon's.
    template <typename Resolver>
    static bytes32 comp_hash(const v37::Bucket& b, Resolver&& id_key) {
        std::vector<std::pair<bytes32, const v37::CompEntry*>> rows;
        rows.reserve(b.comp.size());
        for (const auto& e : b.comp) rows.emplace_back(id_key(e.miner), &e);
        std::sort(rows.begin(), rows.end(),
                  [](const auto& a, const auto& c) { return a.first < c.first; });
        std::vector<std::uint8_t> buf;
        for (const auto& [key, e] : rows) {
            buf.insert(buf.end(), key.begin(), key.end());
            append_u256(buf, e->scaled);
            append_u128(buf, e->raw);
        }
        return v37::sha256d(buf);
    }

    static std::size_t popcount64(u64 x) {
        std::size_t c = 0;
        while (x) { x &= x - 1; ++c; }
        return c;
    }

private:
    struct Snap { std::size_t level; v37::Bucket b; };
    struct SealMeta { std::size_t level; u64 pos_lo, pos_hi; };

    // ── canon serialization helpers (fixed-width LE, §8.3) ────────────────────
    static void append_bytes(std::vector<std::uint8_t>& b, const char* p, std::size_t n) {
        b.insert(b.end(), p, p + n);
    }
    static void append_u64(std::vector<std::uint8_t>& b, u64 x) {
        for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
    }
    static void append_u128(std::vector<std::uint8_t>& b, u128 x) {
        append_u64(b, static_cast<u64>(x));
        append_u64(b, static_cast<u64>(x >> 64));
    }
    static void append_u256(std::vector<std::uint8_t>& b, const v37::U256& x) {
        for (int i = 0; i < 4; ++i) append_u64(b, x.v[i]);
    }
    static bytes32 leaf_hash(const std::vector<std::uint8_t>& payload) {
        std::vector<std::uint8_t> b;
        b.reserve(payload.size() + 1);
        b.push_back(0x00);
        b.insert(b.end(), payload.begin(), payload.end());
        return v37::sha256d(b);
    }
    static bytes32 interior_hash(const bytes32& l, const bytes32& r) {
        std::uint8_t b[65];
        b[0] = 0x01;
        std::copy(l.begin(), l.end(), b + 1);
        std::copy(r.begin(), r.end(), b + 33);
        return v37::sha256d(b, 65);
    }
    // Root of a perfect (power-of-two) leaf level — one MMR peak.
    static bytes32 perfect_root(std::vector<bytes32> level) {
        while (level.size() > 1) {
            std::vector<bytes32> next;
            next.reserve(level.size() / 2);
            for (std::size_t i = 0; i + 1 < level.size(); i += 2)
                next.push_back(interior_hash(level[i], level[i + 1]));
            level = std::move(next);
        }
        return level[0];
    }

    // A snapshot bucket is still live iff a bucket with its pos_lo sits in the
    // same level (buckets are strictly ordered by pos_lo, so we can stop early).
    static bool still_live(const std::vector<std::deque<v37::Bucket>>& levels,
                           std::size_t level, u64 pos_lo) {
        if (level >= levels.size()) return false;
        for (const auto& b : levels[level]) {
            if (b.pos_lo == pos_lo) return true;
            if (b.pos_lo > pos_lo) return false;
        }
        return false;
    }
    // A gone bucket was FOLDED (not evicted) iff a live bucket still covers its
    // pos_lo — its work moved up a level rather than leaving the window.
    static bool covered(const std::vector<std::deque<v37::Bucket>>& levels, u64 pos_lo) {
        for (const auto& lvl : levels)
            for (const auto& b : lvl)
                if (b.pos_lo <= pos_lo && pos_lo <= b.pos_hi) return true;
        return false;
    }

    void set_hist(u64 next_pos, std::size_t sz) {
        if (m_hist.size() <= next_pos) m_hist.resize(next_pos + 1, 0);
        m_hist[next_pos] = sz;
    }
    // Recompute the peaks as the perfect-subtree roots of the binary
    // decomposition of `keep` — the archival form, bit-identical to the
    // incremental binary-counter append (the fundamental MMR identity).
    void rebuild_peaks_from_prefix(std::size_t keep) {
        m_mmr.peaks.clear();
        m_mmr.leaf_count = static_cast<u64>(keep);
        const u64 n = static_cast<u64>(keep);
        std::size_t off = 0;
        for (int h = 63; h >= 0; --h) {
            if (!((n >> h) & 1)) continue;
            const std::size_t span = std::size_t(1) << h;
            std::vector<bytes32> lvl(m_log.begin() + static_cast<long>(off),
                                     m_log.begin() + static_cast<long>(off + span));
            m_mmr.peaks.push_back(perfect_root(std::move(lvl)));
            off += span;
        }
    }

    MmrShadowGate m_gate;
    PeakSet m_mmr;
    std::vector<bytes32> m_log;                              // sealed leaves, seal order
    std::vector<std::vector<std::uint8_t>> m_log_payloads;   // raw "V37B" payloads (archival)
    std::vector<SealMeta> m_log_meta;                        // (level, pos_lo, pos_hi) per seal
    std::vector<Snap> m_snapshot;                            // pre-push front-bucket snapshot
    bool m_snapshot_full = true;                             // detection window not exhausted
    std::vector<std::size_t> m_hist;                         // hist[next_pos] = log size
public:
    bool snapshot_window_ok() const { return m_snapshot_full; }
};

} // namespace c2pool::v37n
