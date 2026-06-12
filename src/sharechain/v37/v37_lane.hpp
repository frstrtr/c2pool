#pragma once
// V37 MRR roundabout — one sharechain lane, ORIGIN-BIN temporal model.
// Spec: c2pool-v37-the-temporal-levels.md v1.0 (NORMATIVE, T-OQ1 ratified) +
// docs/c2pool-v37-mrr-roundabout-buffer.md v3.0 (§4.2 machinery, §8 rules).
//
// The consensus clock is the mainchain block height committed in every
// share/receipt ("bin"). Decay, vesting, the window, folds and epochs are
// all indexed by origin bin — work decays by the time it was PERFORMED,
// not the time it was accounted (RDWR receipts credit their origin bin).
//
// CONSENSUS-DETERMINISM (§8.3): structure events fire only on clock
// advance (a push whose bin exceeds the current clock), in fixed order:
//   (1) epoch rebuild while t - B >= E      (B advances by E; journal seals)
//   (2) fold of bin bands older than the fine horizon (band-aligned)
//   (3) eviction of whole buckets older than the window
// then the insert itself. Non-advancing pushes (same-bin work, receipts)
// only insert. Every input is committed share/receipt bytes.

#include <algorithm>
#include <cstdint>
#include <deque>
#include <map>
#include <stdexcept>
#include <vector>

#include "v37_fixed.hpp"
#include "v37_hash.hpp"

namespace v37 {

using MinerId = std::uint32_t;

struct LaneParams {
    u64 window_bins = 576;       // W (~24 h LTC); 0 = INFINITE (archive/
                                 // reputation lanes, AR-OQ1: never evict)
    u64 fine_bins = 64;          // open-bin horizon (Present); must exceed n_ctx
    u64 rollup = 8;              // bins per level-1 bucket (band-aligned)
    std::vector<u64> level_caps = {80};  // bucket counts for levels >= 1
    u64 half_life = 144;         // bins (= W/4); 0 = NO DECAY (archive)
    u64 epoch_bins = 256;        // E (needs lambda^-(E-1) < 4: E <~ 2*HL)
    u64 n_ctx = 2;               // receipt context window, bins (RDWR N_CTX)
    u64 journal_depth = 64;      // D (OQ-7)
    u64 vest_threshold_shares = 4320;  // §4.2a (0 disables)

    std::size_t levels() const { return 1 + level_caps.size(); }
};

// L0 slot flag bits — annotation-only, never digest leaves, never weights.
constexpr std::uint32_t L0F_FEE_SHARE     = 0x01;
constexpr std::uint32_t L0F_STALE_DOA     = 0x02;
constexpr std::uint32_t L0F_AUTHORITY_MSG = 0x08;  // V36-compatible bit
constexpr std::uint32_t L0F_MINER_MSG     = 0x10;  // miner-messages doc v1.1
constexpr std::uint32_t L0F_LATE          = 0x20;  // ELL alternative (reserved)
constexpr std::uint32_t L0F_UNCLE         = 0x40;  // uncle-DAG fallback (reserved)
constexpr std::uint32_t L0F_RECEIPT       = 0x80;  // RDWR work receipt (primary)

struct L0Slot {
    u64 w_raw = 0;       // work(T_origin), verbatim (F-1; feeds epoch rebuild)
    u128 w_scaled = 0;   // origin-bin scaled contribution, Q62 (see scaled_for)
    MinerId miner = 0;
    std::uint32_t flags = 0;
};

struct OpenBin {                 // the Present: one origin bin, still writable
    u64 bin = 0;
    std::vector<L0Slot> entries; // arrival (= consensus push) order
};

struct CompEntry {               // (miner, w_scaled, w_raw) triple, F-1
    MinerId miner = 0;
    U256 scaled;                 // in the bucket's epoch frame
    u128 raw = 0;
};

struct Bucket {                  // settled bin band (the Past) — immutable
    u64 bin_lo = 0, bin_hi = 0;  // band-aligned origin-bin span
    u64 epoch_tag = 0;           // B at close; shift applied at read/evict
    U256 scaled_sum;
    u128 raw_work = 0;           // F-1: per-time-band settlement leaf
    std::vector<CompEntry> comp; // miner-id order (deterministic)
};

class Lane {
public:
    explicit Lane(const LaneParams& p) : m_p(p) {
        if (p.rollup == 0) throw std::invalid_argument("v37: zero rollup");
        if (p.n_ctx == 0) throw std::invalid_argument("v37: zero n_ctx");
        if (p.fine_bins <= p.n_ctx)
            throw std::invalid_argument(
                "v37: fine horizon must exceed the receipt context window "
                "(receipts must always land in open bins)");
        if (p.window_bins != 0 && p.window_bins < p.fine_bins + p.rollup)
            throw std::invalid_argument("v37: window must exceed fine+rollup");
        if (p.level_caps.empty())
            throw std::invalid_argument("v37: at least one bucket level");
        for (std::size_t k = 0; k + 1 < p.level_caps.size(); ++k)
            if (p.level_caps[k] < p.rollup)
                throw std::invalid_argument(
                    "v37: inner level cap smaller than roll-up factor");
        // decay[] covers query depths [0,E) and rebuild/insert depths up to
        // E + fine + n_ctx; epoch_shift[] covers the max bucket age.
        u64 max_depth = p.epoch_bins + p.fine_bins + p.n_ctx + 2;
        u64 max_epochs = p.window_bins / p.epoch_bins + 4;  // shift_at extends
        m_tab.init(p.half_life, p.epoch_bins, max_depth, max_epochs);
        m_levels.resize(p.level_caps.size());
    }

    const LaneParams& params() const { return m_p; }
    const DecayTables& tables() const { return m_tab; }
    bool started() const { return m_started; }
    u64 clock() const { return m_t; }            // current bin (mainchain ht)
    u64 epoch_base() const { return m_B; }
    u64 event_count() const { return m_events; }
    const U256& acc_total() const { return m_acc_total; }
    u128 raw_total() const { return m_raw_total; }
    const std::map<MinerId, U256>& acc() const { return m_acc; }
    const std::map<u64, OpenBin>& open_bins() const { return m_open; }
    const std::vector<std::deque<Bucket>>& levels() const { return m_levels; }
    const U256& open_scaled_sum() const { return m_open_scaled_sum; }
    u128 open_raw_sum() const { return m_open_raw_sum; }

    // ── push: O(1) amortized; structure events only on clock advance ──────
    void push(MinerId miner, u64 w_raw, std::uint32_t flags, u64 bin) {
        if (w_raw == 0)
            throw std::invalid_argument("v37: zero-work share");
        u64 prev_t = m_t;
        bool prev_started = m_started;
        if (!m_started) {
            m_started = true;
            m_t = bin;
            m_B = bin;
        } else if (bin > m_t) {
            advance_clock(bin);                    // (1)(2)(3)
        } else if (m_t - bin > m_p.n_ctx) {
            throw std::invalid_argument(
                "v37: origin bin beyond the receipt context window");
        }
        u128 w_scaled = scaled_for(w_raw, bin);    // insert
        L0Slot s{w_raw, w_scaled, miner, flags};
        m_open[bin].bin = bin;
        m_open[bin].entries.push_back(s);
        m_acc[miner] += U256::from_u128(w_scaled);
        m_acc_total += U256::from_u128(w_scaled);
        m_raw_total += w_raw;
        m_open_scaled_sum += U256::from_u128(w_scaled);
        m_open_raw_sum += w_raw;
        m_events += 1;
        Op op; op.type = Op::Type::Push; op.slot = s; op.bin = bin;
        op.prev_t = prev_t; op.prev_started = prev_started;
        journal_push(std::move(op));
    }

    // ── queries (head factor = lambda^(t - B), Q62) ───────────────────────
    U256 decayed_weight(MinerId m) const {
        auto it = m_acc.find(m);
        if (it == m_acc.end()) return U256();
        return it->second.mul_q(head_decay());
    }
    U256 decayed_total() const { return m_acc_total.mul_q(head_decay()); }

    std::map<MinerId, U256> payout_map() const {
        std::map<MinerId, U256> out;
        u64 f = head_decay();
        for (const auto& [m, a] : m_acc) out[m] = a.mul_q(f);
        return out;
    }

    // Vesting (§4.2a): threshold in event-EMA share-work units.
    u64 vesting_factor(MinerId m) const {
        if (m_p.vest_threshold_shares == 0 || m_events == 0) return Q_ONE;
        u64 ema = static_cast<u64>(m_raw_total / m_events);
        if (ema == 0) return Q_ONE;
        u128 tw = u128(ema) * m_p.vest_threshold_shares;
        U256 threshold = U256::from_u128(tw).shl(FRAC_BITS);
        return U256::ratio_q(decayed_weight(m), threshold);
    }
    std::map<MinerId, U256> vested_payout_map() const {
        std::map<MinerId, U256> out;
        u64 f = head_decay();
        for (const auto& [m, a] : m_acc) {
            U256 dw = a.mul_q(f);
            u64 vf = (m_p.vest_threshold_shares == 0) ? Q_ONE
                                                      : vesting_factor(m);
            out[m] = dw.mul_q(vf);
        }
        return out;
    }

    // Per-time-band raw delivered work over origin bins [lo, hi]: open bins
    // individually, settled bands when fully inside (F-1 reading; settlement
    // bands MUST align to band boundaries).
    u128 raw_work_in_span(u64 lo, u64 hi) const {
        u128 sum = 0;
        for (const auto& [b, ob] : m_open)
            if (b >= lo && b <= hi)
                for (const auto& e : ob.entries) sum += e.w_raw;
        for (const auto& lvl : m_levels)
            for (const auto& bkt : lvl)
                if (bkt.bin_lo >= lo && bkt.bin_hi <= hi) sum += bkt.raw_work;
        return sum;
    }

    // ── reorg rewind (§6.2, OQ-7): unchanged semantics, bin-aware undo ────
    bool rewind(u64 d) {
        u64 pushes = 0;
        bool boundary = false;
        for (const auto& op : m_journal) {
            if (op.type == Op::Type::Push) ++pushes;
            else if (op.type == Op::Type::RebuildBoundary) boundary = true;
        }
        if (d > pushes) return false;
        if (boundary && d == pushes) return false;  // can't undo the rebuild
        u64 undone = 0;
        while (undone < d) {
            Op op = m_journal.back();
            m_journal.pop_back();
            switch (op.type) {
            case Op::Type::Push:  undo_push(op);  ++undone; break;
            case Op::Type::FoldL0: undo_fold_l0(op); break;
            case Op::Type::FoldLevel: undo_fold_level(op); break;
            case Op::Type::Evict: undo_evict(op); break;
            case Op::Type::RebuildBoundary:
                throw std::logic_error("v37: rewind crossed rebuild sentinel");
            }
        }
        // trailing folds/evicts belong to the landing push's clock advance
        // and must be undone with it (state = before the share arrived)
        while (!m_journal.empty() &&
               (m_journal.back().type == Op::Type::FoldL0 ||
                m_journal.back().type == Op::Type::FoldLevel ||
                m_journal.back().type == Op::Type::Evict)) {
            Op op = m_journal.back();
            m_journal.pop_back();
            if (op.type == Op::Type::FoldL0) undo_fold_l0(op);
            else if (op.type == Op::Type::FoldLevel) undo_fold_level(op);
            else undo_evict(op);
        }
        return true;
    }

    // ── Merkle digest (§8.5, OQ-4 + OQ-M5) over the origin-bin state ──────
    struct MerkleProof {
        u64 leaf_count = 0;
        u64 index = 0;
        std::vector<bytes32> path;
    };
    template <typename Resolver>
    bytes32 digest(Resolver&& id_key) const {
        return merkle_root(build_leaves(id_key));
    }
    template <typename Resolver>
    bool acc_proof(MinerId m, Resolver&& id_key, bytes32& leaf_out,
                   MerkleProof& proof_out) const {
        if (!m_acc.count(m)) return false;
        auto leaves = build_leaves(id_key);
        bytes32 key = id_key(m);
        std::vector<std::uint8_t> payload;
        append_bytes(payload, "V37A", 4);
        payload.insert(payload.end(), key.begin(), key.end());
        append_u256(payload, m_acc.at(m));
        bytes32 target = leaf_hash(payload);
        u64 idx = 0;
        for (; idx < leaves.size(); ++idx)
            if (leaves[idx] == target) break;
        if (idx == leaves.size()) return false;
        leaf_out = target;
        proof_out = make_proof(leaves, idx);
        return true;
    }
    static bool verify_proof(const bytes32& root, const bytes32& leaf,
                             const MerkleProof& p) {
        bytes32 h = leaf;
        u64 idx = p.index, size = p.leaf_count;
        std::size_t used = 0;
        if (idx >= size || size == 0) return false;
        while (size > 1) {
            bool odd_last = (size & 1) && idx == size - 1;
            if (!odd_last) {
                if (used >= p.path.size()) return false;
                const bytes32& sib = p.path[used++];
                h = (idx & 1) ? interior_hash(sib, h) : interior_hash(h, sib);
            }
            idx /= 2;
            size = (size + 1) / 2;
        }
        return used == p.path.size() && h == root;
    }

    // ── OQ-2 exact rebuild from durable records (origin-bin indexed) ──────
    // Public for tests; refuses off the positional boundary.
    void epoch_rebuild() {
        if (!m_started || m_t - m_B < m_p.epoch_bins)
            throw std::logic_error("v37: epoch_rebuild before the boundary");
        u64 B_new = m_B + m_p.epoch_bins;
        m_acc.clear();
        m_acc_total = U256();
        m_open_scaled_sum = U256();
        for (auto& [b, ob] : m_open) {
            for (auto& s : ob.entries) {
                s.w_scaled = (b >= B_new)
                                 ? u128(s.w_raw) * m_tab.inv_decay[b - B_new]
                                 : u128(s.w_raw) * m_tab.decay[B_new - b];
                m_acc[s.miner] += U256::from_u128(s.w_scaled);
                m_acc_total += U256::from_u128(s.w_scaled);
                m_open_scaled_sum += U256::from_u128(s.w_scaled);
            }
        }
        for (const auto& lvl : m_levels) {
            for (const auto& bkt : lvl) {
                u64 f = m_tab.shift_at((B_new - bkt.epoch_tag) / m_p.epoch_bins);
                for (const auto& e : bkt.comp) {
                    U256 c = e.scaled.mul_q(f);
                    m_acc[e.miner] += c;
                    m_acc_total += c;
                }
            }
        }
        m_B = B_new;
        m_journal.clear();
        Op b2; b2.type = Op::Type::RebuildBoundary;
        m_journal.push_back(std::move(b2));
    }

private:
    struct Op {
        enum class Type { Push, FoldL0, FoldLevel, Evict, RebuildBoundary };
        Type type = Type::Push;
        L0Slot slot;                 // Push
        u64 bin = 0;                 // Push: origin bin
        u64 prev_t = 0;              // Push: clock before this push
        bool prev_started = false;   // Push: lane started before this push
        Bucket bucket;               // fold result / evicted bucket
        std::vector<OpenBin> folded_bins;     // FoldL0: removed open bins
        std::vector<Bucket> folded_children;  // FoldLevel
        std::size_t level_index = 0;
        std::vector<std::pair<MinerId, U256>> subtracted;  // Evict
    };

    u64 head_decay() const {
        if (!m_started) return Q_ONE;
        return m_tab.decay[m_t - m_B];   // t - B in [0, E)
    }

    u128 scaled_for(u64 w_raw, u64 bin) const {
        return (bin >= m_B) ? u128(w_raw) * m_tab.inv_decay[bin - m_B]
                            : u128(w_raw) * m_tab.decay[m_B - bin];
    }

    void advance_clock(u64 new_t) {
        m_t = new_t;
        while (m_t - m_B >= m_p.epoch_bins) epoch_rebuild();   // (1)
        fold_ready();                                          // (2)
        evict_old();                                           // (3)
    }

    // (2) fold band-aligned bin bands fully older than the fine horizon
    void fold_ready() {
        while (!m_open.empty()) {
            u64 oldest = m_open.begin()->first;
            u64 band = oldest / m_p.rollup;
            u64 band_lo = band * m_p.rollup;
            u64 band_hi = band_lo + m_p.rollup - 1;
            if (band_hi + m_p.fine_bins >= m_t) break;  // still the Present
            Bucket b;
            b.bin_lo = band_lo;
            b.bin_hi = band_hi;
            b.epoch_tag = m_B;
            std::map<MinerId, CompEntry> agg;
            Op op; op.type = Op::Type::FoldL0; op.level_index = 0;
            for (u64 bi = band_lo; bi <= band_hi; ++bi) {
                auto it = m_open.find(bi);
                if (it == m_open.end()) continue;  // empty bin in the band
                for (const auto& s : it->second.entries) {
                    b.scaled_sum += U256::from_u128(s.w_scaled);
                    b.raw_work += s.w_raw;
                    auto& e = agg[s.miner];
                    e.miner = s.miner;
                    e.scaled += U256::from_u128(s.w_scaled);
                    e.raw += s.w_raw;
                    m_open_scaled_sum -= U256::from_u128(s.w_scaled);
                    m_open_raw_sum -= s.w_raw;
                }
                op.folded_bins.push_back(std::move(it->second));
                m_open.erase(it);
            }
            for (auto& [m, e] : agg) b.comp.push_back(e);
            op.bucket = b;
            m_levels[0].push_back(std::move(b));
            m_journal.push_back(std::move(op));
            cascade_folds();
        }
    }

    void cascade_folds() {
        for (std::size_t k = 0; k + 1 < m_levels.size(); ++k) {
            if (m_levels[k].size() < m_p.level_caps[k]) continue;
            Bucket b;
            b.epoch_tag = m_B;
            std::map<MinerId, CompEntry> agg;
            Op op; op.type = Op::Type::FoldLevel; op.level_index = k;
            for (u64 i = 0; i < m_p.rollup && !m_levels[k].empty(); ++i) {
                Bucket child = m_levels[k].front();
                m_levels[k].pop_front();
                u64 f = m_tab.shift_at((m_B - child.epoch_tag) / m_p.epoch_bins);
                if (i == 0) b.bin_lo = child.bin_lo;
                b.bin_hi = child.bin_hi;
                b.scaled_sum += child.scaled_sum.mul_q(f);
                b.raw_work += child.raw_work;
                for (const auto& e : child.comp) {
                    auto& a = agg[e.miner];
                    a.miner = e.miner;
                    a.scaled += e.scaled.mul_q(f);
                    a.raw += e.raw;
                }
                op.folded_children.push_back(std::move(child));
            }
            for (auto& [m, e] : agg) b.comp.push_back(e);
            op.bucket = b;
            m_levels[k + 1].push_back(std::move(b));
            m_journal.push_back(std::move(op));
        }
    }

    // (3) evict whole buckets fully older than the window (time-true OQ-1);
    // window_bins == 0 => infinite window: archive lanes never evict.
    void evict_old() {
        if (m_p.window_bins == 0) return;
        for (;;) {
            std::size_t best = SIZE_MAX;
            for (std::size_t k = 0; k < m_levels.size(); ++k) {
                if (m_levels[k].empty()) continue;
                if (best == SIZE_MAX ||
                    m_levels[k].front().bin_lo < m_levels[best].front().bin_lo)
                    best = k;
            }
            if (best == SIZE_MAX) return;
            if (m_levels[best].front().bin_hi + m_p.window_bins >= m_t)
                return;                            // still inside the window
            Bucket b = m_levels[best].front();
            m_levels[best].pop_front();
            u64 f = m_tab.shift_at((m_B - b.epoch_tag) / m_p.epoch_bins);
            Op op; op.type = Op::Type::Evict; op.level_index = best;
            for (const auto& e : b.comp) {
                U256 sub = e.scaled.mul_q(f);
                m_acc[e.miner] -= sub;
                m_acc_total -= sub;
                if (m_acc[e.miner].is_zero()) m_acc.erase(e.miner);
                op.subtracted.emplace_back(e.miner, sub);
            }
            m_raw_total -= b.raw_work;
            op.bucket = std::move(b);
            m_journal.push_back(std::move(op));
        }
    }

    void journal_push(Op op) {
        m_journal.push_back(std::move(op));
        u64 pushes = 0;
        std::size_t keep_from = 0;
        for (std::size_t i = m_journal.size(); i-- > 0;) {
            if (m_journal[i].type == Op::Type::Push) {
                if (++pushes == m_p.journal_depth) { keep_from = i; break; }
            }
        }
        if (pushes < m_p.journal_depth || keep_from == 0) return;
        // keep everything attached to the kept-oldest push (its preceding
        // ops are only ever this call's folds/evicts or the sentinel —
        // structure ops follow clock advances, which precede the insert)
        while (keep_from > 0 &&
               m_journal[keep_from - 1].type != Op::Type::Push)
            --keep_from;
        if (keep_from > 0)
            m_journal.erase(m_journal.begin(),
                            m_journal.begin() + static_cast<long>(keep_from));
    }

    void undo_push(const Op& op) {
        auto it = m_open.find(op.bin);
        it->second.entries.pop_back();
        if (it->second.entries.empty()) m_open.erase(it);
        const L0Slot& s = op.slot;
        m_acc[s.miner] -= U256::from_u128(s.w_scaled);
        if (m_acc[s.miner].is_zero()) m_acc.erase(s.miner);
        m_acc_total -= U256::from_u128(s.w_scaled);
        m_raw_total -= s.w_raw;
        m_open_scaled_sum -= U256::from_u128(s.w_scaled);
        m_open_raw_sum -= s.w_raw;
        m_events -= 1;
        m_t = op.prev_t;
        m_started = op.prev_started;
    }
    void undo_fold_l0(const Op& op) {
        m_levels[0].pop_back();
        for (auto it = op.folded_bins.rbegin(); it != op.folded_bins.rend();
             ++it) {
            for (const auto& s : it->entries) {
                m_open_scaled_sum += U256::from_u128(s.w_scaled);
                m_open_raw_sum += s.w_raw;
            }
            m_open[it->bin] = *it;
        }
    }
    void undo_fold_level(const Op& op) {
        m_levels[op.level_index + 1].pop_back();
        for (auto it = op.folded_children.rbegin();
             it != op.folded_children.rend(); ++it)
            m_levels[op.level_index].push_front(*it);
    }
    void undo_evict(const Op& op) {
        m_levels[op.level_index].push_front(op.bucket);
        for (const auto& [m, sub] : op.subtracted) {
            m_acc[m] += sub;
            m_acc_total += sub;
        }
        m_raw_total += op.bucket.raw_work;
    }

    // ── Merkle machinery (unchanged rules; origin-bin leaves) ─────────────
    static bytes32 leaf_hash(const std::vector<std::uint8_t>& payload) {
        std::vector<std::uint8_t> b;
        b.reserve(payload.size() + 1);
        b.push_back(0x00);
        b.insert(b.end(), payload.begin(), payload.end());
        return sha256d(b);
    }
    static bytes32 interior_hash(const bytes32& l, const bytes32& r) {
        std::uint8_t b[65];
        b[0] = 0x01;
        std::copy(l.begin(), l.end(), b + 1);
        std::copy(r.begin(), r.end(), b + 33);
        return sha256d(b, 65);
    }
    static bytes32 merkle_root(std::vector<bytes32> level) {
        while (level.size() > 1) {
            std::vector<bytes32> next;
            next.reserve((level.size() + 1) / 2);
            std::size_t i = 0;
            for (; i + 1 < level.size(); i += 2)
                next.push_back(interior_hash(level[i], level[i + 1]));
            if (i < level.size()) next.push_back(level[i]);
            level = std::move(next);
        }
        return level[0];
    }
    static MerkleProof make_proof(const std::vector<bytes32>& leaves, u64 idx) {
        MerkleProof p;
        p.leaf_count = static_cast<u64>(leaves.size());
        p.index = idx;
        std::vector<bytes32> level = leaves;
        while (level.size() > 1) {
            bool odd_last = (level.size() & 1) && idx == level.size() - 1;
            if (!odd_last) p.path.push_back(level[idx ^ 1]);
            std::vector<bytes32> next;
            next.reserve((level.size() + 1) / 2);
            std::size_t i = 0;
            for (; i + 1 < level.size(); i += 2)
                next.push_back(interior_hash(level[i], level[i + 1]));
            if (i < level.size()) next.push_back(level[i]);
            level = std::move(next);
            idx /= 2;
        }
        return p;
    }

    template <typename Resolver>
    std::vector<bytes32> build_leaves(Resolver&& id_key) const {
        std::vector<bytes32> leaves;
        u64 bucket_total = 0;
        for (const auto& lvl : m_levels) bucket_total += lvl.size();
        leaves.reserve(1 + m_acc.size() + bucket_total);
        {   // header leaf: geometry (consensus params), clock state, counts,
            // open (Present) sums — T-OQ4: open partial state is committed
            std::vector<std::uint8_t> h;
            append_bytes(h, "V37H", 4);
            append_u64(h, m_p.window_bins);
            append_u64(h, m_p.fine_bins);
            append_u64(h, m_p.rollup);
            append_u64(h, m_p.half_life);
            append_u64(h, m_p.epoch_bins);
            append_u64(h, m_p.n_ctx);
            append_u64(h, m_p.vest_threshold_shares);
            append_u64(h, static_cast<u64>(m_p.level_caps.size()));
            for (u64 c : m_p.level_caps) append_u64(h, c);
            append_u64(h, m_B);
            append_u64(h, m_t);
            append_u64(h, m_started ? 1 : 0);
            append_u64(h, static_cast<u64>(m_acc.size()));
            append_u64(h, m_events);
            append_u64(h, static_cast<u64>(m_open.size()));
            append_u256(h, m_open_scaled_sum);
            append_u128(h, m_open_raw_sum);
            for (const auto& lvl : m_levels)
                append_u64(h, static_cast<u64>(lvl.size()));
            leaves.push_back(leaf_hash(h));
        }
        {
            std::vector<std::pair<bytes32, const U256*>> rows;
            rows.reserve(m_acc.size());
            for (const auto& [m, a] : m_acc) rows.emplace_back(id_key(m), &a);
            std::sort(rows.begin(), rows.end(),
                      [](const auto& a, const auto& b) { return a.first < b.first; });
            for (const auto& [k, a] : rows) {
                std::vector<std::uint8_t> b;
                append_bytes(b, "V37A", 4);
                b.insert(b.end(), k.begin(), k.end());
                append_u256(b, *a);
                leaves.push_back(leaf_hash(b));
            }
        }
        for (std::size_t k = 0; k < m_levels.size(); ++k) {
            for (const auto& bkt : m_levels[k]) {
                std::vector<std::uint8_t> b;
                append_bytes(b, "V37B", 4);
                append_u64(b, static_cast<u64>(k));
                append_u64(b, bkt.bin_lo);
                append_u64(b, bkt.bin_hi);
                append_u128(b, bkt.raw_work);
                append_u64(b, bkt.epoch_tag);
                auto ch = comp_hash(bkt, id_key);
                b.insert(b.end(), ch.begin(), ch.end());
                leaves.push_back(leaf_hash(b));
            }
        }
        return leaves;
    }

    template <typename Resolver>
    static bytes32 comp_hash(const Bucket& b, Resolver&& id_key) {
        std::vector<std::pair<bytes32, const CompEntry*>> rows;
        rows.reserve(b.comp.size());
        for (const auto& e : b.comp) rows.emplace_back(id_key(e.miner), &e);
        std::sort(rows.begin(), rows.end(),
                  [](const auto& a, const auto& c) { return a.first < c.first; });
        std::vector<std::uint8_t> buf;
        for (const auto& [k, e] : rows) {
            buf.insert(buf.end(), k.begin(), k.end());
            append_u256(buf, e->scaled);
            append_u128(buf, e->raw);
        }
        return sha256d(buf);
    }

    static void append_bytes(std::vector<std::uint8_t>& b, const char* p,
                             std::size_t n) {
        b.insert(b.end(), p, p + n);
    }
    static void append_u64(std::vector<std::uint8_t>& b, u64 x) {
        for (int i = 0; i < 8; ++i)
            b.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
    }
    static void append_u128(std::vector<std::uint8_t>& b, u128 x) {
        append_u64(b, static_cast<u64>(x));
        append_u64(b, static_cast<u64>(x >> 64));
    }
    static void append_u256(std::vector<std::uint8_t>& b, const U256& x) {
        for (int i = 0; i < 4; ++i) append_u64(b, x.v[i]);
    }

    LaneParams m_p;
    DecayTables m_tab;
    bool m_started = false;
    u64 m_t = 0;                 // consensus clock: latest origin bin seen
    u64 m_B = 0;                 // epoch base, bin units
    u64 m_events = 0;            // accounting events (EMA denominator)
    std::map<u64, OpenBin> m_open;             // the Present, by origin bin
    std::vector<std::deque<Bucket>> m_levels;  // the Past, settling coarser
    std::map<MinerId, U256> m_acc;
    U256 m_acc_total;
    u128 m_raw_total = 0;
    U256 m_open_scaled_sum;
    u128 m_open_raw_sum = 0;
    std::deque<Op> m_journal;
};

} // namespace v37
