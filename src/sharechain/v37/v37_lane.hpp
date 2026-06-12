#pragma once
// V37 MRR roundabout — one sharechain lane.
// Spec: docs/c2pool-v37-mrr-roundabout-buffer.md §3 (data model), §4.1
// (roll-up pyramid), §4.2 (epoch-scaled incremental decay + OQ-2 exact
// rebuild), §6.1 (quantized window, OQ-1), §6.2 (reorg journal, OQ-7).
//
// CONSENSUS-DETERMINISM (§8.3): the operation order inside push() is fixed —
//   (1) epoch rebuild when next_pos - B == E,
//   (2) L0 fold when L0 is full,
//   (3) level-k fold cascade when a level ring is full,
//   (4) insert,
//   (5) whole-bucket eviction while cover > W.
// All folds/evicts/rebuilds happen at positionally defined points; no input
// to the sequence is node-local.

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
    u64 window = 8640;          // W   (OQ-5 default)
    u64 c0 = 4096;              // C0, power of two; also E (epoch length)
    u64 rollup = 8;             // R
    std::vector<u64> level_caps = {568};  // slot counts for levels >= 1
    u64 half_life = 2160;       // W/4 (OQ-5)
    u64 journal_depth = 64;     // D   (OQ-7)

    u64 epoch_len() const { return c0; }
    std::size_t levels() const { return 1 + level_caps.size(); }
};

// L0 slot flag bits. Annotation-only: flags are NOT digest leaves and never
// affect weights. Bit 0x08 mirrors V36 share_messages FLAG_PROTOCOL_AUTHORITY
// for operator familiarity: it marks shares whose message_data carried
// validated authority messages (V36 share_messages.hpp — envelope under the
// authority pubkeys, ECDSA-signed, ref_hash/PoW-protected; validation happens
// in share_check BEFORE push, payloads stay in the share store). Views join
// message payloads by `pos`; messages age out of visibility at fold, which
// matches their per-share nature (FLAG_PERSISTENT semantics: operator OQ).
constexpr std::uint32_t L0F_FEE_SHARE     = 0x01;
constexpr std::uint32_t L0F_STALE_DOA     = 0x02;
constexpr std::uint32_t L0F_AUTHORITY_MSG = 0x08;
constexpr std::uint32_t L0F_MINER_MSG     = 0x10;  // permissionless miner
// message present (c2pool-v37-miner-messages.md v1.1: plaintext envelope,
// derived signing key announced in the share binds to the payout identity
// (A-1), TTL funded by decayed_weight() with share-sacrifice premium lane
// (A-2) — the lane is the budget ledger; message index is view-layer)

// Level-0 slot (SoA in the production layout; AoS here for clarity — the
// arrays are contiguous std::vector rings either way).
struct L0Slot {
    u64 pos = 0;
    u64 w_raw = 0;       // work(target), verbatim (F-1; feeds epoch rebuild)
    u128 w_scaled = 0;   // w_raw x InvD[pos - B] at insert, Q62
    MinerId miner = 0;
    std::uint32_t flags = 0;   // L0F_* bits above
};

struct CompEntry {              // (miner, w_scaled, w_raw) triple, F-1
    MinerId miner = 0;
    U256 scaled;                // stored in the bucket's epoch frame
    u128 raw = 0;
};

struct Bucket {                 // immutable after close (§4.1)
    u64 pos_lo = 0, pos_hi = 0;
    u64 epoch_tag = 0;          // B at close; shift applied at read/evict
    U256 scaled_sum;
    u128 raw_work = 0;          // F-1: per-band settlement leaf
    std::vector<CompEntry> comp;  // sorted by miner id (deterministic)
};

class Lane {
public:
    explicit Lane(const LaneParams& p) : m_p(p) {
        if (p.c0 == 0 || (p.c0 & (p.c0 - 1)) != 0)
            throw std::invalid_argument("v37: C0 must be a power of two");
        if (p.rollup == 0 || p.c0 % p.rollup != 0)
            throw std::invalid_argument("v37: R must divide C0");
        if (p.window < p.c0)
            throw std::invalid_argument("v37: window must be >= C0 "
                                        "(eviction needs whole buckets)");
        if (p.level_caps.empty())
            throw std::invalid_argument("v37: at least one bucket level");
        // Inner bucket levels must hold at least one roll-up group; the
        // outermost level never folds, so its cap is not load-bearing.
        for (std::size_t k = 0; k + 1 < p.level_caps.size(); ++k)
            if (p.level_caps[k] < p.rollup)
                throw std::invalid_argument(
                    "v37: inner level cap smaller than roll-up factor");
        // decay[] must cover query depths [0,E) and rebuild depths [1,E];
        // epoch_shift[] must cover the max bucket age in epochs.
        u64 max_epochs = (p.window / p.epoch_len()) + 4;
        m_tab.init(p.half_life, p.epoch_len(), p.epoch_len() + p.c0, max_epochs);
        m_levels.resize(p.level_caps.size());
    }

    const LaneParams& params() const { return m_p; }
    const DecayTables& tables() const { return m_tab; }
    u64 next_pos() const { return m_next_pos; }
    u64 epoch_base() const { return m_B; }
    u64 cover() const { return m_cover; }
    const U256& acc_total() const { return m_acc_total; }
    u128 raw_total() const { return m_raw_total; }
    const std::map<MinerId, U256>& acc() const { return m_acc; }
    const std::deque<L0Slot>& l0() const { return m_l0; }
    const std::vector<std::deque<Bucket>>& levels() const { return m_levels; }
    const U256& l0_scaled_sum() const { return m_l0_scaled_sum; }
    u128 l0_raw_sum() const { return m_l0_raw_sum; }

    // ── push: O(1) amortized (§7) ─────────────────────────────────────────
    void push(MinerId miner, u64 w_raw, std::uint32_t flags) {
        if (w_raw == 0)
            throw std::invalid_argument("v37: zero-work share");
            // (a zero-weight acc entry would be committed by the digest but
            //  erased by undo_push — rewind would not be bit-exact)
        if (m_next_pos - m_B == m_p.epoch_len())
            epoch_rebuild();                              // (1) — clears journal

        if (m_l0.size() == m_p.c0)
            fold_l0();                                    // (2)
        cascade_folds();                                  // (3)

        u64 p = m_next_pos++;
        u64 j = p - m_B;                                  // in [0, E)
        u128 w_scaled = u128(w_raw) * m_tab.inv_decay[j]; // Q62, fits u128
        L0Slot s{p, w_raw, w_scaled, miner, flags};
        m_l0.push_back(s);                                // (4)
        m_acc[miner] += U256::from_u128(w_scaled);
        m_acc_total += U256::from_u128(w_scaled);
        m_raw_total += w_raw;
        m_l0_scaled_sum += U256::from_u128(w_scaled);
        m_l0_raw_sum += w_raw;
        m_cover += 1;
        journal_push(Op::push(s));

        while (m_cover > m_p.window)                      // (5) OQ-1
            evict_oldest_bucket();
    }

    // ── queries ───────────────────────────────────────────────────────────
    // Decayed weight of one miner at the current head (O(1) + map lookup).
    U256 decayed_weight(MinerId m) const {
        auto it = m_acc.find(m);
        if (it == m_acc.end()) return U256();
        return it->second.mul_q(head_decay());
    }
    U256 decayed_total() const { return m_acc_total.mul_q(head_decay()); }

    // Full payout map: O(active miners) (§7).
    std::map<MinerId, U256> payout_map() const {
        std::map<MinerId, U256> out;
        u64 f = head_decay();
        for (const auto& [m, a] : m_acc) out[m] = a.mul_q(f);
        return out;
    }

    // Per-band raw delivered work over [lo, hi] positions, bucket-granular
    // at coarse levels (settlement-grade reading, F-1 / market §4.1).
    u128 raw_work_in_span(u64 lo, u64 hi) const {
        u128 sum = 0;
        for (const auto& s : m_l0)
            if (s.pos >= lo && s.pos <= hi) sum += s.w_raw;
        for (const auto& lvl : m_levels)
            for (const auto& b : lvl)
                if (b.pos_lo >= lo && b.pos_hi <= hi) sum += b.raw_work;
        return sum;
    }

    // ── reorg rewind (§6.2, OQ-7) ─────────────────────────────────────────
    // Rewind the last d pushes. Returns false when the journal cannot serve
    // the request (d > recorded pushes, or the span crosses an epoch-rebuild
    // boundary — the journal is cleared at rebuilds); the caller then does
    // the full lane rebuild from the tracker (the >D path).
    bool rewind(u64 d) {
        u64 pushes = 0;
        bool boundary = false;
        for (const auto& op : m_journal) {
            if (op.type == Op::Type::Push) ++pushes;
            else if (op.type == Op::Type::RebuildBoundary) boundary = true;
        }
        if (d > pushes) return false;
        // The push that TRIGGERED an epoch rebuild cannot be undone without
        // undoing the rebuild itself (the canonical pre-share state is the
        // pre-rebuild frame, which the journal cannot restore). When the
        // boundary sentinel is in the journal, the rebuild-triggering push
        // is the oldest journaled push — refuse to land on it.
        if (boundary && d == pushes) return false;
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
                throw std::logic_error("v37: rewind crossed rebuild sentinel"
                                       " (guarded above — unreachable)");
            }
        }
        // One push() call journals [Folds][Push][Evicts]. The loop above
        // stops at the d-th Push; any folds IMMEDIATELY preceding it were
        // triggered by that same share's arrival and must be undone too —
        // the restored state is "before the share arrived", not "after its
        // folds". Trailing folds are unambiguous: nothing else sits between
        // a push's folds and its Push record.
        while (!m_journal.empty() &&
               (m_journal.back().type == Op::Type::FoldL0 ||
                m_journal.back().type == Op::Type::FoldLevel)) {
            Op op = m_journal.back();
            m_journal.pop_back();
            if (op.type == Op::Type::FoldL0) undo_fold_l0(op);
            else undo_fold_level(op);
        }
        return true;
    }

    // ── digest (§8.5, OQ-4 + OQ-M5) — Merkle root, consensus-committed ────
    // CONSENSUS: intern ids are NODE-LOCAL (assigned at first global
    // sighting, which interleaves differently across lanes on different
    // nodes). All consensus bytes use the CANONICAL identity key
    // (PayoutDescriptor identity, 32 bytes) supplied by the resolver, sorted
    // by those bytes — never raw intern ids.
    //
    // OQ-M5 (resolved): the digest is the root of a Merkle tree over the
    // canonical leaves, so lite clients can verify one accumulator entry
    // (message-TTL budget) or one bucket's raw work (market settlement band)
    // with a log-size proof against the on-chain commitment. Tree rule:
    //   leaf node     = sha256d(0x00 || leaf payload)
    //   interior node = sha256d(0x01 || left || right)   (domain-separated)
    //   odd node      = promoted unchanged (no duplication ambiguity)
    // Leaf order (fixed): [0] header leaf (geometry, B, next_pos, counts,
    // L0 sums); then acc leaves in canonical-identity order; then bucket
    // leaves level-by-level, oldest -> newest.
    template <typename Resolver>  // bytes32 resolver(MinerId)
    bytes32 digest(Resolver&& id_key) const {
        return merkle_root(build_leaves(id_key));
    }

    // Inclusion proof for one miner's accumulator leaf (lite-client TTL
    // verification). Returns false if the miner has no acc entry.
    struct MerkleProof {
        u64 leaf_count = 0;
        u64 index = 0;
        std::vector<bytes32> path;  // siblings bottom-up; promote-odd levels
                                    // contribute no entry (structure is
                                    // derivable from leaf_count + index)
    };
    template <typename Resolver>
    bool acc_proof(MinerId m, Resolver&& id_key, bytes32& leaf_out,
                   MerkleProof& proof_out) const {
        if (!m_acc.count(m)) return false;
        auto leaves = build_leaves(id_key);
        // locate the miner's acc leaf: header is leaf 0; acc leaves follow
        // in canonical order — recompute its leaf hash and find it.
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

    // Stateless verifier (what a lite client runs against the committed
    // root): recomputes the path using only leaf_count/index for structure.
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

    // ── OQ-2 exact epoch rebuild, exposed for tests/reference checks ──────
    // Re-derives every scaled quantity from durable records (w_raw + pos for
    // L0; immutable bucket records with the epoch-shift rule). This IS the
    // reference function the fast path re-converges to (§8.4).
    void epoch_rebuild() {
        if (m_next_pos - m_B != m_p.epoch_len())
            throw std::logic_error("v37: epoch_rebuild outside the epoch "
                                   "boundary (positionally defined, §8.3)");
        u64 B_new = m_B + m_p.epoch_len();
        m_acc.clear();
        m_acc_total = U256();
        m_l0_scaled_sum = U256();
        // L0: recompute from primary inputs, oldest -> newest.
        for (auto& s : m_l0) {
            u64 depth = B_new - s.pos;          // in [1, E] (E == C0)
            s.w_scaled = u128(s.w_raw) * m_tab.decay[depth];
            m_acc[s.miner] += U256::from_u128(s.w_scaled);
            m_acc_total += U256::from_u128(s.w_scaled);
            m_l0_scaled_sum += U256::from_u128(s.w_scaled);
        }
        // Buckets: immutable; shifted by lambda^(E*age) at read.
        for (const auto& lvl : m_levels) {
            for (const auto& b : lvl) {
                u64 age = (B_new - b.epoch_tag) / m_p.epoch_len();
                u64 f = m_tab.epoch_shift[age];
                for (const auto& e : b.comp) {
                    U256 c = e.scaled.mul_q(f);
                    m_acc[e.miner] += c;
                    m_acc_total += c;
                }
            }
        }
        m_B = B_new;
        m_journal.clear();   // rewind cannot cross a rebuild (see notes)
        Op b2; b2.type = Op::Type::RebuildBoundary;
        m_journal.push_back(std::move(b2));  // sentinel: see rewind()
    }

private:
    // ── journal ───────────────────────────────────────────────────────────
    struct Op {
        enum class Type { Push, FoldL0, FoldLevel, Evict, RebuildBoundary };
        Type type;
        // Push
        L0Slot slot;
        // FoldL0 / FoldLevel / Evict
        Bucket bucket;                 // created (folds) or removed (evict)
        std::vector<L0Slot> folded_slots;     // FoldL0: removed L0 slots
        std::vector<Bucket> folded_children;  // FoldLevel: removed buckets
        std::size_t level_index = 0;          // FoldLevel/Evict: which level
        std::vector<std::pair<MinerId, U256>> subtracted;  // Evict: exact subs

        static Op push(const L0Slot& s) { Op o; o.type = Type::Push; o.slot = s; return o; }
    };

    u64 head_decay() const {
        // factor lambda^(H - B) with H = next_pos - 1; H - B in [0, E).
        if (m_next_pos == m_B) return Q_ONE;
        return m_tab.decay[(m_next_pos - 1) - m_B];
    }

    void journal_push(Op op) {
        m_journal.push_back(std::move(op));
        // Trim: keep ops back to (and including) the D-th most recent push,
        // PLUS that push's immediately preceding folds — rewind(D) must be
        // able to undo the full push() call it lands on.
        u64 pushes = 0;
        std::size_t keep_from = 0;
        for (std::size_t i = m_journal.size(); i-- > 0;) {
            if (m_journal[i].type == Op::Type::Push) {
                if (++pushes == m_p.journal_depth) { keep_from = i; break; }
            }
        }
        if (pushes < m_p.journal_depth || keep_from == 0) return;
        while (keep_from > 0 &&
               (m_journal[keep_from - 1].type == Op::Type::FoldL0 ||
                m_journal[keep_from - 1].type == Op::Type::FoldLevel ||
                m_journal[keep_from - 1].type == Op::Type::RebuildBoundary))
            --keep_from;
            // the boundary sentinel is kept when adjacent: rewind() must
            // still see it to refuse landing on the rebuild-triggering push
        if (keep_from > 0)
            m_journal.erase(m_journal.begin(),
                            m_journal.begin() + static_cast<long>(keep_from));
    }

    // ── fold: L0 -> level 1 (§4.1) ────────────────────────────────────────
    void fold_l0() {
        Bucket b;
        b.epoch_tag = m_B;
        std::map<MinerId, CompEntry> agg;
        Op op; op.type = Op::Type::FoldL0; op.level_index = 0;
        for (u64 i = 0; i < m_p.rollup; ++i) {
            const L0Slot& s = m_l0.front();
            if (i == 0) b.pos_lo = s.pos;
            b.pos_hi = s.pos;
            b.scaled_sum += U256::from_u128(s.w_scaled);
            b.raw_work += s.w_raw;
            auto& e = agg[s.miner];
            e.miner = s.miner;
            e.scaled += U256::from_u128(s.w_scaled);
            e.raw += s.w_raw;
            m_l0_scaled_sum -= U256::from_u128(s.w_scaled);
            m_l0_raw_sum -= s.w_raw;
            op.folded_slots.push_back(s);
            m_l0.pop_front();
        }
        for (auto& [m, e] : agg) b.comp.push_back(e);  // miner-id order
        op.bucket = b;
        m_levels[0].push_back(std::move(b));
        m_journal.push_back(std::move(op));
        // acc is untouched: fold relocates scaled value, it does not change it.
    }

    // ── fold cascade: level k -> k+1 when ring k is full ──────────────────
    void cascade_folds() {
        for (std::size_t k = 0; k + 1 < m_levels.size(); ++k) {
            if (m_levels[k].size() < m_p.level_caps[k]) continue;
            Bucket b;
            b.epoch_tag = m_B;
            std::map<MinerId, CompEntry> agg;
            Op op; op.type = Op::Type::FoldLevel; op.level_index = k;
            for (u64 i = 0; i < m_p.rollup; ++i) {
                Bucket child = m_levels[k].front();
                m_levels[k].pop_front();
                u64 age = (m_B - child.epoch_tag) / m_p.epoch_len();
                u64 f = m_tab.epoch_shift[age];
                if (i == 0) b.pos_lo = child.pos_lo;
                b.pos_hi = child.pos_hi;
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
            // NOTE: shifting children to the current frame at fold changes
            // their stored frame; acc tracked them in their OLD frame, so a
            // truncation residual is created here. It is deterministic and
            // flushed at the next epoch rebuild (§4.2 determinism note) —
            // and with default L = 2 this path never runs.
        }
    }

    // ── eviction: whole outermost buckets (OQ-1) ──────────────────────────
    void evict_oldest_bucket() {
        // Globally oldest bucket = the one with the smallest pos_lo across
        // all bucket levels (data is strictly ordered through the pyramid).
        std::size_t best = SIZE_MAX;
        for (std::size_t k = 0; k < m_levels.size(); ++k) {
            if (m_levels[k].empty()) continue;
            if (best == SIZE_MAX ||
                m_levels[k].front().pos_lo < m_levels[best].front().pos_lo)
                best = k;
        }
        if (best == SIZE_MAX)
            throw std::logic_error("v37: cover > W with no buckets");
        Bucket b = m_levels[best].front();
        m_levels[best].pop_front();
        u64 age = (m_B - b.epoch_tag) / m_p.epoch_len();
        u64 f = m_tab.epoch_shift[age];
        Op op; op.type = Op::Type::Evict; op.level_index = best;
        for (const auto& e : b.comp) {
            U256 sub = e.scaled.mul_q(f);
            m_acc[e.miner] -= sub;
            m_acc_total -= sub;
            if (m_acc[e.miner].is_zero()) m_acc.erase(e.miner);
            op.subtracted.emplace_back(e.miner, sub);
        }
        m_raw_total -= b.raw_work;
        m_cover -= (b.pos_hi - b.pos_lo + 1);
        op.bucket = std::move(b);
        m_journal.push_back(std::move(op));
    }

    // ── undo ops (exact bit-restoration; no rebuild in between by rule) ───
    void undo_push(const Op& op) {
        const L0Slot& s = op.slot;
        m_l0.pop_back();
        m_acc[s.miner] -= U256::from_u128(s.w_scaled);
        if (m_acc[s.miner].is_zero()) m_acc.erase(s.miner);
        m_acc_total -= U256::from_u128(s.w_scaled);
        m_raw_total -= s.w_raw;
        m_l0_scaled_sum -= U256::from_u128(s.w_scaled);
        m_l0_raw_sum -= s.w_raw;
        m_cover -= 1;
        m_next_pos -= 1;
    }
    void undo_fold_l0(const Op& op) {
        m_levels[0].pop_back();
        for (auto it = op.folded_slots.rbegin(); it != op.folded_slots.rend(); ++it) {
            m_l0.push_front(*it);
            m_l0_scaled_sum += U256::from_u128(it->w_scaled);
            m_l0_raw_sum += it->w_raw;
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
        m_cover += (op.bucket.pos_hi - op.bucket.pos_lo + 1);
    }

    // ── digest serialization helpers (fixed-width LE, §8.3) ───────────────
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
    static void append_u256(std::vector<std::uint8_t>& b, const U256& x) {
        for (int i = 0; i < 4; ++i) append_u64(b, x.v[i]);
    }
    // ── Merkle digest machinery (OQ-M5) ───────────────────────────────────
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
        // never empty: build_leaves always emits the header leaf
        while (level.size() > 1) {
            std::vector<bytes32> next;
            next.reserve((level.size() + 1) / 2);
            std::size_t i = 0;
            for (; i + 1 < level.size(); i += 2)
                next.push_back(interior_hash(level[i], level[i + 1]));
            if (i < level.size()) next.push_back(level[i]);  // promote odd
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

    // Canonical leaf list — the fixed order every conforming node produces.
    template <typename Resolver>
    std::vector<bytes32> build_leaves(Resolver&& id_key) const {
        std::vector<bytes32> leaves;
        u64 bucket_total = 0;
        for (const auto& lvl : m_levels) bucket_total += lvl.size();
        leaves.reserve(1 + m_acc.size() + bucket_total);
        {   // [0] header leaf: geometry (consensus parameters — a mismatch
            // becomes an attributable digest difference), position state,
            // counts, and the L0 ring sums (F-1 leaves).
            std::vector<std::uint8_t> h;
            append_bytes(h, "V37H", 4);
            append_u64(h, m_p.window);
            append_u64(h, m_p.c0);
            append_u64(h, m_p.rollup);
            append_u64(h, m_p.half_life);
            append_u64(h, static_cast<u64>(m_p.level_caps.size()));
            for (u64 c : m_p.level_caps) append_u64(h, c);
            append_u64(h, m_B);
            append_u64(h, m_next_pos);
            append_u64(h, static_cast<u64>(m_acc.size()));
            append_u64(h, static_cast<u64>(m_l0.size()));
            append_u256(h, m_l0_scaled_sum);
            append_u128(h, m_l0_raw_sum);
            for (const auto& lvl : m_levels)
                append_u64(h, static_cast<u64>(lvl.size()));
            leaves.push_back(leaf_hash(h));
        }
        {   // acc leaves, canonical-identity order
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
        // bucket leaves, level-by-level, oldest -> newest (F-1 settlement
        // bands provable individually)
        for (std::size_t k = 0; k < m_levels.size(); ++k) {
            for (const auto& bkt : m_levels[k]) {
                std::vector<std::uint8_t> b;
                append_bytes(b, "V37B", 4);
                append_u64(b, static_cast<u64>(k));
                append_u64(b, bkt.pos_lo);
                append_u64(b, bkt.pos_hi);
                append_u128(b, bkt.raw_work);
                append_u64(b, bkt.epoch_tag);
                auto ch = comp_hash(bkt, id_key);
                b.insert(b.end(), ch.begin(), ch.end());
                leaves.push_back(leaf_hash(b));
            }
        }
        return leaves;
    }

    // Composition hash, also in canonical-identity order (see digest()).
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

    LaneParams m_p;
    DecayTables m_tab;
    u64 m_next_pos = 0;
    u64 m_B = 0;
    u64 m_cover = 0;
    std::deque<L0Slot> m_l0;
    std::vector<std::deque<Bucket>> m_levels;
    std::map<MinerId, U256> m_acc;           // ordered: digest determinism
    U256 m_acc_total;
    u128 m_raw_total = 0;
    U256 m_l0_scaled_sum;
    u128 m_l0_raw_sum = 0;
    std::deque<Op> m_journal;
};

} // namespace v37
