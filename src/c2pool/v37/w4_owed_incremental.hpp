#pragma once
// V37 W4 — R3 incremental OWED-ledger acceleration. CONSUMER-tree code
// (src/c2pool/v37/), a pure PERFORMANCE add-on to OwedLedger in
// w4_settlement.hpp; it touches NO consensus header (src/sharechain/v37/*) and
// changes NO committed byte. It exists to make three block-rate paths cheap
// while remaining provably DIGEST-NEUTRAL:
//
//   (1) DigestMemo         — a seq-keyed single-slot memo of owed_digest().
//                            owed_digest() is a pure function of ledger state;
//                            state changes iff OwedLedger::m_seq bumps; so a hit
//                            on an equal seq returns the byte-identical digest
//                            by construction. Removes the repeated O(K) SHA over
//                            m_finalW (e.g. read_cut() hashes twice per attempt).
//
//   (2) EffectiveOwedIndex — the incremental EffectiveOwed(k) map, maintained by
//                            EXACT deltas instead of the O(K·P) rescan of every
//                            pending block's payout per key (w4:533-553), PLUS an
//                            ordered set of the currently-positive keys by
//                            (first_eligible ASC, key ASC) so a coinbase proposal
//                            takes the first C in O(C log K) (w4:565-591) rather
//                            than re-deriving + re-sorting the whole eligible set.
//
// DELTA ALGEBRA (EffectiveOwed(k) = finalW(k) − Σ_{pending} payout(k)):
//   FOUND(payout)       eo[k] -= payout[k]      // payout ENTERS pending
//   FINALIZE(credit)    eo[k] += credit[k]      // finalW += credit − payout AND
//                                               //   pending drops payout ⇒ the
//                                               //   two payout terms cancel; net
//                                               //   change is +credit only.
//   ORPHAN_pre(payout)  eo[k] += payout[k]      // payout LEAVES pending
// (Proof of the FINALIZE cancellation and full byte-identity is exercised by the
//  oracle KAT v37_w4_owed_incremental_test.cpp against the original algorithm.)
//
// first_eligible (the K_fair age key, digest-visible via owed_digest) stays OWNED
// by OwedLedger and is (dis)armed ONLY at FINALIZE, exactly as the shipped
// rearm_first_eligible — so the digest's fe column is frozen between finalizes.
// This header only READS fe (through a caller-supplied lookup) to order the
// positive view; it never invents or reorders fe state.

#include <cstdint>
#include <map>
#include <set>
#include <utility>

#include <sharechain/v37/v37_fixed.hpp>   // u64
#include <sharechain/v37/v37_hash.hpp>    // bytes32

namespace c2pool::v37n::settle::detail {

using ::v37::bytes32;
using ::v37::u64;

// ─────────────────────────────────────────────────────────────────────────
// (1) Seq-keyed memo for owed_digest(). Pure memoization: the stored digest is
// returned only when queried at the SAME m_seq it was computed at, and m_seq
// bumps on every ledger mutation, so a hit is byte-identical to a recompute.
// ─────────────────────────────────────────────────────────────────────────
struct DigestMemo {
    u64     seq   = 0;
    bytes32 value{};
    bool    valid = false;

    // Non-null iff a digest was memoized at exactly `cur_seq`.
    const bytes32* get(u64 cur_seq) const {
        return (valid && seq == cur_seq) ? &value : nullptr;
    }
    void put(u64 cur_seq, const bytes32& d) {
        seq = cur_seq;
        value = d;
        valid = true;
    }
};

// ─────────────────────────────────────────────────────────────────────────
// (2) Incremental EffectiveOwed + ordered (first_eligible, key) positive view.
//
// Ownership split: this index owns the derived acceleration state ONLY —
//   m_eo       : key → EffectiveOwed(k), maintained by the delta algebra above;
//   m_order    : the set {(fe(k), k) : eo(k) > 0}, ascending — the K_fair order;
//   m_order_fe : key → the fe currently used for k's m_order entry (so an entry
//                can be erased by key without knowing the old fe).
// finalW and first_eligible remain OWNED by OwedLedger (both are digest-visible).
// Every method that needs fe(k) receives it from a caller-supplied lookup that
// reads OwedLedger::m_first_eligible, so this header is never a second source of
// truth for the age key.
// ─────────────────────────────────────────────────────────────────────────
class EffectiveOwedIndex {
public:
    using Amounts = std::map<bytes32, long long>;

    // EffectiveOwed(k); 0 for an untouched key (identical to a rescan of an
    // absent finalW row minus no pending payouts).
    long long value(const bytes32& k) const {
        auto it = m_eo.find(k);
        return it == m_eo.end() ? 0 : it->second;
    }

    // ── FOUND(b): payout enters pending ⇒ eo -= payout. fe is frozen (FOUND
    // never rearms), so each touched key is reindexed at its unchanged fe.
    template <class FeOf>
    void on_found(const Amounts& payout, FeOf&& fe_of) {
        for (const auto& [k, v] : payout) {
            if (v == 0) continue;
            add_eo(k, -v);
            reindex(k, fe_of(k));
        }
    }

    // ── ORPHAN(b) pre-SETTLED: payout leaves pending ⇒ eo += payout. fe frozen.
    template <class FeOf>
    void on_orphan_pre(const Amounts& payout, FeOf&& fe_of) {
        for (const auto& [k, v] : payout) {
            if (v == 0) continue;
            add_eo(k, +v);
            reindex(k, fe_of(k));
        }
    }

    // ── FINALIZE(b) step 1: eo += credit (the payout terms cancel — see header).
    // The ordered view is NOT touched here; OwedLedger::rearm_first_eligible()
    // updates fe next and then calls rebuild_order() to re-establish it.
    void apply_finalize_credit(const Amounts& credit) {
        for (const auto& [k, v] : credit) {
            if (v == 0) continue;
            add_eo(k, +v);
        }
    }

    // Iterate every tracked key with its current eo — the arm/disarm driver for
    // rearm_first_eligible. This key set is the shipped
    // (finalW ∪ pending-payout) union PLUS only keys whose eo ≤ 0 and which
    // carry no fe (their disarm is a no-op), so the fe map it produces is
    // identical to the shipped rearm (oracle KAT proves it).
    template <class Fn>
    void for_each_eo(Fn&& fn) const {
        for (const auto& [k, e] : m_eo) fn(k, e);
    }

    // Rebuild the ordered positive view from the freshly-updated fe (called at
    // the end of rearm_first_eligible). O(K log K) at finalize (block rate).
    template <class FeOf>
    void rebuild_order(FeOf&& fe_of) {
        m_order.clear();
        m_order_fe.clear();
        for (const auto& [k, e] : m_eo) {
            if (e <= 0) continue;
            u64 fe = fe_of(k);
            m_order.insert({fe, k});
            m_order_fe[k] = fe;
        }
    }

    // Iterate the positive keys in (first_eligible ASC, key ASC) order — the
    // exact order propose_coinbase() selects in. `fn(k)` returns false to stop
    // early, so a proposal that fills C outputs is O(C log K).
    template <class Fn>
    void for_each_eligible(Fn&& fn) const {
        for (const auto& [fe, k] : m_order) {
            (void)fe;
            if (!fn(k)) break;
        }
    }

    // Diagnostics only (never consensus).
    std::size_t eligible_size() const { return m_order.size(); }
    std::size_t tracked_keys()  const { return m_eo.size(); }

private:
    void add_eo(const bytes32& k, long long delta) { m_eo[k] += delta; }

    // Remove k's current ordered entry (via its recorded fe), then reinsert iff
    // it is still positive, at the supplied current fe.
    void reindex(const bytes32& k, u64 fe_now) {
        auto fit = m_order_fe.find(k);
        if (fit != m_order_fe.end()) {
            m_order.erase({fit->second, k});
            m_order_fe.erase(fit);
        }
        if (value(k) > 0) {
            m_order.insert({fe_now, k});
            m_order_fe[k] = fe_now;
        }
    }

    Amounts                          m_eo;        // key → EffectiveOwed(k)
    std::set<std::pair<u64, bytes32>> m_order;    // {(fe, k) : eo(k) > 0}, ASC
    std::map<bytes32, u64>           m_order_fe;  // k → fe used in m_order
};

}  // namespace c2pool::v37n::settle::detail
