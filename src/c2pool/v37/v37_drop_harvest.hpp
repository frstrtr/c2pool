#pragma once
// ============================================================================
// V37 consumer seam T2 (upper half) — the DROP HARVESTER.
//
// W2 admission (w2_admission.hpp) classifies a below-consensus-target work event
// as Disposition::OK_SUBTARGET_DROP and hands it to a DropSink as a
// HarvestedDrop. This is that sink: it accumulates raindrops into one
// subthreshold::ReceiptCollector per (payee, interval) and, when an interval is
// BURIED, hands the collectors to the W4 fold as settle::HarvestedReceipt rows.
//
// THE F1 CONTRACT IS THE WHOLE DESIGN HERE
//   The estimator may only ever be shown OUT-OF-INTERVAL, BURIED data. An
//   interval that is still accumulating has a truncated near-miss set, so its
//   h_(K) is biased and its S is incomplete. take_buried(b) therefore releases
//   ONLY intervals strictly below the burial frontier, and once released an
//   interval is ERASED: it can never be released twice, and a late raindrop for
//   a released interval is dropped on the floor rather than re-opening it.
//   Together with the module's per-(payee, interval) straddle dedup this gives
//   two independent guards against the same interval being credited twice.
//
// WHAT IT IS NOT
//   Not consensus state. Nothing here is digested, persisted, or exchanged: it
//   is a node-local measurement buffer. Two nodes that harvested different
//   raindrops will propose different credit — which is exactly why the credit is
//   carried in the FOUND event the winner writes, not re-derived by each node.
//
// h_T, THE SHARE BOUNDARY
//   W2 targets are leading-zero-bit targets: a hash meets target lz iff it has
//   >= lz leading zero bits, i.e. iff hash < 2^(256-lz). So the estimator's
//   boundary — "hash <= h_T is a SHARE, above it is a near-miss" — is
//   h_T = 2^(256-lz) - 1, and the per-share work is T = 2^256/(h_T+1) = 2^lz,
//   which is exactly w2_receipt.hpp's work_of_lz(lz). One definition, no drift.
// ============================================================================
#include <cstdint>
#include <map>
#include <set>
#include <utility>
#include <vector>

#include <c2pool/v37/w2_admission.hpp>        // HarvestedDrop, DropSink
#include <c2pool/v37/w4_settlement.hpp>       // settle::HarvestedReceipt

namespace c2pool::v37n {

namespace drops_detail {

// h_T for a leading-zero-bit consensus target: 2^(256-lz) - 1.
//   lz == 0   -> h_T = 2^256 - 1: every hash is a share, nothing is a near-miss.
//   lz >= 256 -> h_T = 0: nothing can be a share (degenerate; the estimator's
//                share_covered_work() returns 0 there, which is correct).
inline ::c2pool::v37::subthreshold::u256 h_t_of_lz(unsigned lz) {
    ::c2pool::v37::subthreshold::u256 t;
    if (lz >= 256) return t;                       // 0
    const unsigned bits = 256u - lz;               // h_T = 2^bits - 1
    for (unsigned i = 0; i < bits; ++i)
        t.w[i >> 6] |= (1ull << (i & 63));
    return t;
}

// A W2 bytes32 (big-endian hash) as the estimator's u256.
inline ::c2pool::v37::subthreshold::u256 u256_of(const ::v37::bytes32& h) {
    std::array<std::uint8_t, 32> b{};
    for (std::size_t i = 0; i < 32; ++i) b[i] = h[i];
    return ::c2pool::v37::subthreshold::u256::from_be_bytes(b);
}

} // namespace drops_detail

// The node-local harvest buffer. ONE per lane.
class DropHarvester {
public:
    // K must be the lane's SubthresholdGate::K, so the collectors retain exactly
    // the K the fold will later ask for. A K < 3 harvester is legal to build and
    // will simply never produce a credit (the module's K >= 3 guard refuses it);
    // it is not this class's job to second-guess the gate.
    // (payee, interval) — the harvester's row key, public so the share-count
    // producer can enumerate the open rows it must declare an S for.
    using IntervalKey = std::pair<::v37::bytes32, u64>;

    explicit DropHarvester(std::uint32_t K) : m_K(K) {}

    std::uint32_t K() const { return m_K; }
    std::size_t open_intervals() const { return m_open.size(); }
    std::uint64_t observed() const { return m_observed; }
    std::uint64_t late_discarded() const { return m_late; }

    // The DropSink W2 calls. Idempotence is W2's dedup window's job, not this
    // one's: a hash presented twice IS counted twice here, exactly as a real
    // second hash would be, which is why the window entry in admit() matters.
    void observe(const HarvestedDrop& d) {
        if (d.interval < m_released_below) { ++m_late; return; }  // F1: too late
        const Key k{d.payee, d.interval};
        auto it = m_open.find(k);
        if (it == m_open.end())
            it = m_open.emplace(k, ::c2pool::v37::subthreshold::ReceiptCollector(
                                       m_K, drops_detail::h_t_of_lz(d.consensus_lz)))
                     .first;
        it->second.observe(drops_detail::u256_of(d.hash));
        ++m_observed;
    }

    // ★★ DECLARE the payee's in-interval SHARE COUNT. THIS IS MANDATORY, AND AN
    // UNDECLARED INTERVAL IS NEVER RELEASED (see take_buried).
    //
    // Why it cannot be optional. Under the canon COMBINED rule the estimate
    // covers a payee's WHOLE interval, and the REPLACE composition subtracts the
    // W_shares = S*T that E_b already paid. W2 accounts shares through the PUSH
    // path, not through the drop sink, so a collector that only ever saw
    // raindrops has S == 0 — and at any realistic share target almost every hash
    // is a near-miss, so (K-1)*D_K over that stream still estimates essentially
    // the payee's TOTAL work. Leaving S at 0 for a payee that DID land shares
    // would therefore credit the whole interval AGAIN on top of an intact E_b
    // row: the double count this PR removes, returning through the harvester
    // instead of through the composition. Silence is NOT the safe default here,
    // so it is not accepted as one.
    //
    // Declaring S == 0 is the correct, explicit statement for a drop-only payee
    // — the participation case DROPS exists for — and is exactly what a caller
    // should pass when the share tracker says the payee landed nothing in this
    // interval. What is refused is not "zero", it is "unknown".
    //
    // Over-declaring is self-punishing and needs no separate guard: a larger S
    // removes a larger W_shares from the same payee's credit.
    void declare_shares(const ::v37::bytes32& payee, u64 interval,
                        std::uint64_t S, unsigned consensus_lz) {
        if (interval < m_released_below) { ++m_late; return; }
        const Key k{payee, interval};
        auto it = m_open.find(k);
        if (it == m_open.end())
            it = m_open.emplace(k, ::c2pool::v37::subthreshold::ReceiptCollector(
                                       m_K, drops_detail::h_t_of_lz(consensus_lz)))
                     .first;
        it->second.set_shares(S);
        m_declared.insert(k);
    }

    bool shares_declared(const ::v37::bytes32& payee, u64 interval) const {
        return m_declared.count(Key{payee, interval}) != 0;
    }

    // The (payee, interval) keys currently open, in deterministic order. The
    // share-count producer (v37_share_counter.hpp) walks these to declare the
    // in-interval S for every interval that saw raindrops, which is what turns
    // the fail-closed declare_shares() rule from an API into a live path.
    std::vector<IntervalKey> open_keys() const {
        std::vector<IntervalKey> v;
        v.reserve(m_open.size());
        for (const auto& [k, rc] : m_open) { (void)rc; v.push_back(k); }
        return v;
    }

    // Consume and DISCARD every interval below the frontier without crediting
    // it. The S-1c peer path needs exactly this: under DROPS-R3 a peer folds the
    // WINNER'S composed map, so its own harvest must not be credited — but it
    // MUST still be advanced, or the same intervals would sit open and be folded
    // into this node's NEXT own win while the winner had already settled them.
    // Two nodes that consume their harvests at the same frontiers stay in step.
    std::size_t discard_buried(u64 bury_before) {
        const std::size_t n = take_buried(bury_before).size();
        m_discarded += n;
        return n;
    }
    std::uint64_t discarded() const { return m_discarded; }
    std::uint64_t undeclared_withheld() const { return m_undeclared; }

    // Release every interval STRICTLY BELOW `bury_before` as W4 harvest rows, in
    // deterministic (payee, interval) order, and erase them. Everything at or
    // above the frontier stays open. Calling it twice with the same frontier
    // returns rows the first time and nothing the second: intervals are consumed.
    //
    // ★ FAIL-CLOSED: an interval whose share count was never DECLARED is
    // WITHHELD — dropped, counted in undeclared_withheld(), and never handed to
    // the estimator. Crediting nothing for an interval we cannot account is the
    // conservative error; crediting it as if the payee held no shares is the
    // double count. The counter is there so an operator can see the harvest
    // going to waste and fix the wiring, rather than the node quietly
    // over-crediting.
    std::vector<settle::HarvestedReceipt> take_buried(u64 bury_before) {
        std::vector<settle::HarvestedReceipt> out;
        for (auto it = m_open.begin(); it != m_open.end();) {
            if (it->first.second >= bury_before) { ++it; continue; }
            if (m_declared.count(it->first)) {
                out.push_back(settle::HarvestedReceipt{it->first.first,
                                                       it->first.second,
                                                       it->second});
            } else {
                ++m_undeclared;          // ★ withheld, never credited
            }
            m_declared.erase(it->first);
            it = m_open.erase(it);
        }
        if (bury_before > m_released_below) m_released_below = bury_before;
        return out;
    }

    // Drop everything (a lane RemoveLane -> AddLane, or a reorg deep enough that
    // the measurement is no longer about the chain we are on).
    void reset() {
        m_open.clear();
        m_declared.clear();
        m_released_below = 0;
        m_observed = 0;
        m_late = 0;
        m_undeclared = 0;
        m_discarded = 0;
    }

private:
    using Key = IntervalKey;                       // ordered: (payee, interval)
    std::uint32_t m_K;
    std::map<Key, ::c2pool::v37::subthreshold::ReceiptCollector> m_open;
    std::set<Key> m_declared;      // (payee, interval) whose S is KNOWN
    u64 m_released_below = 0;      // F1 frontier: everything below is settled
    std::uint64_t m_observed = 0;
    std::uint64_t m_late = 0;
    std::uint64_t m_undeclared = 0;
    std::uint64_t m_discarded = 0;
};

} // namespace c2pool::v37n
