#pragma once
// V37 — the OWED-EVENT instance of the generic record log (record_log.hpp).
//
// CONSUMER-tree code (src/c2pool/v37/). It adds ONE thing to the generic
// primitive: the canonical leaf bytes for an OWED-ledger mutation. Everything
// else — the MMR discipline, the root, the proofs, the serialization — is the
// generic log, which is the shipped ::v37::Lane MMR code.
//
// ── WHAT THIS COMMITS, AND WHAT IT DOES NOT ──────────────────────────────
// owed_digest() (w4_settlement.hpp) is a FLAT commitment to the ledger STATE:
// the sorted finalW rows at one cut. It is untouched by this header — not
// replaced, not reordered, not re-tagged; its anchors (b4db1ded... empty,
// 87c5249a... the V37.1 gate-ON ridge cut) do not move.
// The owed-event MMR is a commitment to the ledger's HISTORY: the ordered
// stream of mutations that produced that state. The two live BESIDE each
// other. A node can prove "this event happened, at this position, under the
// root you already committed" with an O(log n) inclusion proof — which a flat
// state digest cannot do at all.
//
// ── THE CANONICAL ORDER (the part that makes convergence structural) ─────
// The append order is the LEDGER MUTATION ORDER: exactly ONE leaf per
// ledger_seq increment, so
//                 leaf index i (0-based)  <->  ledger_seq i+1
//                 leaf_count()            ==   ledger_seq()
// and the invariant is enforced by CONSTRUCTION, not by convention: in W4 the
// only way to advance m_seq is OwedLedger::bump(payload), which appends the
// leaf and increments the sequence in one step. There is no bump() that mints
// no leaf.
//
// This is deliberately NOT "(bin_height, then bid)". A height-ordered rule
// cannot be an APPEND order: an MMR has no insertion, and two of the three
// event kinds carry no height at all (FOUND records the height in its own
// sidecar, ORPHAN has none), so a late lower-height event would demand an
// insert. Mutation order is total, is the same order every node's ledger
// applies, and is exactly the order w6 replays from disk.
//
// ── THE LEAF BYTES ───────────────────────────────────────────────────────
//   payload = "V37L"                      (4 bytes, domain tag; unused
//                                          elsewhere in the tree)
//           || u8   evkind                (1 FOUND, 2 FINALIZE, 3 ORPHAN —
//                                          the same numbering as w6 EvKind)
//           || u32  LE len(bid) || bid    (the lower-hex block id, exactly as
//                                          keyed in the ledger)
//           || u64  LE bin_height
//           || amap credit
//           || amap payout
//           || amap settled_payout
//   amap    = u32 LE n || n x ( key(32) || i64 amount as u64 LE two's complement )
//             in std::map<bytes32> ascending key order
//   leaf    = sha256d(0x00 || payload)     (the lane leaf rule)
//
// NORMALIZATION — the leaf carries the MUTATOR ARGUMENTS THE LEDGER ACTUALLY
// CONSUMED, never the raw call arguments:
//   * rows whose amount is 0 are DROPPED (this mirrors what on_block_found
//     already does when it builds the Pending maps, so the leaf matches the
//     state the ledger kept);
//   * FOUND     : bin_height := 0, settled := {}  (the height lives in the
//                 blk/pfound sidecar, not in the mutation);
//   * FINALIZE  : all three maps := {}  (the mutator consumes only bid and
//                 bin_height; the amounts come from the pending row the
//                 ledger already holds);
//   * ORPHAN, pre-SETTLED (pure pending removal): bin_height := 0, ALL three
//     maps := {}. The settled_payout argument is IGNORED by the ledger on this
//     branch, so it is kept out of the leaf as well — otherwise two nodes with
//     IDENTICAL ledger state could commit different roots purely because one
//     caller passed {} and the other passed the payout map. This is the one
//     place where "the arguments the ledger consumed" and "the arguments the
//     caller passed" differ, and the consumed set is the convergent one.
//   * ORPHAN, post-SETTLED (priced residual): bin_height := 0, credit := {},
//     payout := {}, settled := the passed map with zero rows dropped.
//
// NOTHING NODE-LOCAL ENTERS A LEAF: no seq (it is the position), no boot_id,
// no incarnation, no timestamp, no cursor, no hardware or wall-clock value.
// The chain id is not in the payload either — it is bound by the key the log
// is persisted under (v37s:lmmr:<chain>) and by the ledger that owns the log.
//
// KNOWN, DOCUMENTED AMBIGUITY: a pre-SETTLED ORPHAN of bid b and a
// post-SETTLED ORPHAN of the same b whose settled map is empty or all-zero
// produce the SAME leaf bytes. They are not confusable in practice, because
// reaching the post-SETTLED branch requires a FINALIZE leaf for b earlier in
// the same log, so the two histories differ before this leaf and therefore
// differ in leaf_count and root. It is recorded here rather than papered over.

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <c2pool/v37/record_log.hpp>
#include <sharechain/v37/v37_fixed.hpp>      // u64
#include <sharechain/v37/v37_hash.hpp>       // bytes32

namespace c2pool::v37n::owedevent {

using ::v37::bytes32;
using ::v37::u64;

using Amounts = std::map<bytes32, long long>;

// Same numbering as w6_persistence.hpp's EvKind (static_assert'd there).
enum EvKind : std::uint8_t { EV_FOUND = 1, EV_FINALIZE = 2, EV_ORPHAN = 3 };

inline constexpr char LEAF_TAG[4] = {'V', '3', '7', 'L'};

namespace detail {
inline void put_u32(std::vector<std::uint8_t>& b, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) b.push_back(std::uint8_t((x >> (8 * i)) & 0xff));
}
inline void put_u64(std::vector<std::uint8_t>& b, u64 x) {
    for (int i = 0; i < 8; ++i) b.push_back(std::uint8_t((x >> (8 * i)) & 0xff));
}
// u32 n || n x (key || i64 LE), zero rows dropped, std::map key order.
inline void put_amap(std::vector<std::uint8_t>& b, const Amounts& m) {
    std::uint32_t n = 0;
    for (const auto& [k, v] : m) { (void)k; if (v != 0) ++n; }
    put_u32(b, n);
    for (const auto& [k, v] : m) {
        if (v == 0) continue;                       // normalization: drop zero rows
        b.insert(b.end(), k.begin(), k.end());
        put_u64(b, static_cast<u64>(v));            // i64 two's complement, LE
    }
}
} // namespace detail

// The canonical leaf payload. `credit`, `payout`, `settled` are the maps the
// ledger consumed on this mutation (see the normalization table above).
inline std::vector<std::uint8_t> leaf_payload(std::uint8_t evkind,
                                              const std::string& bid,
                                              u64 bin_height,
                                              const Amounts& credit,
                                              const Amounts& payout,
                                              const Amounts& settled) {
    std::vector<std::uint8_t> p;
    p.reserve(64 + bid.size());
    p.insert(p.end(), LEAF_TAG, LEAF_TAG + 4);
    p.push_back(evkind);
    detail::put_u32(p, static_cast<std::uint32_t>(bid.size()));
    p.insert(p.end(), bid.begin(), bid.end());
    detail::put_u64(p, bin_height);
    detail::put_amap(p, credit);
    detail::put_amap(p, payout);
    detail::put_amap(p, settled);
    return p;
}

// ── the four canonical mutations ─────────────────────────────────────────
inline std::vector<std::uint8_t> found_payload(const std::string& bid,
                                               const Amounts& credit,
                                               const Amounts& payout) {
    return leaf_payload(EV_FOUND, bid, 0, credit, payout, {});
}
inline std::vector<std::uint8_t> finalize_payload(const std::string& bid, u64 bin_height) {
    return leaf_payload(EV_FINALIZE, bid, bin_height, {}, {}, {});
}
inline std::vector<std::uint8_t> orphan_pre_payload(const std::string& bid) {
    return leaf_payload(EV_ORPHAN, bid, 0, {}, {}, {});
}
inline std::vector<std::uint8_t> orphan_settled_payload(const std::string& bid,
                                                        const Amounts& settled) {
    return leaf_payload(EV_ORPHAN, bid, 0, {}, {}, settled);
}

// ─────────────────────────────────────────────────────────────────────────
// The instance. A thin, typed face on the generic RecordLog: it owns no rule
// the generic log does not already own, and it hands the generic log out so a
// caller can prove, serialize or restore with the primitive's own API.
// ─────────────────────────────────────────────────────────────────────────
class OwedEventLog {
public:
    using PrefixProof = ::c2pool::v37n::recordlog::RecordLog::PrefixProof;

    u64 append_payload(const std::vector<std::uint8_t>& payload) {
        return m_log.append(payload);
    }
    u64 append_found(const std::string& bid, const Amounts& credit, const Amounts& payout) {
        return m_log.append(found_payload(bid, credit, payout));
    }
    u64 append_finalize(const std::string& bid, u64 bin_height) {
        return m_log.append(finalize_payload(bid, bin_height));
    }
    u64 append_orphan_pre(const std::string& bid) {
        return m_log.append(orphan_pre_payload(bid));
    }
    u64 append_orphan_settled(const std::string& bid, const Amounts& settled) {
        return m_log.append(orphan_settled_payload(bid, settled));
    }

    bytes32 root() const { return m_log.root(); }
    u64 leaf_count() const { return m_log.leaf_count(); }
    const ::v37::PeakSet& peaks() const { return m_log.peaks(); }
    bool consistent() const { return m_log.consistent(); }

    const ::c2pool::v37n::recordlog::RecordLog& log() const { return m_log; }
    ::c2pool::v37n::recordlog::RecordLog& log() { return m_log; }

private:
    ::c2pool::v37n::recordlog::RecordLog m_log;
};

} // namespace c2pool::v37n::owedevent
