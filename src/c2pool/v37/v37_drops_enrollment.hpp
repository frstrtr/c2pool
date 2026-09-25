#pragma once
// ============================================================================
// V37 DROPS — EX-ANTE ENROLLMENT (operator ruling R-SYBIL).
//
// THE ATTACK THIS CLOSES. Under the replace-not-add composition the DROPS delta
// is Hhat_comb - W_shares, and it is SIGNED: an interval where the estimator
// undershot the payee's share-derived work credits a NEGATIVE number. That is
// correct and deliberate — a one-sided payoff is exactly the sybil surface the
// rejected max(S*T, Hhat) clamp had. But a delta that is signed is only neutral
// if the payee cannot CHOOSE, per interval and AFTER the draw, whether to take
// it. If it can, the choice is worth (measured over the same draws by the
// adversarial verify pass):
//
//     identities n :      1      4     20    200    2000
//     selective    :  1.02x  1.08x  1.30x  1.84x  1.96x      <- opt in iff Hhat > S*T
//     unconditional: ~0.93..0.97x, FLAT in n                 <- take every interval
//
// The selective curve RISES with n because splitting hashrate across identities
// multiplies the number of INDEPENDENT per-interval draws, and the attacker
// keeps only the upside of each. At n = 2000 it recovers the whole x1.96 the
// replace-not-add ruling had just removed — through a different door.
//
// THE RULING. Participation in DROPS is decided EX ANTE, ONCE, by a commitment
// that is BOUND TO A DIGEST and takes effect only at an interval STRICTLY LATER
// than the one it was made in. After that:
//
//   ENROLLED identity      the harvested interval is ALWAYS composed by
//                          REPLACEMENT — credit Hhat_comb (which is 0 when
//                          J < K) and remove W_shares — EVEN WHEN Hhat_comb is
//                          SMALLER than W_shares. It takes the downside.
//   NON-ENROLLED identity  DROPS never applies at all. It keeps the ordinary
//                          S*T path, in full, in every interval.
//
// There is no third state and no per-interval switch, so the selective rule is
// not a policy this code declines to implement — it is NOT EXPRESSIBLE. The
// only choice left is the ex-ante one, and at that point the payee's own draws
// are still in the future, so its expected gain is the unconditional one:
// E[Hhat_comb - W_shares] = 0 by the exact unbiasedness of Hhat, flat in n.
//
// WHY A DIGEST-BOUND COMMITMENT AND NOT JUST A FLAG. A node-local boolean could
// be flipped between the draw and the fold, and two nodes could hold different
// booleans for the same payee at the same interval. The commitment is
//   commit = sha256d("V37ENROLL1" || payee || LE64(effective_from))
// and the BOOK DIGEST over all records
//   sha256d("V37ENROLLBOOK1" || LE32(n) || commit_0 || .. || commit_{n-1})
// (records in canonical (payee, effective_from) order) rides the S-1 wire beside
// the composed credit map, so a receiver can see WHICH enrollment set the winner
// composed under. commit() itself REFUSES a record whose effective_from is not
// strictly greater than the interval it is being made in: "enrol me, starting
// now, for the interval I have already mined" is the attack, and it is rejected
// at the only place it could enter.
//
// NOT CONSENSUS STATE BY ITSELF. Like the harvest, the book is node-local: a
// node knows the enrollments it was told about. What crosses the wire is the
// winner's COMPOSED credit map (operator ruling R3) plus this digest as its
// witness. Nothing here is re-derived by a receiver.
//
// Stdlib-only, header-only, C++20.
// ============================================================================
#include <cstdint>
#include <map>
#include <utility>
#include <vector>

#include <sharechain/v37/v37_hash.hpp>   // bytes32, sha256d

namespace c2pool::v37n {

namespace enroll_detail {

inline void put_le64(std::vector<std::uint8_t>& b, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
}
inline void put_le32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
}

}  // namespace enroll_detail

// The commitment a payee makes when it enrols. Domain-separated so it can never
// collide with a share, a receipt, a cut descriptor or an owed leaf.
inline ::v37::bytes32 enrollment_commit(const ::v37::bytes32& payee,
                                        std::uint64_t effective_from) {
    std::vector<std::uint8_t> b;
    b.reserve(10 + 32 + 8);
    const char* dom = "V37ENROLL1";
    for (const char* p = dom; *p; ++p) b.push_back(static_cast<std::uint8_t>(*p));
    for (std::uint8_t x : payee) b.push_back(x);
    enroll_detail::put_le64(b, effective_from);
    return ::v37::sha256d(b);
}

// One enrolment: this payee is a DROPS participant from `effective_from`
// onwards, committed at `committed_at` which is strictly earlier.
struct EnrollmentRecord {
    ::v37::bytes32 payee{};
    std::uint64_t  effective_from = 0;   // first interval the enrolment covers
    std::uint64_t  committed_at   = 0;   // the interval the commitment was made in
    ::v37::bytes32 commit{};             // enrollment_commit(payee, effective_from)
};

// The node's enrolment book. ONE per lane.
//
// It is deliberately APPEND-ONLY in effect: there is no withdraw(). Letting a
// payee leave between the draw and the fold would restore the per-interval
// choice this whole mechanism exists to remove. An operator that needs to stop
// crediting a lane turns the LANE gate off, which stops it for everybody at
// once and is visible in the digest.
class EnrollmentBook {
public:
    // ★ THE EX-ANTE RULE, enforced at the only entry point.
    // `now_interval` is the interval the node is currently accounting; the
    // enrolment may only take effect STRICTLY LATER. An attempt to enrol with
    // effective_from <= now_interval is REFUSED (returns false, nothing stored):
    // that is precisely "let me decide after I have seen my draws".
    //
    // Re-committing the same payee is allowed only to move its start EARLIER is
    // NOT allowed: the first effective_from that is already recorded wins, and a
    // later commit for the same payee is a no-op returning true (it cannot
    // change anything, so it is not an error). Enrolment, once made, stands.
    bool commit(const ::v37::bytes32& payee, std::uint64_t now_interval,
                std::uint64_t effective_from) {
        if (effective_from <= now_interval) { ++m_refused; return false; }
        auto it = m_by_payee.find(payee);
        if (it != m_by_payee.end()) return true;      // already enrolled: stands
        EnrollmentRecord r;
        r.payee          = payee;
        r.effective_from = effective_from;
        r.committed_at   = now_interval;
        r.commit         = enrollment_commit(payee, effective_from);
        m_by_payee.emplace(payee, r);
        return true;
    }

    // Is this payee an enrolled DROPS participant for this interval?
    // FALSE is the default for every identity that never committed — and false
    // means "the ordinary S*T path, untouched", never "credited zero".
    bool enrolled(const ::v37::bytes32& payee, std::uint64_t interval) const {
        auto it = m_by_payee.find(payee);
        if (it == m_by_payee.end()) return false;
        return interval >= it->second.effective_from;
    }

    const EnrollmentRecord* find(const ::v37::bytes32& payee) const {
        auto it = m_by_payee.find(payee);
        return it == m_by_payee.end() ? nullptr : &it->second;
    }

    std::size_t size() const { return m_by_payee.size(); }
    std::uint64_t refused() const { return m_refused; }

    // The witness that rides the wire beside the composed credit map. Canonical
    // order is the map's own (payee ascending), so two nodes holding the same
    // set of records produce the same digest regardless of arrival order.
    ::v37::bytes32 book_digest() const {
        std::vector<std::uint8_t> b;
        const char* dom = "V37ENROLLBOOK1";
        for (const char* p = dom; *p; ++p) b.push_back(static_cast<std::uint8_t>(*p));
        enroll_detail::put_le32(b, static_cast<std::uint32_t>(m_by_payee.size()));
        for (const auto& [k, r] : m_by_payee) {
            (void)k;
            for (std::uint8_t x : r.commit) b.push_back(x);
        }
        return ::v37::sha256d(b);
    }

    std::vector<EnrollmentRecord> records() const {
        std::vector<EnrollmentRecord> v;
        v.reserve(m_by_payee.size());
        for (const auto& [k, r] : m_by_payee) { (void)k; v.push_back(r); }
        return v;
    }

    void reset() { m_by_payee.clear(); m_refused = 0; }

private:
    std::map<::v37::bytes32, EnrollmentRecord> m_by_payee;
    std::uint64_t m_refused = 0;
};

// The digest of an EMPTY book — what a node with no enrolments at all carries,
// and therefore what every node on a DROPS-dormant fleet carries.
inline ::v37::bytes32 empty_enrollment_digest() {
    return EnrollmentBook{}.book_digest();
}

}  // namespace c2pool::v37n
