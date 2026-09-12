#pragma once
// ============================================================================
// V37 DROPS — THE PER-(payee, interval) SHARE-COUNT PRODUCER.
//
// THE GAP THIS CLOSES. DropHarvester::declare_shares(payee, interval, S, lz) is
// MANDATORY and fail-closed: an interval whose in-interval share count was never
// declared is WITHHELD and never credited. That is the right rule — under the
// REPLACE composition an undeclared S silently means "S == 0", and a payee that
// DID land shares would then have its whole interval estimated on top of an
// intact E_b row, which is the x2 coming back through the harvester. But the
// rule left declare_shares with NO PRODUCER IN-TREE: IShareTracker exposes only
// has_prev_own() and record_share(), neither of which counts per (payee, bin),
// so on a live node every harvested interval was withheld and DROPS, though
// reachable, could never actually credit anything. The turnkey was API-only.
//
// WHERE THE COUNT ACTUALLY LIVES. W2 accounts a share on the PUSH path: every
// EmittedPush ReceiptAdmitter::emit() produces — the carrier itself, and each
// ACCEPTED receipt — is one share credited to (identity, origin_bin), and
// origin_bin is the same F1 monotone bin the harvester keys its intervals on.
// Raindrops do not go through emit() at all (that is the whole point of
// OK_SUBTARGET_DROP), so this counter sees shares and only shares. It is
// therefore not a new source of truth; it is the existing one, indexed.
//
// FAIL-CLOSED, TWICE.
//   1. The book must be ARMED, and it speaks only for intervals at or after the
//      interval it was armed at. Attach it mid-stream and every earlier interval
//      stays UNDECLARED and therefore WITHHELD — because for those the book
//      genuinely does not know whether the payee landed shares, and "unknown" is
//      exactly what declare_shares refuses to have guessed as zero.
//   2. declare_into() synthesises a row for a payee that has shares but NO
//      raindrops only when that payee is ENROLLED (v37_drops_enrollment.hpp).
//      That is required for the ex-ante rule to bind — an enrolled payee must
//      not be able to escape a bad interval by withholding its raindrops — and
//      it also bounds the memory: rows are created for the enrolled set, never
//      for every payee the lane has ever seen.
//
// NOT CONSENSUS STATE. Like the harvest, this is a node-local measurement index.
// What crosses the wire is the winner's COMPOSED credit map (DROPS-R3).
//
// Stdlib-only, header-only, C++20.
// ============================================================================
#include <cstdint>
#include <functional>
#include <map>
#include <utility>

#include <c2pool/v37/v37_drop_harvest.hpp>        // DropHarvester
#include <c2pool/v37/v37_drops_enrollment.hpp>    // EnrollmentBook
#include <c2pool/v37/w2_admission.hpp>            // EmittedPush, RecordSink

namespace c2pool::v37n {

class ShareCountBook {
public:
    using Key = std::pair<::v37::bytes32, u64>;   // (payee, interval) — ordered

    // Arm the book at the first interval it can speak for. Everything strictly
    // below stays UNKNOWN for ever (and so stays withheld by the harvester).
    void arm(u64 from_interval) { m_armed = true; m_from = from_interval; }
    bool armed() const { return m_armed; }
    u64  covers_from() const { return m_from; }
    bool covers(u64 interval) const { return m_armed && interval >= m_from; }

    // ★ THE PRODUCER. One accepted share -> one count at (identity, origin_bin).
    // Fed from the LIVE admission stream; see tee() for the one-line wiring.
    void on_push(const EmittedPush& p) {
        if (!m_armed) { ++m_unarmed_dropped; return; }
        if (p.origin_bin < m_from) { ++m_pre_arm_dropped; return; }
        ++m_count[Key{p.identity, p.origin_bin}];
        ++m_observed;
    }

    // Wrap a RecordSink so the counter sees every EmittedPush the admitter emits
    // and the engine still gets it, in order, unchanged. This is the whole
    // wiring: admitter.admit(carrier, receipts, book.tee(engine_sink)).
    RecordSink tee(RecordSink downstream) {
        return [this, downstream = std::move(downstream)](const EmittedPush& p) {
            on_push(p);
            if (downstream) downstream(p);
        };
    }

    std::uint64_t count(const ::v37::bytes32& payee, u64 interval) const {
        auto it = m_count.find(Key{payee, interval});
        return it == m_count.end() ? 0 : it->second;
    }
    std::uint64_t observed() const { return m_observed; }
    std::uint64_t pre_arm_dropped() const { return m_pre_arm_dropped; }
    std::uint64_t unarmed_dropped() const { return m_unarmed_dropped; }
    std::size_t rows() const { return m_count.size(); }

    // consensus_lz for an interval — the harvester needs it to build a
    // collector's h_T for a row that has no raindrops to carry it.
    using LzOfInterval = std::function<unsigned(u64)>;

    // ★ DECLARE every (payee, interval) strictly below `bury_before` into the
    // harvester, then forget those rows. Two sources are declared:
    //   (a) every interval the HARVESTER already holds open (it saw raindrops):
    //       S = this book's count, which is 0 for a drop-only payee — and 0 is
    //       the correct EXPLICIT statement there, not a guess;
    //   (b) every interval this BOOK counted for an ENROLLED payee that the
    //       harvester has NO row for (shares but no raindrops): the row is
    //       synthesised so the enrolled payee's interval is composed anyway
    //       (J < K => Hhat == 0 => the whole share work comes back out). Without
    //       (b) an enrolled payee could dodge a bad interval simply by not
    //       relaying its raindrops, which is the per-interval choice the ex-ante
    //       ruling exists to remove.
    // Intervals the book does not COVER are left undeclared on purpose: the
    // harvester withholds them, which is the fail-closed error.
    std::size_t declare_into(DropHarvester& h, u64 bury_before,
                             const LzOfInterval& lz_of,
                             const EnrollmentBook* enrollment) {
        std::size_t declared = 0;
        // (a) the harvester's own open intervals.
        for (const auto& k : h.open_keys()) {
            if (k.second >= bury_before) continue;
            if (!covers(k.second)) continue;                 // UNKNOWN: withhold
            h.declare_shares(k.first, k.second, count(k.first, k.second),
                             lz_of ? lz_of(k.second) : 0u);
            ++declared;
        }
        // (b) enrolled payees with shares but no raindrops in the interval.
        if (enrollment) {
            for (const auto& [k, s] : m_count) {
                (void)s;
                if (k.second >= bury_before) continue;
                if (!covers(k.second)) continue;
                if (!enrollment->enrolled(k.first, k.second)) continue;
                if (h.shares_declared(k.first, k.second)) continue;
                h.declare_shares(k.first, k.second, count(k.first, k.second),
                                 lz_of ? lz_of(k.second) : 0u);
                ++declared;
            }
        }
        // forget what is now settled
        for (auto it = m_count.begin(); it != m_count.end();)
            it = (it->first.second < bury_before) ? m_count.erase(it) : std::next(it);
        return declared;
    }

    void reset() {
        m_count.clear();
        m_armed = false;
        m_from = 0;
        m_observed = 0;
        m_pre_arm_dropped = 0;
        m_unarmed_dropped = 0;
    }

private:
    std::map<Key, std::uint64_t> m_count;
    bool m_armed = false;
    u64  m_from = 0;
    std::uint64_t m_observed = 0;
    std::uint64_t m_pre_arm_dropped = 0;
    std::uint64_t m_unarmed_dropped = 0;
};

}  // namespace c2pool::v37n
