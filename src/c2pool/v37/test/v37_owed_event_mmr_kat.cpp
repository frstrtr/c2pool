// v37_owed_event_mmr_kat.cpp
//
// OWED-EVENT MMR — the append-only authenticated record log as a GATED
// committed field. Stdlib-only harness (no gtest, no core/Boost link), the
// same convention as its siblings in this directory; returns non-zero on the
// first failure count.
//
// WHAT IT PINS, in six sections:
//
//   A  MIRROR       the one rule this change mirrors rather than calls —
//                   leaf = sha256d(0x00||payload) — against a hand-built
//                   digest, against an absolute hex golden, and against the
//                   w5 StateCommitment's own mirror (through a one-leaf
//                   commitment, whose root IS that leaf).
//   B  PRIMITIVE    the generic record log: binary-counter append, peak
//                   bagging, inclusion proofs verified by the SHIPPED
//                   ::v37::Lane::mmr_verify, prefix (append-only) proofs,
//                   serialize/deserialize with its fail-closed guards, and
//                   root-identity with a raw Lane::mmr_append/mmr_bag walk.
//   C  INSTANCE     the owed-event log inside OwedLedger: goldens over a fixed
//                   schedule, the leaf_count == ledger_seq invariant at every
//                   step, and the two mutations that deliberately mint nothing.
//   D  CONVERGENCE  two independent ledgers fed the SAME events in the SAME
//                   order reach the IDENTICAL root at every step; a permuted
//                   order does NOT (the check is not vacuous); and an ORPHAN
//                   called with a different ignored argument still converges.
//   E  RECOVERY     a real SettlementJournal writes the head, a real
//                   RecoveryDriver replays levt and re-derives the root; a
//                   corrupted head is fail-closed; an absent head (a database
//                   written before this record existed) still recovers.
//   F  GATE         with the gate OFF every committed root is byte-identical
//                   to pristine master; with it ON the StateCommitment root
//                   moves to the pinned new value, balance-leaf indices do not
//                   move, and prove() never hands back the gated leaf.
//
// The owed_digest anchors are asserted here too (the empty-ledger
// b4db1ded...); the gate-ON V37.1 ridge anchor 87c5249a... is pinned by
// v37_1_ridge_activation_test, which this change does not touch.

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include <c2pool/v37/record_log.hpp>
#include <c2pool/v37/owed_event_log.hpp>
#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/w5_coinbase.hpp>
#include <c2pool/v37/w6_persistence.hpp>

#include "owed_event_mmr_golden_v1.hpp"

using ::c2pool::v37n::coinbase::StateCommitment;
using ::c2pool::v37n::recordlog::RecordLog;
using ::c2pool::v37n::settle::OwedLedger;
using ::c2pool::v37n::settle::SettleHW;
using ::v37::bytes32;
using ::v37::u64;

namespace persist = ::c2pool::v37n::persist;
namespace recover = ::c2pool::v37n::recover;
namespace owedevent = ::c2pool::v37n::owedevent;

// ── harness ──────────────────────────────────────────────────────────────
static int g_checks = 0, g_fail = 0;
static void ok(bool cond, const std::string& what) {
    ++g_checks;
    if (!cond) { ++g_fail; std::printf("   FAIL  %s\n", what.c_str()); }
}
static std::string hx(const bytes32& h) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(64);
    for (unsigned char c : h) { s.push_back(d[c >> 4]); s.push_back(d[c & 0xf]); }
    return s;
}
static std::string hx(const std::vector<std::uint8_t>& v) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(v.size() * 2);
    for (unsigned char c : v) { s.push_back(d[c >> 4]); s.push_back(d[c & 0xf]); }
    return s;
}
static void put_u64(std::vector<std::uint8_t>& b, u64 x) {
    for (int i = 0; i < 8; ++i) b.push_back(std::uint8_t((x >> (8 * i)) & 0xff));
}
// A golden still carrying its @PLACEHOLDER@ is reported, never silently passed.
static bool minted(const char* g) { return g && g[0] != '@'; }
static void pin(const std::string& got, const char* golden, const std::string& what) {
    if (!minted(golden)) {
        ++g_checks; ++g_fail;
        std::printf("   FAIL  %s: golden not minted (placeholder %s), got %s\n",
                    what.c_str(), golden, got.c_str());
        return;
    }
    ok(got == golden, what + ": got " + got + " want " + golden);
}

// ── an in-memory ISettleStore for section E ──────────────────────────────
class MemStore : public persist::ISettleStore {
public:
    struct Batch : persist::ISettleBatch {
        MemStore* s;
        std::vector<std::pair<std::string, std::optional<std::string>>> ops;
        explicit Batch(MemStore* st) : s(st) {}
        void put(const std::string& k, const std::string& v) override { ops.push_back({k, v}); }
        void remove(const std::string& k) override { ops.push_back({k, std::nullopt}); }
        bool commit_sync() override {
            if (s->fail_next) { s->fail_next = false; return false; }
            for (auto& [k, v] : ops) { if (v) s->kv[k] = *v; else s->kv.erase(k); }
            ++s->commits;
            return true;
        }
    };
    std::unique_ptr<persist::ISettleBatch> batch() override {
        return std::make_unique<Batch>(this);
    }
    std::optional<std::string> get(const std::string& k) override {
        auto it = kv.find(k);
        if (it == kv.end()) return std::nullopt;
        return it->second;
    }
    bool for_each_prefix(const std::string& prefix,
                         const std::function<bool(const std::string&, const std::string&)>& fn) override {
        for (auto it = kv.lower_bound(prefix); it != kv.end(); ++it) {
            if (it->first.compare(0, prefix.size(), prefix) != 0) break;
            if (!fn(it->first, it->second)) return false;
        }
        return true;
    }
    std::map<std::string, std::string> kv;   // ordered: iteration is key order
    bool fail_next = false;
    int commits = 0;
};

// ═════════════════════════════════════════════════════════════════════════
int main() {
    const auto steps = oes_v1::schedule_v1();
    const auto goldens = oes_v1::goldens_v1();
    const u64 CHAIN = 7;

    // ── A · MIRROR ───────────────────────────────────────────────────────
    std::printf("-- A: the mirrored leaf rule --\n");
    {
        auto hand = [](const std::vector<std::uint8_t>& payload) {
            std::vector<std::uint8_t> b;
            b.push_back(0x00);
            b.insert(b.end(), payload.begin(), payload.end());
            return ::v37::sha256d(b);
        };
        std::vector<std::vector<std::uint8_t>> vecs = {
            {},
            {0x01},
            {'V', '3', '7', 'L'},
        };
        for (unsigned i = 0; i < 40; ++i) {
            std::vector<std::uint8_t> v;
            for (unsigned j = 0; j < i; ++j) v.push_back(std::uint8_t((i * 131u + j * 17u) & 0xff));
            vecs.push_back(v);
        }
        bool all = true;
        for (const auto& v : vecs) if (RecordLog::leaf_hash(v) != hand(v)) all = false;
        ok(all, "A1 leaf_hash == sha256d(0x00||payload) over 43 payloads");

        std::vector<std::uint8_t> kv(oes_v1::LEAF_KAT_PAYLOAD,
                                     oes_v1::LEAF_KAT_PAYLOAD + std::strlen(oes_v1::LEAF_KAT_PAYLOAD));
        const std::string got = hx(RecordLog::leaf_hash(kv));
        std::printf("   leaf_kat_golden=%s\n", got.c_str());
        pin(got, oes_v1::LEAF_KAT_GOLDEN, "A2 absolute leaf golden");

        // A3 — the w5 StateCommitment mirror. A fresh ledger has NO positive
        // balance rows, so its commitment is exactly one leaf (the "V37S"
        // summary) and merkle_root of one leaf is that leaf. Rebuilding the
        // summary payload here and hashing it with OUR mirror must reproduce
        // the w5 root, which proves the two mirrors are the same rule.
        OwedLedger fresh(static_cast<::v37::ChainId>(CHAIN));
        StateCommitment sc0(fresh, CHAIN, /*commit_owed_event_mmr*/ false);
        ok(sc0.leaf_count() == 1, "A3a fresh commitment is a single summary leaf");
        std::vector<std::uint8_t> sp;
        const char stag[4] = {'V', '3', '7', 'S'};
        sp.insert(sp.end(), stag, stag + 4);
        put_u64(sp, CHAIN);
        put_u64(sp, 0);      // ledger_seq
        put_u64(sp, 0);      // num_balances
        const bytes32 od = fresh.owed_digest();
        sp.insert(sp.end(), od.begin(), od.end());
        ok(RecordLog::leaf_hash(sp) == sc0.root(),
           "A3b StateCommitment's leaf mirror == record-log leaf mirror");
        pin(hx(od), oes_v1::EMPTY_OWED_DIGEST_ANCHOR, "A4 empty owed_digest anchor UNMOVED");

        RecordLog empty;
        pin(hx(empty.root()), oes_v1::EMPTY_LOG_ROOT, "A5 empty record-log root is all-zero");
        ok(hx(empty.root()) != std::string(oes_v1::EMPTY_OWED_DIGEST_ANCHOR),
           "A6 empty log root is NOT the empty owed anchor (different commitments)");
        ok(empty.leaf_count() == 0 && empty.consistent(), "A7 empty log is consistent");
    }

    // ── B · THE GENERIC PRIMITIVE ────────────────────────────────────────
    std::printf("-- B: the generic append-only record log --\n");
    {
        const std::size_t N = 37;                 // not a power of two: 3 peaks
        RecordLog log;
        std::vector<bytes32> leaves;
        std::vector<::v37::PeakSet> history;      // state after each append
        std::vector<bytes32> roots;
        for (std::size_t i = 0; i < N; ++i) {
            std::vector<std::uint8_t> p;
            p.push_back(std::uint8_t(i));
            for (unsigned j = 0; j < 7; ++j) p.push_back(std::uint8_t((i * 29u + j * 11u) & 0xff));
            const u64 idx = log.append(p);
            ok(idx == u64(i), "B1 append returns the 0-based index");
            leaves.push_back(RecordLog::leaf_hash(p));
            history.push_back(log.peaks());
            roots.push_back(log.root());
        }
        ok(log.leaf_count() == N, "B2 leaf_count");
        ok(log.consistent(), "B3 structural consistency (peaks == popcount)");

        // B4 — identical to a raw walk of the SHIPPED lane statics.
        ::v37::PeakSet raw;
        for (const bytes32& l : leaves) ::v37::Lane::mmr_append(raw, l);
        ok(::v37::Lane::mmr_bag(raw.peaks) == log.root(),
           "B4 root == raw Lane::mmr_append/mmr_bag over the same leaves");
        ok(raw == log.peaks(), "B5 peak set == the lane's own");

        // B6 — inclusion proof for EVERY index, verified by the shipped verifier.
        bool all_incl = true, tamper_rejected = true, wrongidx_rejected = true;
        for (u64 i = 0; i < N; ++i) {
            bytes32 leaf{}; ::v37::Lane::MmrProof p;
            if (!log.prove(i, leaf, p)) { all_incl = false; continue; }
            if (leaf != leaves[std::size_t(i)]) all_incl = false;
            if (!RecordLog::verify(log.root(), leaf, p)) all_incl = false;
            bytes32 bad = leaf; bad[0] ^= 0xff;
            if (RecordLog::verify(log.root(), bad, p)) tamper_rejected = false;
            ::v37::Lane::MmrProof q = p;
            q.index = (p.index + 1) % N;
            if (RecordLog::verify(log.root(), leaf, q)) wrongidx_rejected = false;
        }
        ok(all_incl, "B6 every inclusion proof verifies against root()");
        ok(tamper_rejected, "B7 a tampered leaf is rejected");
        ok(wrongidx_rejected, "B8 a proof replayed at the wrong index is rejected");
        {
            bytes32 leaf{}; ::v37::Lane::MmrProof p;
            ok(!log.prove(N, leaf, p), "B9 prove() refuses an out-of-range index");
        }

        // B10 — prefix (append-only) proofs at EVERY old cut.
        bool all_prefix = true, forged_rejected = true;
        for (u64 n0 = 0; n0 <= N; ++n0) {
            RecordLog::PrefixProof pp;
            if (!log.prove_prefix(n0, pp)) { all_prefix = false; continue; }
            const bytes32 old_root =
                (n0 == 0) ? bytes32{} : roots[std::size_t(n0 - 1)];
            if (!RecordLog::verify_prefix(old_root, n0, log.root(), N, pp)) all_prefix = false;
            if (!pp.appended.empty()) {
                RecordLog::PrefixProof forged = pp;
                forged.appended[0][0] ^= 0x5a;      // rewrite one appended leaf
                if (RecordLog::verify_prefix(old_root, n0, log.root(), N, forged))
                    forged_rejected = false;
                RecordLog::PrefixProof dropped = pp;
                dropped.appended.pop_back();        // claim a shorter extension
                if (RecordLog::verify_prefix(old_root, n0, log.root(), N, dropped))
                    forged_rejected = false;
            }
            if (n0 > 0) {                            // a WRONG old root must fail
                bytes32 wrong = old_root; wrong[31] ^= 0x01;
                if (RecordLog::verify_prefix(wrong, n0, log.root(), N, pp))
                    forged_rejected = false;
            }
        }
        ok(all_prefix, "B10 every prefix proof verifies (old root is a true prefix)");
        ok(forged_rejected, "B11 forged / truncated / mis-rooted prefix proofs are rejected");

        // B12 — serialize / deserialize, including the fail-closed guards.
        const std::string ser = log.serialize();
        auto back = RecordLog::deserialize(ser);
        ok(back.has_value(), "B12 serialize round-trips");
        if (back) {
            ok(back->root() == log.root() && back->leaf_count() == N &&
                   back->peaks() == log.peaks() && back->leaves() == log.leaves(),
               "B13 restored log is identical (root, count, peaks, leaves)");
            bytes32 leaf{}; ::v37::Lane::MmrProof p;
            ok(back->prove(5, leaf, p) && RecordLog::verify(back->root(), leaf, p),
               "B14 a restored log still serves valid proofs");
        }
        RecordLog nolv(false);
        for (std::size_t i = 0; i < N; ++i) nolv.append_leaf(leaves[i]);
        ok(nolv.root() == log.root() && nolv.leaf_count() == N,
           "B15 a non-retaining log has the same root (only proofs are lost)");
        {
            bytes32 leaf{}; ::v37::Lane::MmrProof p;
            ok(!nolv.prove(0, leaf, p), "B16 a non-retaining log cannot prove");
        }
        auto ser2 = nolv.serialize();
        ok(RecordLog::deserialize(ser2).has_value(), "B17 non-retaining form round-trips");
        ok(!RecordLog::deserialize(ser.substr(0, ser.size() - 1)).has_value(),
           "B18 truncation is rejected");
        ok(!RecordLog::deserialize(ser + "x").has_value(), "B19 trailing garbage is rejected");
        {
            std::string bad = ser; bad[0] = char(RecordLog::leaf_hash({})[0] | 0x80);
            bad[0] = char(0x7f);                                  // unknown newer version
            ok(!RecordLog::deserialize(bad).has_value(), "B20 unknown newer version is rejected");
            std::string bad2 = ser; bad2[1] = char(0x02);         // reserved flag bit set
            ok(!RecordLog::deserialize(bad2).has_value(), "B21 reserved flag bits are rejected");
            std::string bad3 = ser; bad3[2] = char(std::uint8_t(bad3[2]) ^ 0x01);  // leaf_count
            ok(!RecordLog::deserialize(bad3).has_value(),
               "B22 a leaf_count whose popcount contradicts n_peaks is rejected");
            if (!log.leaves().empty()) {
                std::string bad4 = ser;
                bad4[bad4.size() - 1] = char(std::uint8_t(bad4[bad4.size() - 1]) ^ 0xff);
                ok(!RecordLog::deserialize(bad4).has_value(),
                   "B23 leaves that do not re-derive the stored peaks are rejected");
            }
        }
    }

    // ── C · THE OWED-EVENT INSTANCE ──────────────────────────────────────
    std::printf("-- C: the owed-event instance --\n");
    {
        OwedLedger led(static_cast<::v37::ChainId>(CHAIN));
        ok(led.owed_event_leaf_count() == 0 && led.owed_event_log_consistent(),
           "C1 a fresh ledger has an empty, consistent record log");

        // C2 — the canonical bytes of the FIRST leaf, pinned as hex.
        {
            const auto& st = steps[0];
            OwedLedger::Amounts norm_c, norm_p;
            for (const auto& [k, v] : st.credit) if (v != 0) norm_c[k] = v;
            for (const auto& [k, v] : st.payout) if (v != 0) norm_p[k] = v;
            const auto pay = owedevent::found_payload(st.bid, norm_c, norm_p);
            std::printf("   first_leaf_payload=%s\n", hx(pay).c_str());
            std::printf("   first_leaf_hash=%s\n", hx(RecordLog::leaf_hash(pay)).c_str());
            pin(hx(pay), oes_v1::FIRST_LEAF_PAYLOAD_HEX, "C2a first leaf payload bytes");
            pin(hx(RecordLog::leaf_hash(pay)), oes_v1::FIRST_LEAF_HASH, "C2b first leaf hash");
        }

        std::size_t applied = 0, gi = 0;
        bool invariant = true, noop_minted_nothing = true;
        auto at_cut = [&](const oes_v1::Golden& g) {
            ok(led.ledger_seq() == g.ledger_seq,
               "C3 ledger_seq at cut " + std::to_string(g.steps));
            ok(led.owed_event_leaf_count() == g.mmr_leaves,
               "C4 mmr leaf_count at cut " + std::to_string(g.steps));
            std::printf("   cut@%-2zu seq=%-3llu mmr_leaves=%-3llu mmr_root=%s\n",
                        g.steps, (unsigned long long)led.ledger_seq(),
                        (unsigned long long)led.owed_event_leaf_count(),
                        hx(led.owed_event_mmr_root()).c_str());
            pin(hx(led.owed_event_mmr_root()), g.mmr_root,
                "C5 owed_event_mmr_root at cut " + std::to_string(g.steps));
            pin(hx(led.owed_digest()), g.owed_digest,
                "C6 owed_digest UNMOVED at cut " + std::to_string(g.steps));
        };
        while (gi < goldens.size() && goldens[gi].steps == 0) { at_cut(goldens[gi]); ++gi; }
        for (const auto& st : steps) {
            const u64 seq0 = led.ledger_seq();
            const u64 lc0 = led.owed_event_leaf_count();
            oes_v1::apply_step(led, st);
            const u64 seq1 = led.ledger_seq();
            const u64 lc1 = led.owed_event_leaf_count();
            if (seq1 - seq0 != lc1 - lc0) invariant = false;
            if (!led.owed_event_log_consistent()) invariant = false;
            if (!st.expect_seq_bump && (seq1 != seq0 || lc1 != lc0)) noop_minted_nothing = false;
            if (st.expect_seq_bump && (seq1 != seq0 + 1 || lc1 != lc0 + 1)) invariant = false;
            ++applied;
            while (gi < goldens.size() && goldens[gi].steps == applied) { at_cut(goldens[gi]); ++gi; }
        }
        ok(gi == goldens.size(), "C7 every golden cut was reached");
        ok(invariant, "C8 leaf_count() == ledger_seq() at EVERY step (one leaf per bump)");
        ok(noop_minted_nothing, "C9 the two refused mutations mint neither seq nor leaf");

        // C10 — determinism: the same schedule on a fresh object, twice.
        OwedLedger a(static_cast<::v37::ChainId>(CHAIN)), b(static_cast<::v37::ChainId>(CHAIN));
        for (const auto& st : steps) oes_v1::apply_step(a, st);
        for (const auto& st : steps) oes_v1::apply_step(b, st);
        ok(a.owed_event_mmr_root() == led.owed_event_mmr_root() &&
               b.owed_event_mmr_root() == led.owed_event_mmr_root(),
           "C10 the root is deterministic over a fixed event stream");
    }

    // ── D · CONVERGENCE BY CONSTRUCTION ──────────────────────────────────
    std::printf("-- D: convergence by construction --\n");
    {
        // D1 — two INDEPENDENT ledgers, same events, same order: identical root
        // after EVERY step, not merely at the end.
        OwedLedger n1(static_cast<::v37::ChainId>(CHAIN));
        OwedLedger n2(static_cast<::v37::ChainId>(11));   // different chain id:
        // the chain is NOT in the leaf bytes, so it must not move the root.
        bool lockstep = true;
        for (const auto& st : steps) {
            oes_v1::apply_step(n1, st);
            oes_v1::apply_step(n2, st);
            if (n1.owed_event_mmr_root() != n2.owed_event_mmr_root()) lockstep = false;
            if (n1.owed_event_leaf_count() != n2.owed_event_leaf_count()) lockstep = false;
        }
        ok(lockstep, "D1 two independent ledgers agree on the root at EVERY step");
        std::printf("   converged_root=%s leaves=%llu\n",
                    hx(n1.owed_event_mmr_root()).c_str(),
                    (unsigned long long)n1.owed_event_leaf_count());

        // D2 — the check is NOT vacuous: a different ORDER gives a different
        // root. Swap the first FOUND/FINALIZE pair's neighbours.
        {
            auto perm = steps;
            for (std::size_t i = 0; i + 1 < perm.size(); ++i) {
                if (perm[i].op == 0 && perm[i + 1].op == 0) { std::swap(perm[i], perm[i + 1]); break; }
            }
            OwedLedger p(static_cast<::v37::ChainId>(CHAIN));
            for (const auto& st : perm) oes_v1::apply_step(p, st);
            ok(p.owed_event_leaf_count() == n1.owed_event_leaf_count(),
               "D2a the permutation applies the same number of mutations");
            ok(p.owed_event_mmr_root() != n1.owed_event_mmr_root(),
               "D2b a REORDERED event stream gives a DIFFERENT root (non-vacuous)");
        }

        // D3 — the pre-SETTLED ORPHAN argument the ledger ignores must not
        // reach the leaf: a peer that passes {} and one that passes the payout
        // map still converge.
        {
            auto variant = steps;
            for (auto& st : variant)
                if (st.op == 2) st.settled.clear();     // strip every ORPHAN argument
            OwedLedger v(static_cast<::v37::ChainId>(CHAIN));
            for (const auto& st : variant) oes_v1::apply_step(v, st);
            // The post-SETTLED residual DOES enter the leaf (the ledger consumes
            // it), so stripping it must move the root; the pre-SETTLED ones must
            // not. Isolate the pre-SETTLED case.
            auto pre_only = steps;
            for (auto& st : pre_only)
                if (st.op == 2 && st.note == std::string("ORPHAN pre-SETTLED"))
                    st.settled[oes_v1::key_of(31)] = 123456;   // a different ignored value
            OwedLedger w(static_cast<::v37::ChainId>(CHAIN));
            for (const auto& st : pre_only) oes_v1::apply_step(w, st);
            ok(w.owed_event_mmr_root() == n1.owed_event_mmr_root(),
               "D3a a pre-SETTLED ORPHAN's IGNORED argument does not move the root");
            ok(v.owed_event_mmr_root() != n1.owed_event_mmr_root(),
               "D3b a post-SETTLED ORPHAN's CONSUMED residual DOES move the root");
        }

        // D4 — a randomized cross-check: 200 random schedules, two ledgers each.
        std::mt19937 rng(20260912u);
        bool rand_converged = true, rand_distinct = false;
        bytes32 prev{};
        for (int t = 0; t < 200; ++t) {
            std::vector<oes_v1::Step> rs;
            std::vector<std::string> live;
            for (int k = 0; k < 16; ++k) {
                oes_v1::Step st;
                const int pick = int(rng() % 3);
                if (pick == 0 || live.empty()) {
                    st.op = 0;
                    st.bid = "r" + std::to_string(t) + "_" + std::to_string(k);
                    st.credit[oes_v1::key_of(rng() % 8)] = static_cast<long long>(rng() % 5000);
                    st.payout[oes_v1::key_of(rng() % 8)] = static_cast<long long>(rng() % 500);
                    live.push_back(st.bid);
                } else {
                    const std::size_t j = rng() % live.size();
                    st.op = (pick == 1) ? 1 : 2;
                    st.bid = live[j];
                    st.bin_height = 1000 + (rng() % 100);
                    if (st.op == 2) st.settled[oes_v1::key_of(rng() % 8)] = static_cast<long long>(rng() % 400);
                }
                rs.push_back(st);
            }
            OwedLedger x(static_cast<::v37::ChainId>(1)), y(static_cast<::v37::ChainId>(2));
            for (const auto& st : rs) { oes_v1::apply_step(x, st); oes_v1::apply_step(y, st); }
            if (x.owed_event_mmr_root() != y.owed_event_mmr_root()) rand_converged = false;
            if (!x.owed_event_log_consistent()) rand_converged = false;
            if (t > 0 && x.owed_event_mmr_root() != prev) rand_distinct = true;
            prev = x.owed_event_mmr_root();
        }
        ok(rand_converged, "D4a 200 random schedules: both ledgers always agree");
        ok(rand_distinct, "D4b those roots are not all the same value");
    }

    // ── E · W6 PERSISTENCE + RECOVERY ────────────────────────────────────
    std::printf("-- E: persistence and recovery --\n");
    {
        auto drive = [&](MemStore& store, OwedLedger& led, SettleHW& hw,
                         std::map<u64, bytes32>& winners) {
            persist::SettlementJournal j(store, /*boot_id*/ 1);
            persist::MetaRec meta; meta.schema = 1; meta.boot_id = 1;
            j.write_meta(meta);
            const auto C = static_cast<::v37::ChainId>(CHAIN);
            u64 height = 1000;
            for (const auto& st : steps) {
                if (st.op == 0) {
                    bytes32 sh{};
                    sh[0] = std::uint8_t(height & 0xff);
                    sh[1] = std::uint8_t((height >> 8) & 0xff);
                    j.on_tip_advanced(C, height, sh, hw, led);
                    winners[height] = sh;
                    ::c2pool::v37n::settle::CutToken cut;
                    cut.chain = C; cut.ledger_seq = led.ledger_seq();
                    cut.owed_digest = led.owed_digest(); cut.hw_height = hw.hw_height;
                    j.on_block_found_twophase(C, st.bid, sh, height, 5000000000ull,
                                              st.credit, st.payout, cut, hw, led,
                                              []() { return true; });
                    height += 10;
                } else if (st.op == 1) {
                    j.on_block_finalized(C, st.bid, st.bin_height <= hw.hw_height
                                                        ? st.bin_height : hw.hw_height,
                                         hw, led);
                } else {
                    j.on_block_orphaned(C, st.bid, st.settled, hw, led);
                }
            }
        };

        MemStore store;
        OwedLedger led(static_cast<::v37::ChainId>(CHAIN));
        SettleHW hw;
        std::map<u64, bytes32> winners;
        drive(store, led, hw, winners);

        const bytes32 live_root = led.owed_event_mmr_root();
        const u64 live_leaves = led.owed_event_leaf_count();
        std::printf("   live seq=%llu mmr_leaves=%llu mmr_root=%s\n",
                    (unsigned long long)led.ledger_seq(),
                    (unsigned long long)live_leaves, hx(live_root).c_str());
        ok(led.owed_event_log_consistent(), "E1 the journal-driven ledger stays consistent");

        const std::string lk = "v37s:lmmr:" + persist::keys::chain_fmt(
            static_cast<::v37::ChainId>(CHAIN));
        auto raw = store.get(lk);
        ok(raw.has_value(), "E2 the lmmr head record was written");
        if (raw) {
            auto dec = persist::decode_lmmr(*raw);
            ok(dec.has_value(), "E3 the lmmr record decodes");
            if (dec) {
                ok(dec->root == live_root && dec->leaf_count == live_leaves &&
                       dec->ledger_seq == led.ledger_seq(),
                   "E4 the persisted head matches the live log");
                ok(dec->peaks == led.owed_event_peaks().peaks, "E5 the persisted peaks match");
            }
        }
        // census must accept the new record kind.
        ok(persist::census_open(store).ok,
           "E6 census_open accepts a database carrying lmmr records");

        auto make_hooks = [&winners]() {
            recover::RecoveryHooks h;
            h.winner_at = [&winners](u64, u64 height) -> std::optional<bytes32> {
                auto it = winners.find(height);
                if (it == winners.end()) return std::nullopt;
                return it->second;
            };
            return h;
        };

        {   // E7 — the happy path: replay re-derives the root.
            MemStore copy = store;
            recover::RecoveryDriver rd(copy, make_hooks());
            auto res = rd.recover();
            ok(res.ok(), "E7a recovery succeeds");
            auto it = res.chains.find(CHAIN);
            ok(it != res.chains.end(), "E7b the chain was recovered");
            if (it != res.chains.end()) {
                ok(it->second.lmmr_present, "E7c the head was found");
                ok(it->second.lmmr_verified, "E7d the REPLAYED log reproduced the head");
                ok(it->second.ledger && it->second.ledger->owed_event_mmr_root() == live_root,
                   "E7e the replayed record-log root == the live root");
                ok(it->second.ledger && it->second.ledger->owed_event_leaf_count() == live_leaves,
                   "E7f the replayed leaf_count == the live leaf_count");
                ok(it->second.ledger && it->second.ledger->owed_digest() == led.owed_digest(),
                   "E7g the replayed owed_digest still matches too");
            }
        }
        {   // E8 — a corrupted head is fail-closed, and names itself.
            MemStore copy = store;
            auto rec = persist::decode_lmmr(copy.kv[lk]);
            persist::LmmrRec bad = *rec;
            bad.root[0] ^= 0xff;
            copy.kv[lk] = persist::encode_lmmr(bad);
            recover::RecoveryDriver rd(copy, make_hooks());
            auto res = rd.recover();
            auto it = res.chains.find(CHAIN);
            bool named = false;
            if (it != res.chains.end())
                for (const auto& f : it->second.fails)
                    if (f.condition == "lmmr_root_mismatch") named = true;
            ok(!res.ok(), "E8a a corrupted head refuses the start");
            ok(named, "E8b the refusal is named lmmr_root_mismatch");
        }
        {   // E9 — a truncated head value is rejected by the decoder.
            MemStore copy = store;
            copy.kv[lk] = copy.kv[lk].substr(0, copy.kv[lk].size() - 3);
            recover::RecoveryDriver rd(copy, make_hooks());
            auto res = rd.recover();
            bool named = false;
            auto it = res.chains.find(CHAIN);
            if (it != res.chains.end())
                for (const auto& f : it->second.fails)
                    if (f.condition == "lmmr_decode") named = true;
            ok(!res.ok() && named, "E9 a truncated head is rejected as lmmr_decode");
        }
        {   // E10 — BACKWARD COMPATIBILITY: a database written before this
            // record existed has no lmmr key and must still recover.
            MemStore copy = store;
            copy.kv.erase(lk);
            recover::RecoveryDriver rd(copy, make_hooks());
            auto res = rd.recover();
            auto it = res.chains.find(CHAIN);
            ok(res.ok(), "E10a a pre-lmmr database still recovers");
            ok(it != res.chains.end() && !it->second.lmmr_present && !it->second.lmmr_verified,
               "E10b it is reported as 'no head to check', not as corruption");
            ok(it != res.chains.end() && it->second.ledger &&
                   it->second.ledger->owed_event_mmr_root() == live_root,
               "E10c the replayed log is still rebuilt to the same root");
        }
        {   // E11 — a dropped levt tail must NOT pass: the log is one leaf short.
            MemStore copy = store;
            std::string last;
            for (const auto& [k, v] : copy.kv)
                if (k.rfind("v37s:levt:", 0) == 0) last = k;
            copy.kv.erase(last);
            recover::RecoveryDriver rd(copy, make_hooks());
            auto res = rd.recover();
            ok(!res.ok(), "E11 a dropped levt tail is fail-closed");
        }
    }

    // ── F · THE GATE ─────────────────────────────────────────────────────
    std::printf("-- F: the committed-field gate --\n");
    {
        // F1 — the DEFAULT build has the gate OFF. Compiling the whole tree
        // with -DV37_OWED_EVENT_MMR_COMMIT=1 flips it; this KAT then still
        // passes (every check below names the gate explicitly), and F1b is the
        // assertion that the SHIPPED default is 0.
        std::printf("   commit gate default = %s\n",
                    ::c2pool::v37n::recordlog::kCommitOwedEventMmrDefault ? "ON" : "OFF");
#if !defined(V37_OWED_EVENT_MMR_COMMIT) || (V37_OWED_EVENT_MMR_COMMIT == 0)
        ok(::c2pool::v37n::recordlog::kCommitOwedEventMmrDefault == false,
           "F1a the commit gate is OFF in the default build");
#else
        ok(::c2pool::v37n::recordlog::kCommitOwedEventMmrDefault == true,
           "F1a -DV37_OWED_EVENT_MMR_COMMIT=1 turns the gate ON");
#endif
        {   // the default-constructed commitment must follow the gate constant.
            OwedLedger probe(static_cast<::v37::ChainId>(CHAIN));
            StateCommitment dflt(probe, CHAIN);
            ok(dflt.commits_owed_event_mmr() ==
                   ::c2pool::v37n::recordlog::kCommitOwedEventMmrDefault,
               "F1b the default commitment follows the gate constant");
        }

        OwedLedger led(static_cast<::v37::ChainId>(CHAIN));
        std::size_t applied = 0, gi = 0;
        auto at_cut = [&](const oes_v1::Golden& g) {
            StateCommitment off(led, CHAIN, /*commit_owed_event_mmr*/ false);
            StateCommitment on(led, CHAIN, /*commit_owed_event_mmr*/ true);
            pin(hx(off.root()), g.sc_root_gate_off,
                "F2 gate-OFF StateCommitment root BYTE-IDENTICAL to master at cut " +
                    std::to_string(g.steps));
            ok(!off.commits_owed_event_mmr(), "F3 gate-OFF commitment carries no MMR leaf");
            ok(on.commits_owed_event_mmr(), "F4 gate-ON commitment carries the MMR leaf");
            ok(on.leaf_count() == off.leaf_count() + 1, "F5 the gate adds exactly one leaf");
            ok(on.root() != off.root(), "F6 the gate MOVES the committed root (a flag day)");
            ok(on.owed_event_mmr_root() == led.owed_event_mmr_root() &&
                   off.owed_event_mmr_root() == led.owed_event_mmr_root(),
               "F7 the value is readable either way; only committing is gated");
            ok(on.owed_digest() == off.owed_digest() && on.owed_digest() == led.owed_digest(),
               "F8 owed_digest is identical on both sides of the gate");
            std::printf("   cut@%-2zu sc_off=%s\n            sc_on =%s\n",
                        g.steps, hx(off.root()).c_str(), hx(on.root()).c_str());
            pin(hx(on.root()), g.sc_root_gate_on,
                "F9 gate-ON StateCommitment root at cut " + std::to_string(g.steps));

            // F10 — balance-leaf indices do not move, and prove() never returns
            // the gated leaf.
            bool proofs_ok = true, mmr_leaf_never_proved = true;
            for (const auto& [k, w] : led.finalW()) {
                if (w <= 0) continue;
                bytes32 lo{}, ln{};
                ::v37::Lane::MerkleProof po, pn;
                if (!off.prove(k, lo, po) || !on.prove(k, ln, pn)) { proofs_ok = false; continue; }
                if (lo != ln) proofs_ok = false;                    // same leaf bytes
                if (po.index != pn.index) proofs_ok = false;        // same position
                if (!::v37::Lane::verify_proof(off.root(), lo, po)) proofs_ok = false;
                if (!::v37::Lane::verify_proof(on.root(), ln, pn)) proofs_ok = false;
            }
            {
                bytes32 lz{}; ::v37::Lane::MerkleProof pz;
                if (on.prove(bytes32{}, lz, pz)) mmr_leaf_never_proved = false;
            }
            ok(proofs_ok, "F10 balance leaves keep their bytes and index across the gate");
            ok(mmr_leaf_never_proved, "F11 prove() never returns the gated MMR leaf");
        };
        while (gi < goldens.size() && goldens[gi].steps == 0) { at_cut(goldens[gi]); ++gi; }
        for (const auto& st : steps) {
            oes_v1::apply_step(led, st);
            ++applied;
            while (gi < goldens.size() && goldens[gi].steps == applied) { at_cut(goldens[gi]); ++gi; }
        }
        ok(gi == goldens.size(), "F12 every golden cut was evaluated on both sides of the gate");
    }

    std::printf("\n== v37_owed_event_mmr_kat: %d checks, %d failures -> %s\n",
                g_checks, g_fail, g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
