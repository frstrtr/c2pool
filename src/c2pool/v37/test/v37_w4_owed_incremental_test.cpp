// V37 W4 — R3 incremental OWED-ledger acceleration: DIGEST-NEUTRALITY oracle KAT.
//
// Same tiny CHECK harness as v37_w4_settlement_test.cpp: no gtest, no core/Boost
// link; g++ -std=c++20 -pthread with an -I on src. This suite exercises
// OwedLedger through its PUBLIC API ONLY (on_block_found / on_block_finalized /
// on_block_orphaned / effective_owed / propose_coinbase / owed_digest / finalW),
// so it compiles and PASSES both BEFORE the R3 patch (pinning the shipped
// behaviour as the oracle) and AFTER it (proving the incremental path reproduces
// that behaviour BYTE-FOR-BYTE).
//
// The test maintains an independent SHADOW ledger implementing the ORIGINAL
// algorithm (rescan-pending EffectiveOwed, effective_owed_all()+sort proposal,
// sort-based owed_digest, rearm over finalW∪pending-payout) directly from the
// event stream it drives, and asserts at EVERY step:
//   • owed_digest()      == shadow owed_digest()        (byte-for-byte)
//   • effective_owed(k)  == shadow eo(k)   for all keys
//   • propose_coinbase() == shadow propose (key/amount/order, bit-for-bit)
// across a long pseudo-random schedule of FOUND / FINALIZE / ORPHAN(pre &
// post-SETTLED) events, plus the two adversarial cases R3's neutrality proof
// turns on: (A) a payout that drives eo to 0 then finalize prunes a zero row;
// (B) a found→orphan round-trip that restores eo without a rearm.

#include <cstdint>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>
#include <sharechain/v37/v37_descriptor.hpp>
#include <sharechain/v37/v37_fixed.hpp>
#include <sharechain/v37/v37_hash.hpp>

using ::v37::bytes32;
using ::v37::ScriptKind;
using ::v37::ScriptRef;
using ::v37::u64;
namespace S = c2pool::v37n::settle;

static int g_failures = 0;
static int g_checks = 0;
#define CHECK(cond)                                                          \
    do {                                                                     \
        ++g_checks;                                                          \
        if (!(cond)) {                                                       \
            ++g_failures;                                                    \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
        }                                                                    \
    } while (0)

// ── deterministic key + payout-script fixtures ────────────────────────────
static bytes32 mkkey(unsigned id) {
    bytes32 k{};
    k[0] = static_cast<std::uint8_t>(id & 0xff);
    k[1] = static_cast<std::uint8_t>((id >> 8) & 0xff);
    k[31] = 0xAB;  // make keys non-trivially ordered across the low bytes
    return k;
}
// pay_of: kind alternates by key so the h_min carry path differs across keys.
static ScriptRef pay_of(const bytes32& k) {
    ScriptRef r;
    r.kind = (k[0] & 1) ? ScriptKind::P2WPKH : ScriptKind::P2PKH;
    r.payload.assign(20, k[0]);
    return r;
}
static u64 h_min_of(ScriptKind kind) {
    return (kind == ScriptKind::P2WPKH) ? 330u : 546u;  // distinct dust floors
}

// ── the SHADOW ledger: the ORIGINAL (pre-R3) algorithm, verbatim ──────────
struct Shadow {
    using Amounts = std::map<bytes32, long long>;
    struct Pending { Amounts credit, payout; };
    Amounts finalW;
    std::map<std::string, Pending> pending;
    std::set<std::string> settled;
    std::map<bytes32, u64> first_eligible;

    void on_found(const std::string& bid, const Amounts& credit, const Amounts& payout) {
        if (pending.count(bid) || settled.count(bid)) return;
        Pending p;
        for (const auto& [k, v] : credit) if (v != 0) p.credit[k] = v;
        for (const auto& [k, v] : payout) if (v != 0) p.payout[k] = v;
        pending.emplace(bid, std::move(p));
    }
    long long eo(const bytes32& k) const {
        long long e = 0;
        auto it = finalW.find(k);
        if (it != finalW.end()) e = it->second;
        for (const auto& [bid, p] : pending) {
            auto pit = p.payout.find(k);
            if (pit != p.payout.end()) e -= pit->second;
        }
        return e;
    }
    Amounts eo_all() const {
        std::set<bytes32> keys;
        for (const auto& [k, v] : finalW) { (void)v; keys.insert(k); }
        for (const auto& [bid, p] : pending)
            for (const auto& [k, v] : p.payout) { (void)v; keys.insert(k); }
        Amounts out;
        for (const auto& k : keys) out[k] = eo(k);
        return out;
    }
    void rearm(u64 bin_height) {
        for (const auto& [k, e] : eo_all()) {
            if (e > 0) { if (!first_eligible.count(k)) first_eligible[k] = bin_height; }
            else first_eligible.erase(k);
        }
    }
    void on_finalize(const std::string& bid, u64 bin_height) {
        auto it = pending.find(bid);
        if (it == pending.end()) return;
        for (const auto& [k, v] : it->second.credit) finalW[k] += v;
        for (const auto& [k, v] : it->second.payout) finalW[k] -= v;
        pending.erase(it);
        settled.insert(bid);
        rearm(bin_height);
    }
    void on_orphan(const std::string& bid) {
        auto it = pending.find(bid);
        if (it != pending.end()) { pending.erase(it); return; }
        // post-SETTLED priced residual: no finalW/first_eligible change.
    }
    bytes32 owed_digest() const {
        std::vector<std::pair<bytes32, long long>> rows(finalW.begin(), finalW.end());
        std::sort(rows.begin(), rows.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        std::vector<std::uint8_t> pre;
        const char tag[4] = {'V', '3', '7', 'O'};
        pre.insert(pre.end(), tag, tag + 4);
        for (const auto& [k, w] : rows) {
            if (w == 0) continue;
            pre.insert(pre.end(), k.begin(), k.end());
            std::uint64_t uw = static_cast<std::uint64_t>(w);
            for (int i = 0; i < 8; ++i) pre.push_back((uw >> (8 * i)) & 0xff);
            u64 fe = 0;
            auto it = first_eligible.find(k);
            if (it != first_eligible.end()) fe = it->second;
            for (int i = 0; i < 8; ++i) pre.push_back((fe >> (8 * i)) & 0xff);
        }
        return ::v37::sha256d(pre);
    }
    // The original propose loop, using the shipped count-cap comparison.
    struct Out { bytes32 key; ScriptRef pay; u64 amount; };
    std::vector<Out> propose(u64 reward, unsigned C) const {
        std::vector<std::pair<u64, bytes32>> elig;
        for (const auto& [k, e] : eo_all()) {
            if (e <= 0) continue;
            u64 fe = 0;
            auto it = first_eligible.find(k);
            if (it != first_eligible.end()) fe = it->second;
            elig.emplace_back(fe, k);
        }
        std::sort(elig.begin(), elig.end());
        std::vector<Out> outs;
        u64 budget = reward;
        for (const auto& [fe, k] : elig) {
            (void)fe;
            // R1 (combined R1+R3 tree): slot_budget_C == 0 means UNBOUNDED
            // output count — the reference cap the live propose_coinbase now
            // uses (w4_settlement.hpp). R3 does not change the count-cap; this
            // mirrors R1's 0=unbounded so the shadow stays the correct oracle.
            if (C != 0 && outs.size() >= C) break;
            if (budget == 0) break;
            long long owed = eo(k);
            if (owed <= 0) continue;
            u64 take = std::min<u64>(static_cast<u64>(owed), budget);
            ScriptRef pay = pay_of(k);
            if (take < h_min_of(pay.kind)) continue;
            budget -= take;
            outs.push_back(Out{k, pay, take});
        }
        return outs;
    }
};

// splitmix64 — deterministic PRNG (no <random> variance across libstdc++).
struct Rng {
    std::uint64_t s;
    explicit Rng(std::uint64_t seed) : s(seed) {}
    std::uint64_t next() {
        std::uint64_t z = (s += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    unsigned pick(unsigned n) { return static_cast<unsigned>(next() % n); }
};

// Compare live ledger vs shadow at the current state.
static void assert_equiv(const S::OwedLedger& L, const Shadow& sh,
                         const std::set<bytes32>& universe) {
    CHECK(L.owed_digest() == sh.owed_digest());
    for (const auto& k : universe) CHECK(L.effective_owed(k) == sh.eo(k));
    // finalW: pruned zero-and-unarmed rows may be absent in L but present-as-0
    // in the shadow; every other row must match exactly.
    const auto& lw = L.finalW();
    for (const auto& k : universe) {
        auto li = lw.find(k);
        long long lv = (li == lw.end()) ? 0 : li->second;
        long long sv = 0;
        auto si = sh.finalW.find(k);
        if (si != sh.finalW.end()) sv = si->second;
        CHECK(lv == sv);
    }
    for (u64 reward : {u64(1), u64(1000), u64(5000000000ull), u64(3)}) {
        for (unsigned C : {0u, 1u, 3u, 64u}) {
            auto lp = L.propose_coinbase(reward, C, pay_of,
                                         [](ScriptKind kd) { return h_min_of(kd); });
            auto sp = sh.propose(reward, C);
            CHECK(lp.outs.size() == sp.size());
            std::size_t n = std::min(lp.outs.size(), sp.size());
            for (std::size_t i = 0; i < n; ++i) {
                CHECK(lp.outs[i].key == sp[i].key);
                CHECK(lp.outs[i].amount == sp[i].amount);
                CHECK(lp.outs[i].pay == sp[i].pay);
            }
        }
    }
}

int main() {
    S::OwedLedger L(/*chain=*/7);
    Shadow sh;
    std::set<bytes32> universe;
    for (unsigned i = 0; i < 24; ++i) universe.insert(mkkey(i));

    Rng rng(0xC0FFEEu);
    u64 bin_height = 100;
    std::vector<std::string> live_pending;  // bids currently FOUND-not-final
    std::vector<std::string> live_settled;  // bids finalized (for post-SETTLED orphan)
    unsigned bid_ctr = 0;

    assert_equiv(L, sh, universe);  // empty ledger baseline

    for (int step = 0; step < 4000; ++step) {
        unsigned op = rng.pick(10);
        if (op < 5) {
            // FOUND: 1-4 credit keys, 0-3 payout keys (payouts small so eo can hit 0)
            std::string bid = "b" + std::to_string(bid_ctr++);
            Shadow::Amounts credit, payout;
            unsigned nc = 1 + rng.pick(4);
            for (unsigned j = 0; j < nc; ++j)
                credit[mkkey(rng.pick(24))] += 1 + (long long)rng.pick(500);
            unsigned np = rng.pick(4);
            for (unsigned j = 0; j < np; ++j)
                payout[mkkey(rng.pick(24))] += 1 + (long long)rng.pick(200);
            L.on_block_found(bid, credit, payout);
            sh.on_found(bid, credit, payout);
            live_pending.push_back(bid);
        } else if (op < 8) {
            // FINALIZE a random pending bid
            if (!live_pending.empty()) {
                unsigned idx = rng.pick((unsigned)live_pending.size());
                std::string bid = live_pending[idx];
                live_pending.erase(live_pending.begin() + idx);
                bin_height += 1 + rng.pick(3);
                L.on_block_finalized(bid, bin_height);
                sh.on_finalize(bid, bin_height);
                live_settled.push_back(bid);
            }
        } else if (op < 9) {
            // ORPHAN pre-SETTLED (a pending bid)
            if (!live_pending.empty()) {
                unsigned idx = rng.pick((unsigned)live_pending.size());
                std::string bid = live_pending[idx];
                live_pending.erase(live_pending.begin() + idx);
                L.on_block_orphaned(bid, {});
                sh.on_orphan(bid);
            }
        } else {
            // ORPHAN post-SETTLED (surfaced residual; no finalW/fe change)
            if (!live_settled.empty()) {
                unsigned idx = rng.pick((unsigned)live_settled.size());
                std::string bid = live_settled[idx];
                Shadow::Amounts sp{{mkkey(rng.pick(24)), 1 + (long long)rng.pick(50)}};
                L.on_block_orphaned(bid, sp);
                sh.on_orphan(bid);
            }
        }
        if ((step & 63) == 0) assert_equiv(L, sh, universe);
    }
    assert_equiv(L, sh, universe);

    // ── Adversarial A: payout drives eo to exactly 0, finalize prunes the row.
    {
        S::OwedLedger A(1);
        Shadow a;
        std::set<bytes32> u{mkkey(1)};
        A.on_block_found("x1", {{mkkey(1), 100}}, {});
        a.on_found("x1", {{mkkey(1), 100}}, {});
        A.on_block_finalized("x1", 10); a.on_finalize("x1", 10);   // finalW=100, armed
        assert_equiv(A, a, u);
        A.on_block_found("x2", {}, {{mkkey(1), 100}});             // pay it all → eo 0
        a.on_found("x2", {}, {{mkkey(1), 100}});
        assert_equiv(A, a, u);                                     // eo 0, still armed (no rearm)
        A.on_block_finalized("x2", 11); a.on_finalize("x2", 11);   // finalW=0, disarmed, pruned
        assert_equiv(A, a, u);
        CHECK(A.owed_digest() == a.owed_digest());
    }

    // ── Adversarial B: found→orphan round-trip restores eo with NO rearm between.
    {
        S::OwedLedger B(1);
        Shadow b;
        std::set<bytes32> u{mkkey(2)};
        B.on_block_found("y1", {{mkkey(2), 80}}, {});  b.on_found("y1", {{mkkey(2), 80}}, {});
        B.on_block_finalized("y1", 5); b.on_finalize("y1", 5);
        B.on_block_found("y2", {}, {{mkkey(2), 80}});  b.on_found("y2", {}, {{mkkey(2), 80}});
        assert_equiv(B, b, u);                          // eo 0 while y2 pending
        B.on_block_orphaned("y2", {}); b.on_orphan("y2");
        assert_equiv(B, b, u);                          // eo back to 80, fe unchanged
        CHECK(B.effective_owed(mkkey(2)) == 80);
    }

    std::printf("v37_w4_owed_incremental_test: %d checks, %d failures\n",
                g_checks, g_failures);
    return g_failures ? 1 : 0;
}
