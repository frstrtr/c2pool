// V37 R1 — coinbase-budget non-empty regression pin (src/c2pool/v37/w5_coinbase.hpp
// + src/c2pool/v37/w4_settlement.hpp::propose_coinbase + the btc_node budget).
//
// THE BUG (R1): a DEFAULT-constructed CoinbaseBudget has slot_budget_C == 0, and
// OwedLedger::propose_coinbase gated the output-count cap as
//       if (prop.outs.size() >= slot_budget_C) break;
// so with C == 0 the very first iteration satisfies 0 >= 0 and assembly breaks
// BEFORE pushing any output — every buried coinbase emitted ZERO payout outputs.
// This is asymmetric with W5's byte budget (w5_coinbase.hpp): there
// max_payout_bytes == 0 already means UNBOUNDED. The R1 fix makes slot_budget_C
// == 0 mean UNBOUNDED too (the ratified "unbounded C" default, spec §4.6), and
// arms a real byte-denominated dust floor (k_floor > 0 → h_min > 0) on the live
// BTC-node path.
//
// This suite is the REGRESSION PIN. Same tiny stdlib-only CHECK harness as
// v37_w5_coinbase_test.cpp: no gtest, no core/Boost link; one translation unit
// that returns nonzero on any failure.
//
// Coverage:
//   • test_default_budget_nonempty     — THE PIN: a DEFAULT-constructed
//        CoinbaseBudget over a ledger with positive finalized balances assembles
//        a NON-EMPTY coinbase (every eligible balance the reward covers is paid).
//        Fails on the pre-fix code (0 >= 0 → empty).
//   • test_default_C_is_unbounded      — the default C == 0 does NOT cap the
//        count: N eligible balances → N outputs, symmetric with the byte budget's
//        0-means-unbounded.
//   • test_assemble_is_digest_neutral  — assemble()/propose_coinbase() MUTATE
//        NOTHING in W4: owed_digest() and the §13 state root are byte-identical
//        before and after assembly, and independent of the budget values (the
//        R1 digest-neutrality invariant, at a fixed ledger state).
//   • test_live_floor_arms             — the btc-node live budget (a real
//        slot_budget_C + k_floor > 0): above-floor balances emit, a sub-h_min
//        balance is CARRIED (never dust), non-empty overall.

#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/w5_coinbase.hpp>
#include <sharechain/v37/v37_lane.hpp>

using ::v37::bytes32;
using ::v37::ScriptKind;
using ::v37::ScriptRef;
using ::v37::u64;
namespace S = c2pool::v37n::settle;
namespace CB = c2pool::v37n::coinbase;

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

// ── identities: one distinct P2PKH ScriptRef per fill byte ────────────────
static bytes32 mkkey(std::uint8_t fill) {
    bytes32 k{};
    for (auto& b : k) b = fill;
    return k;
}
static ScriptRef p2pkh(std::uint8_t fill) {
    ScriptRef r;
    r.kind = ScriptKind::P2PKH;
    r.payload.assign(20, fill);
    return r;
}
struct Reg {
    std::map<bytes32, ScriptRef> pay;
    void add(const bytes32& k, const ScriptRef& r) { pay[k] = r; }
    ScriptRef of(const bytes32& k) const {
        auto it = pay.find(k);
        return it == pay.end() ? ScriptRef{} : it->second;
    }
};
static Reg g_reg;
static ScriptRef pay_of(const bytes32& k) { return g_reg.of(k); }

// Credit `amount` to `key` and FINALIZE at bin_height (arms first_eligible, so
// the balance lives in the FINALIZED partition owed_digest commits).
static void credit_final(S::OwedLedger& L, const std::string& bid,
                         const bytes32& key, long long amount, u64 bin_height) {
    S::OwedLedger::Amounts credit{{key, amount}};
    L.on_block_found(bid, credit, {});
    L.on_block_finalized(bid, bin_height);
}

// A ledger with three positive, finalized, distinct-age balances — all eligible.
static S::OwedLedger three_positive() {
    bytes32 A = mkkey(0x21), B = mkkey(0x22), C = mkkey(0x23);
    g_reg.add(A, p2pkh(0x21));
    g_reg.add(B, p2pkh(0x22));
    g_reg.add(C, p2pkh(0x23));
    S::OwedLedger L(11);
    credit_final(L, "a", A, 500, 100);   // oldest
    credit_final(L, "b", B, 700, 200);
    credit_final(L, "c", C, 900, 300);   // youngest
    return L;
}

// ─────────────────────────────────────────────────────────────────────────
// THE PIN: a DEFAULT CoinbaseBudget must assemble a NON-EMPTY coinbase.
// Pre-fix, slot_budget_C == 0 made propose_coinbase break on the first
// iteration (0 >= 0) and emit ZERO outputs. This CHECK is the regression guard.
// ─────────────────────────────────────────────────────────────────────────
static void test_default_budget_nonempty() {
    S::OwedLedger L = three_positive();

    CB::CoinbaseBudget bud;   // DEFAULT: slot_budget_C=0, max_payout_bytes=0, k_floor=0
    CHECK(bud.slot_budget_C == 0);       // the exact default that used to break
    CHECK(bud.max_payout_bytes == 0);
    CHECK(bud.k_floor == 0);

    auto cb = CB::assemble(L, /*block_reward=*/50000, bud, pay_of);

    // The regression pin: NON-EMPTY. (Pre-fix this was 0.)
    CHECK(!cb.outputs.empty());
    CHECK(cb.outputs.size() == 3);   // every eligible balance is paid
    // And the emitted amounts are the owed balances (reward covers them all).
    u64 total = 0;
    for (const auto& o : cb.outputs) total += o.amount;
    CHECK(total == 500 + 700 + 900);
}

// The default C == 0 is UNBOUNDED, not a zero cap — symmetric with the byte
// budget. Growing the eligible set grows the output count with no ceiling.
static void test_default_C_is_unbounded() {
    S::OwedLedger L(12);
    const int N = 9;
    for (int i = 0; i < N; ++i) {
        bytes32 k = mkkey(static_cast<std::uint8_t>(0x40 + i));
        g_reg.add(k, p2pkh(static_cast<std::uint8_t>(0x40 + i)));
        credit_final(L, std::string("k") + char('0' + i), k, 100 + i, 100 + i);
    }
    CB::CoinbaseBudget bud;   // default (all zero → unbounded C, unbounded K_max)
    auto cb = CB::assemble(L, 10000000, bud, pay_of);
    CHECK(cb.outputs.size() == static_cast<std::size_t>(N));   // no count cap
}

// assemble()/propose_coinbase() are const and mutate nothing in W4; the two
// consensus commitments (owed_digest + §13 state root) are byte-identical
// before and after assembly, and identical across DIFFERENT budgets at the same
// ledger state. This is the R1 digest-neutrality invariant (per-digest, fixed
// state): the digest is provably budget-independent.
static void test_assemble_is_digest_neutral() {
    S::OwedLedger L = three_positive();

    bytes32 od_before = L.owed_digest();
    bytes32 root_before = CB::StateCommitment(L, L.chain()).root();
    u64 seq_before = L.ledger_seq();

    CB::CoinbaseBudget def;          // default (unbounded)
    CB::CoinbaseBudget cap;          // a finite, real budget
    cap.slot_budget_C = 2;
    cap.max_payout_bytes = 34;       // room for exactly one P2PKH output
    cap.k_floor = 1;                 // real dust floor
    auto cb_def = CB::assemble(L, 50000, def, pay_of);
    auto cb_cap = CB::assemble(L, 50000, cap, pay_of);

    bytes32 od_after = L.owed_digest();
    bytes32 root_after = CB::StateCommitment(L, L.chain()).root();

    // The ledger is untouched by assembly under ANY budget.
    CHECK(od_after == od_before);
    CHECK(root_after == root_before);
    CHECK(L.ledger_seq() == seq_before);
    // Both assemblies commit the SAME §13 root (it is a function of ledger state
    // only, never of the budget) even though they emit different output sets.
    CHECK(cb_def.state_root == root_before);
    CHECK(cb_cap.state_root == root_before);
    // Non-vacuous: the budgets DO produce different emission (so the equality of
    // the digest above is a real neutrality claim, not a degenerate one).
    CHECK(cb_def.outputs.size() != cb_cap.outputs.size());
}

// The btc-node live budget: a real slot_budget_C + k_floor > 0. An above-floor
// balance emits; a sub-h_min balance is CARRIED (deferred, owed unchanged),
// never emitted as dust. Overall the coinbase is non-empty.
static void test_live_floor_arms() {
    bytes32 BIG = mkkey(0x71), DUST = mkkey(0x72);
    g_reg.add(BIG, p2pkh(0x71));
    g_reg.add(DUST, p2pkh(0x72));

    S::OwedLedger L(13);
    credit_final(L, "big", BIG, 1000, 100);   // >> h_min(P2PKH)=34
    credit_final(L, "dust", DUST, 5, 200);     // < h_min(P2PKH)=34 → carry

    CB::CoinbaseBudget bud;        // model the btc-node live budget
    bud.slot_budget_C = 8;         // a real finite output-count cap
    bud.max_payout_bytes = 0;      // unbounded bytes here
    bud.k_floor = 1;               // real byte floor → h_min(P2PKH)=34

    CHECK(CB::h_min(ScriptKind::P2PKH, bud.k_floor) == 34);
    auto cb = CB::assemble(L, 50000, bud, pay_of);

    CHECK(!cb.outputs.empty());
    CHECK(cb.outputs.size() == 1);          // only the above-floor balance
    CHECK(cb.outputs[0].key == BIG);
    CHECK(cb.outputs[0].amount == 1000);
    // The dust balance stayed owed (carry-forward, not dropped, not dust-emitted).
    CHECK(L.effective_owed(DUST) == 5);
}

int main() {
    test_default_budget_nonempty();
    test_default_C_is_unbounded();
    test_assemble_is_digest_neutral();
    test_live_floor_arms();

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
