// V37 W5 coinbase assembly — standalone unit tests (src/c2pool/v37/w5_coinbase.hpp).
//
// Same tiny CHECK harness as v37_w4_settlement_test.cpp / v37_scaffold_test.cpp:
// no gtest, no core/Boost link; g++ -std=c++20 -pthread with an -I on src, a
// single translation unit that returns nonzero on any failure. W5 is the
// coinbase-assembly layer: given W4's OWED ledger at a found block it selects
// which miners are paid, in what amounts, and commits the §13 state root.
//
// The load-bearing assertion of this whole step is the SELECTION ORDER:
// OLDEST-OWED-FIRST (K_fair F1, (first_eligible_height ASC, key ASC)), NOT
// largest-first. That is whitepaper erratum E-1 — the public paper's §7.2
// "largest-first" is WRONG; test_e1_oldest_not_largest is the regression pin
// that fails the instant anyone re-introduces largest-first.
//
// Coverage:
//   • test_e1_oldest_not_largest  — mixed-age/mixed-amount ledger pays the
//        OLDEST first even though a younger balance owes more AND has a smaller
//        key (so neither amount nor key can be the thing driving the order);
//   • test_two_nodes_identical    — two independent ledgers, same event stream,
//        byte-identical output set (canonical selection = pure function);
//   • test_budget_cap_carry       — the fixed count budget C caps the outputs;
//        the deferred (younger) balances stay owed (ledger unmutated) and the
//        NEXT block, after the paid ones settle out, pays them;
//   • test_byte_budget_carry      — the fixed K_max byte budget stops assembly
//        in strict oldest-first order; the rest carry;
//   • test_dust_minimum           — a sub-h_min balance is never emitted as
//        dust; it accretes across blocks until it clears the floor as one
//        output; no worker excluded (deferred, not denied);
//   • test_buried_gate            — an unburied or orphaned block emits nothing;
//        only a block buried >= D_conf assembles a payout;
//   • test_state_root_proof       — the §13 state root committed in the coinbase
//        + an O(log n) balance inclusion proof verified by the SHIPPED static
//        ::v37::Lane::verify_proof; tamper cases rejected.

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
// A payout registry: canonical key -> ScriptRef (the identity-view pay_of).
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

// Credit `amount` to `key` and FINALIZE at bin_height (arms first_eligible).
static void credit_final(S::OwedLedger& L, const std::string& bid,
                         const bytes32& key, long long amount, u64 bin_height) {
    S::OwedLedger::Amounts credit{{key, amount}};
    L.on_block_found(bid, credit, {});
    L.on_block_finalized(bid, bin_height);
}

// ─────────────────────────────────────────────────────────────────────────
// E-1: OLDEST-OWED-FIRST, not largest-first. Two miners:
//   A: OLDER (first_eligible = 100), SMALL owed (5), LARGE key (0xF0…)
//   B: YOUNGER (first_eligible = 200), LARGE owed (50), SMALL key (0x10…)
// Largest-first would pay B first (50 > 5). Key-ascending would pay B first
// (0x10 < 0xF0). Only OLDEST-first pays A first. Assert A is output[0].
// ─────────────────────────────────────────────────────────────────────────
static void test_e1_oldest_not_largest() {
    bytes32 A = mkkey(0xF0), B = mkkey(0x10);
    g_reg.add(A, p2pkh(0xF0));
    g_reg.add(B, p2pkh(0x10));

    S::OwedLedger L(7);
    credit_final(L, "a", A, 5, /*bin_height=*/100);   // older, small, big key
    credit_final(L, "b", B, 50, /*bin_height=*/200);  // younger, large, small key

    CB::CoinbaseBudget bud;
    bud.slot_budget_C = 10;
    bud.max_payout_bytes = 0;   // unbounded for this test
    bud.k_floor = 0;            // no dust floor for this test
    auto cb = CB::assemble(L, /*block_reward=*/1000000, bud, pay_of);

    CHECK(cb.outputs.size() == 2);
    // THE PIN: oldest (A) is first, despite owing less and having the larger key.
    CHECK(cb.outputs[0].key == A);
    CHECK(cb.outputs[0].amount == 5);
    CHECK(cb.outputs[1].key == B);
    CHECK(cb.outputs[1].amount == 50);
    // Explicitly refute largest-first: had it been largest-first, output[0]
    // would owe MORE than output[1]; assert it owes LESS.
    CHECK(cb.outputs[0].amount < cb.outputs[1].amount);
    // And refute key-ascending: output[0].key is the LARGER key.
    CHECK(cb.outputs[1].key < cb.outputs[0].key);
}

// Two independent ledgers, identical event stream → byte-identical output set.
static void test_two_nodes_identical() {
    bytes32 A = mkkey(0x30), B = mkkey(0x31), C = mkkey(0x32);
    g_reg.add(A, p2pkh(0x30));
    g_reg.add(B, p2pkh(0x31));
    g_reg.add(C, p2pkh(0x32));

    auto build = [&]() {
        S::OwedLedger L(9);
        credit_final(L, "b1", B, 20, 300);   // note: fed out of age order
        credit_final(L, "a1", A, 7, 100);
        credit_final(L, "c1", C, 99, 200);
        return L;
    };
    S::OwedLedger n1 = build();
    S::OwedLedger n2 = build();

    CB::CoinbaseBudget bud;
    bud.slot_budget_C = 10;
    bud.k_floor = 0;
    auto cb1 = CB::assemble(n1, 1000000, bud, pay_of);
    auto cb2 = CB::assemble(n2, 1000000, bud, pay_of);

    CHECK(cb1.outputs.size() == 3);
    CHECK(cb1.outputs.size() == cb2.outputs.size());
    bool identical = true;
    for (std::size_t i = 0; i < cb1.outputs.size(); ++i) {
        if (!(cb1.outputs[i].key == cb2.outputs[i].key) ||
            cb1.outputs[i].amount != cb2.outputs[i].amount ||
            cb1.outputs[i].script != cb2.outputs[i].script)
            identical = false;
    }
    CHECK(identical);
    CHECK(cb1.state_root == cb2.state_root);
    // Canonical order is by age: A(100) < C(200) < B(300).
    CHECK(cb1.outputs[0].key == A);
    CHECK(cb1.outputs[1].key == C);
    CHECK(cb1.outputs[2].key == B);
}

// Fixed count budget C caps outputs; deferred balances stay owed and the NEXT
// block pays them once the paid ones settle out.
static void test_budget_cap_carry() {
    bytes32 A = mkkey(0x40), B = mkkey(0x41), C = mkkey(0x42), D = mkkey(0x43);
    for (auto k : {A, B, C, D}) g_reg.add(k, p2pkh(k[0]));

    S::OwedLedger L(11);
    credit_final(L, "a", A, 10, 100);   // oldest
    credit_final(L, "b", B, 10, 200);
    credit_final(L, "c", C, 10, 300);
    credit_final(L, "d", D, 10, 400);   // youngest

    CB::CoinbaseBudget bud;
    bud.slot_budget_C = 2;   // fixed budget: only two outputs per block
    bud.k_floor = 0;
    auto b1 = CB::assemble(L, 1000000, bud, pay_of);
    CHECK(b1.outputs.size() == 2);
    CHECK(b1.outputs[0].key == A);   // two oldest paid
    CHECK(b1.outputs[1].key == B);

    // Carry-forward: C and D are UNTOUCHED in the owed ledger.
    CHECK(L.effective_owed(C) == 10);
    CHECK(L.effective_owed(D) == 10);
    CHECK(L.effective_owed(A) == 10);   // not yet settled — assembly mutates nothing

    // Settle block b1 out (FOUND its payouts, FINALIZE) → A,B leave owed.
    S::OwedLedger::Amounts payout{{A, 10}, {B, 10}};
    L.on_block_found("blk1", {}, payout);
    L.on_block_finalized("blk1", 500);
    CHECK(L.effective_owed(A) == 0);
    CHECK(L.effective_owed(B) == 0);

    // NEXT block now pays the previously-carried C and D (still oldest).
    auto b2 = CB::assemble(L, 1000000, bud, pay_of);
    CHECK(b2.outputs.size() == 2);
    CHECK(b2.outputs[0].key == C);
    CHECK(b2.outputs[1].key == D);
}

// Fixed K_max byte budget stops assembly in strict oldest-first order.
static void test_byte_budget_carry() {
    bytes32 A = mkkey(0x50), B = mkkey(0x51), C = mkkey(0x52);
    for (auto k : {A, B, C}) g_reg.add(k, p2pkh(k[0]));

    S::OwedLedger L(13);
    credit_final(L, "a", A, 100, 100);
    credit_final(L, "b", B, 100, 200);
    credit_final(L, "c", C, 100, 300);

    // A P2PKH output serializes to output_size(P2PKH) = 8+1+25 = 34 bytes.
    CHECK(CB::output_size(ScriptKind::P2PKH) == 34);

    CB::CoinbaseBudget bud;
    bud.slot_budget_C = 10;
    bud.max_payout_bytes = 34;   // room for exactly ONE P2PKH output
    bud.k_floor = 0;
    auto cb = CB::assemble(L, 1000000, bud, pay_of);
    CHECK(cb.outputs.size() == 1);
    CHECK(cb.outputs[0].key == A);         // the oldest — strict priority
    CHECK(cb.payout_bytes == 34);
    CHECK(cb.carried == 2);                // B and C carried by the byte budget
    // Owed unchanged for the carried balances.
    CHECK(L.effective_owed(B) == 100);
    CHECK(L.effective_owed(C) == 100);
}

// A sub-h_min balance is never emitted as dust; it accretes until it clears the
// floor, then pays as one output. No worker excluded (deferred, not denied).
static void test_dust_minimum() {
    bytes32 X = mkkey(0x60), Y = mkkey(0x61);
    g_reg.add(X, p2pkh(0x60));
    g_reg.add(Y, p2pkh(0x61));

    // k_floor = 1 → h_min(P2PKH) = 1 * 34 = 34.
    CHECK(CB::h_min(ScriptKind::P2PKH, 1) == 34);

    S::OwedLedger L(17);
    credit_final(L, "x", X, 10, 100);    // 10 < 34 → sub-floor (dust)
    credit_final(L, "y", Y, 100, 200);   // 100 >= 34 → payable

    CB::CoinbaseBudget bud;
    bud.slot_budget_C = 10;
    bud.k_floor = 1;   // real byte floor
    auto cb = CB::assemble(L, 1000000, bud, pay_of);

    // X below the floor is NOT emitted (no dust) and NOT dropped (still owed).
    bool x_paid = false;
    for (const auto& o : cb.outputs) if (o.key == X) x_paid = true;
    CHECK(!x_paid);
    CHECK(L.effective_owed(X) == 10);        // carried, not forfeited
    // Y above the floor is paid.
    CHECK(cb.outputs.size() == 1);
    CHECK(cb.outputs[0].key == Y);
    // Every emitted amount is >= h_min (never dust).
    for (const auto& o : cb.outputs)
        CHECK(o.amount >= CB::h_min(o.pay.kind, bud.k_floor));

    // Accretion: X keeps earning until it clears the floor, then emits as ONE
    // output. Credit X another 30 (total 40 >= 34).
    credit_final(L, "x2", X, 30, 300);
    CHECK(L.effective_owed(X) == 40);
    auto cb2 = CB::assemble(L, 1000000, bud, pay_of);
    bool x_paid2 = false;
    u64 x_amt = 0;
    for (const auto& o : cb2.outputs)
        if (o.key == X) { x_paid2 = true; x_amt = o.amount; }
    CHECK(x_paid2);
    CHECK(x_amt == 40);   // the accreted balance as a single output, not dust
}

// The buried gate: unburied or orphaned emits NOTHING; buried >= D_conf pays.
static void test_buried_gate() {
    bytes32 A = mkkey(0x70);
    g_reg.add(A, p2pkh(0x70));
    S::OwedLedger L(19);
    credit_final(L, "a", A, 100, 100);

    CB::CoinbaseBudget bud;
    bud.slot_budget_C = 10;
    bud.k_floor = 0;

    // Unburied (confirmations 3 < D_conf 6): emit nothing.
    CB::BurialGate g_unburied{/*d_conf=*/6, /*canonical=*/true, /*confirmations=*/3};
    auto cb_u = CB::assemble_if_buried(L, 1000000, bud, g_unburied, pay_of);
    CHECK(!cb_u.emitted);
    CHECK(cb_u.outputs.empty());

    // Orphaned (canonical=false) even at depth: emit nothing.
    CB::BurialGate g_orphan{6, /*canonical=*/false, /*confirmations=*/100};
    auto cb_o = CB::assemble_if_buried(L, 1000000, bud, g_orphan, pay_of);
    CHECK(!cb_o.emitted);
    CHECK(cb_o.outputs.empty());

    // Buried (confirmations 6 >= D_conf 6, canonical): assemble the payout.
    CB::BurialGate g_buried{6, /*canonical=*/true, /*confirmations=*/6};
    auto cb_b = CB::assemble_if_buried(L, 1000000, bud, g_buried, pay_of);
    CHECK(cb_b.emitted);
    CHECK(cb_b.outputs.size() == 1);
    CHECK(cb_b.outputs[0].key == A);
}

// §13: the state root committed in the coinbase + an O(log n) balance proof
// verified by the SHIPPED static ::v37::Lane::verify_proof.
static void test_state_root_proof() {
    S::OwedLedger L(23);
    std::vector<bytes32> keys;
    for (std::uint8_t f = 1; f <= 9; ++f) {
        bytes32 k = mkkey(0x80 + f);
        keys.push_back(k);
        g_reg.add(k, p2pkh(0x80 + f));
        credit_final(L, std::string("blk") + char('0' + f), k, 10 + f, 100 + f);
    }

    CB::StateCommitment sc(L, L.chain());
    bytes32 root = sc.root();

    // The assembled coinbase commits the SAME root (§13 root-in-coinbase).
    CB::CoinbaseBudget bud;
    bud.slot_budget_C = 100;
    bud.k_floor = 0;
    auto cb = CB::assemble(L, 100000000, bud, pay_of);
    CHECK(cb.state_root == root);

    // A headers-only device verifies each balance with an O(log n) proof.
    std::size_t leaves = sc.leaf_count();   // 1 summary + 9 balances = 10
    CHECK(leaves == 10);
    for (const auto& k : keys) {
        bytes32 leaf{};
        ::v37::Lane::MerkleProof proof;
        bool ok = sc.prove(k, leaf, proof);
        CHECK(ok);
        // O(log n): the sibling path is <= ceil(log2(leaf_count)) long.
        CHECK(proof.path.size() <= 4);   // ceil(log2(10)) == 4
        // The SHIPPED stateless verifier accepts the proof against the root.
        CHECK(::v37::Lane::verify_proof(root, leaf, proof));

        // Tamper cases MUST be rejected.
        bytes32 bad_root = root;
        bad_root[0] ^= 0xff;
        CHECK(!::v37::Lane::verify_proof(bad_root, leaf, proof));
        bytes32 bad_leaf = leaf;
        bad_leaf[0] ^= 0xff;
        CHECK(!::v37::Lane::verify_proof(root, bad_leaf, proof));
    }

    // A key with no positive balance has no proof.
    bytes32 absent = mkkey(0x01);
    bytes32 leaf{};
    ::v37::Lane::MerkleProof proof;
    CHECK(!sc.prove(absent, leaf, proof));
}

int main() {
    test_e1_oldest_not_largest();
    test_two_nodes_identical();
    test_budget_cap_carry();
    test_byte_budget_carry();
    test_dust_minimum();
    test_buried_gate();
    test_state_root_proof();

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
