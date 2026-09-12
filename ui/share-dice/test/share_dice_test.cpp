// share-dice KATs. Deterministic vectors only - no RNG anywhere in the tests.
//
// Exercises the SAFE, play-money core: the provably-fair commit-reveal roll,
// the standalone verifier, the 11-tier SatoshiDice table, grinding-resistance,
// and the solvency-cap math. Touches no PPLNS/donation/coinbase/consensus code.
//
// Returns 0 iff every KAT passes (ctest reads the exit code).

#include "share_dice/engine.hpp"

#include <cstdint>
#include <cstdio>
#include <functional>
#include <stdexcept>
#include <string>

using namespace share_dice;

namespace {

int g_fail = 0;
int g_checks = 0;

void check(bool cond, const char* what) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        std::printf("    FAIL: %s\n", what);
    }
}

bool throws_invalid(const std::function<void()>& fn) {
    try {
        fn();
    } catch (const std::exception&) {
        return true;
    }
    return false;
}

// Fixed KAT vectors (computed once from the construction, then frozen here).
// terminal/revealed seed S_1 (32 bytes) and its self-authenticating commitment
// S_0 = SHA256(raw(S_1)); a fixed bet_id; and the roll they must always yield.
const std::string S1 =
    "1122334455667788990011223344556677889900112233445566778899001122";
const std::string S0 =
    "ff81cbb6c0299fd36e97e78a774e859e9e3528b6f2ac50c1a430d2e726e80e1e";
const std::string BET_ID =
    "6d07d32050be6d3890be4255447212b18bddd1fd193f12b8918921d67177bf18";
const uint32_t ROLL = 55234;  // 55234 > 32440 (tier 6) but <= 58982 (tier 9)

// KAT (a): commit-reveal correctness - a fixed seed + bet_id yields a fixed
// roll, the chain link authenticates, and the standalone verifier accepts.
void kat_a_commit_reveal_correctness() {
    std::printf("KAT (a) commit-reveal correctness\n");
    // bet_id reproduces exactly from its public inputs.
    check(make_bet_id("kat-client-seed", "kat-miner", 1, 0) == BET_ID,
          "make_bet_id matches frozen vector");
    // chain link: SHA256(raw(S_1)) == S_0.
    check(verify_chain_link(S0, S1), "verify_chain_link(S0, S1) true");
    // fixed roll.
    check(compute_roll(S1, BET_ID) == ROLL, "compute_roll matches frozen roll 55234");
    // build_seed_chain reproduces the same S_0/S_1 pair.
    auto chain = build_seed_chain(S1, 1);
    check(chain.size() == 2 && chain[0] == S0 && chain[1] == S1,
          "build_seed_chain reproduces (S0,S1)");
    // verifier accepts a correct LOSE (tier 6) and a correct WIN (tier 9).
    VerifyResult lose = verify(S0, S1, BET_ID, 6, ROLL, Outcome::Lose);
    check(lose.ok && lose.commitment_ok && lose.roll_ok && lose.outcome_ok,
          "verify accepts correct tier-6 LOSE");
    VerifyResult win = verify(S0, S1, BET_ID, 9, ROLL, Outcome::Win);
    check(win.ok, "verify accepts correct tier-9 WIN");
}

// KAT (b): tamper detection - a wrong revealed seed fails the commitment check,
// both at the primitive and through the engine's reveal path.
void kat_b_tamper_detection() {
    std::printf("KAT (b) tamper detection (wrong revealed seed)\n");
    std::string tampered =
        "1122334455667788990011223344556677889900112233445566778899001123";  // last byte 22->23
    check(!verify_chain_link(S0, tampered),
          "verify_chain_link rejects tampered seed");
    check(compute_roll(tampered, BET_ID) != ROLL,
          "tampered seed produces a different roll");
    // engine: an open round committed to S_0 must reject a reveal != S_1.
    DiceEngine eng(1000000);
    eng.credit_miner("m", 1000);
    eng.open_round(S0, 1);
    eng.place_bet("m", 6, 100, BET_ID);
    check(throws_invalid([&] { eng.reveal(tampered); }),
          "engine.reveal rejects a seed not matching the commitment");
}

// KAT (c): a mismatched-commitment reveal is rejected by the verifier.
void kat_c_mismatched_commitment() {
    std::printf("KAT (c) mismatched-commitment reveal rejected\n");
    std::string bogus_commit =
        "0000000000000000000000000000000000000000000000000000000000000000";
    VerifyResult r = verify(bogus_commit, S1, BET_ID, 6, ROLL, Outcome::Lose);
    check(!r.commitment_ok, "commitment_ok is false for a bogus commitment");
    check(!r.ok, "verify overall rejects a mismatched commitment");
    // roll itself still recomputes correctly - only the commitment binding fails.
    check(r.roll == ROLL, "roll still recomputes even when commitment mismatches");
}

// KAT (d): the 11-tier win/lose boundary. roll == threshold WINS,
// threshold+1 LOSES, for every tier. Plus the extremes (0 wins, 65535 loses).
void kat_d_tier_boundaries() {
    std::printf("KAT (d) 11-tier win/lose boundary\n");
    for (int t = 0; t < kNumTiers; ++t) {
        uint32_t thr = kWinningThresholds[t];
        check(outcome_for_roll(t, thr) == Outcome::Win,
              "roll == threshold WINS");
        check(outcome_for_roll(t, thr + 1) == Outcome::Lose,
              "roll == threshold+1 LOSES");
        check(outcome_for_roll(t, 0) == Outcome::Win, "roll 0 always WINS");
        check(outcome_for_roll(t, kTotalOutcomes - 1) == Outcome::Lose,
              "roll 65535 always LOSES (no threshold reaches it)");
    }
}

// KAT (e): grinding-resistance property - the roll is INDEPENDENT of any share
// hash. There is no share input to bet_id or to the roll, so a miner producing
// arbitrarily many share hashes cannot move the outcome. Deterministic sweep.
void kat_e_grinding_resistance() {
    std::printf("KAT (e) grinding-resistance (roll independent of any share hash)\n");
    bool bet_id_stable = true;
    bool roll_stable = true;
    for (int k = 0; k < 4096; ++k) {
        // A candidate share hash a grinding miner might produce; it is NOT an
        // input to either construction, so neither value may change.
        std::string fake_share = sha256_hex("share-candidate-" + std::to_string(k));
        (void)fake_share;
        std::string bid = make_bet_id("kat-client-seed", "kat-miner", 1, 0);
        if (bid != BET_ID) bet_id_stable = false;
        if (compute_roll(S1, bid) != ROLL) roll_stable = false;
    }
    check(bet_id_stable, "bet_id is invariant across 4096 candidate share hashes");
    check(roll_stable, "roll is invariant across 4096 candidate share hashes");
}

// KAT (f): solvency-cap math and accept-time rejections.
void kat_f_solvency_cap() {
    std::printf("KAT (f) solvency cap math + accept-time rejection\n");
    // max_bet(tier, house) = floor(house / (mult - 1)).
    check(max_bet(6, 100000000) == 100000000, "max_bet tier6 (2x): house/1");
    check(max_bet(0, 999000) == 1000, "max_bet tier0 (1000x): house/999");
    check(max_bet(7, 1000) == 2000, "max_bet tier7 (1.5x): house*2");   // /0.5
    check(max_bet(0, 999) == 1, "max_bet tier0 floors 999/999 = 1");
    check(max_bet(0, 998) == 0, "max_bet tier0 floors 998/999 = 0");

    // Engine accept-time enforcement, tier 0 (1000x). house/999 = 100.
    DiceEngine eng(99900);
    eng.credit_miner("m", 100000);
    eng.open_round(S0, 1);
    check(max_bet(0, 99900) == 100, "max_bet(tier0, 99900) == 100");
    check(throws_invalid([&] { eng.place_bet("m", 0, 0, BET_ID); }),
          "reject bet amount == 0");
    check(throws_invalid([&] { eng.place_bet("m", 0, -5, BET_ID); }),
          "reject negative bet amount");
    check(throws_invalid([&] { eng.place_bet("m", 0, 101, BET_ID); }),
          "reject bet > max_bet (solvency cap)");
    // Exactly max_bet is accepted.
    bool ok = true;
    try {
        eng.place_bet("m", 0, 100, BET_ID);
    } catch (...) {
        ok = false;
    }
    check(ok, "accept bet == max_bet");

    // A miner cannot stake more than accrued credit.
    DiceEngine eng2(1000000000);  // huge pot, so the cap here is credit, not solvency
    eng2.credit_miner("poor", 50);
    eng2.open_round(S0, 1);
    check(throws_invalid([&] { eng2.place_bet("poor", 6, 51, BET_ID); }),
          "reject bet > miner credit");
}

// Extra: end-to-end play-money settlement conserves value and honors the log.
void kat_g_overlay_conservation() {
    std::printf("KAT (+) play-money overlay settlement conserves value\n");
    DiceEngine eng(1000000);
    eng.credit_miner("m", 10000);
    int64_t total_before = eng.house_balance() + eng.credit_of("m");
    eng.open_round(S0, 1);
    std::string bid = make_bet_id("kat-client-seed", "kat-miner", 1, 0);
    eng.place_bet("m", 9, 1000, bid);  // tier 9 (1.33x) - this vector WINS at tier 9
    auto settled = eng.reveal(S1);
    check(settled.size() == 1, "one settlement produced");
    check(settled[0].roll == ROLL, "settled roll matches frozen roll");
    check(settled[0].outcome == Outcome::Win, "tier-9 bet wins on this vector");
    int64_t total_after = eng.house_balance() + eng.credit_of("m");
    check(total_before == total_after, "house + credit conserved across settlement");
    // verifier agrees with the engine's published settlement.
    VerifyResult v = verify(S0, S1, bid, 9, settled[0].roll, settled[0].outcome);
    check(v.ok, "verifier agrees with engine settlement");
}

}  // namespace

int main() {
    std::printf("== share-dice KATs ==\n");
    kat_a_commit_reveal_correctness();
    kat_b_tamper_detection();
    kat_c_mismatched_commitment();
    kat_d_tier_boundaries();
    kat_e_grinding_resistance();
    kat_f_solvency_cap();
    kat_g_overlay_conservation();
    std::printf("\n%d checks, %d failures\n", g_checks, g_fail);
    if (g_fail == 0) std::printf("ALL KATS PASS\n");
    return g_fail == 0 ? 0 : 1;
}
