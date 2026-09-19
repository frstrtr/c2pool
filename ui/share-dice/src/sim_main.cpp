// share-dice play-money simulator (CLI). PLAY-MONEY / STANDALONE only.
//
// The SatoshiDice-sim analog, but using the real provably-fair commit-reveal
// (design section 3.1) instead of random.randint. NOTHING here settles real
// value; the "balance" is play-money credit in a local overlay. It does not
// touch PPLNS, the donation pot, coinbase, or any consensus surface.
//
// Usage:
//   share-dice-sim [--house N] [--balance N] [--seed HEX] [--client STR]
//                  [--miner STR] [--rounds K] [--tier T] [--bet N]
// All flags optional; defaults give a short deterministic demo that also
// prints, for every bet, the data an outside party needs to independently
// verify the roll (design section 4).

#include "share_dice/engine.hpp"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

using namespace share_dice;

namespace {
const char* arg_str(int argc, char** argv, const char* key, const char* dflt) {
    for (int i = 1; i + 1 < argc; ++i)
        if (std::strcmp(argv[i], key) == 0) return argv[i + 1];
    return dflt;
}
long long arg_ll(int argc, char** argv, const char* key, long long dflt) {
    const char* v = arg_str(argc, argv, key, nullptr);
    return v ? std::atoll(v) : dflt;
}
const char* outcome_str(Outcome o) { return o == Outcome::Win ? "WIN " : "LOSE"; }
}  // namespace

int main(int argc, char** argv) {
    int64_t house = arg_ll(argc, argv, "--house", 100000000);   // play-money pot
    int64_t balance = arg_ll(argc, argv, "--balance", 1000000); // player's play credit
    std::string terminal_seed =
        arg_str(argc, argv, "--seed",
                "f00dbabe00000000000000000000000000000000000000000000000000000001");
    std::string client_seed = arg_str(argc, argv, "--client", "player-entropy-001");
    std::string miner = arg_str(argc, argv, "--miner", "miner-A");
    int rounds = static_cast<int>(arg_ll(argc, argv, "--rounds", 5));
    int tier = static_cast<int>(arg_ll(argc, argv, "--tier", 6));  // 2x tier
    int64_t bet = arg_ll(argc, argv, "--bet", 1000);

    if (tier < 0 || tier >= kNumTiers) {
        std::cerr << "tier must be in [0," << (kNumTiers - 1) << "]\n";
        return 2;
    }

    std::cout << "== share-dice PLAY-MONEY simulator (no real value) ==\n";
    std::cout << "house pot     : " << house << " (play)\n";
    std::cout << "player credit : " << balance << " (play)\n";
    std::cout << "tier          : " << tier << "  multiplier x100 = "
              << kMultiplierX100[tier] << "  win iff roll <= "
              << kWinningThresholds[tier] << "\n";
    std::cout << "max_bet(tier) : " << max_bet(tier, house) << "\n\n";

    // Build the server-seed hash chain and publish the head (design section 3.1).
    std::vector<std::string> chain = build_seed_chain(terminal_seed, rounds);
    std::cout << "published head commitment S_0 = " << chain[0] << "\n";
    std::cout << "(seeds S_1..S_" << rounds
              << " revealed one per round; SHA256(S_i) == S_{i-1})\n\n";

    DiceEngine engine(house);
    engine.credit_miner(miner, balance);

    for (int i = 1; i <= rounds && engine.credit_of(miner) >= bet; ++i) {
        // Round i is committed to S_{i-1} (already public); S_i is revealed after.
        engine.open_round(chain[i - 1], static_cast<uint64_t>(i));
        std::string bet_id = make_bet_id(client_seed, miner, i, /*seq=*/0);
        engine.place_bet(miner, tier, bet, bet_id);

        std::vector<BetSettlement> settled = engine.reveal(chain[i]);
        const BetSettlement& s = settled.front();

        std::cout << "round " << i << "  commit(S_" << (i - 1) << ")=" << chain[i - 1]
                  << "\n          reveal(S_" << i << ")=" << chain[i]
                  << "\n          bet_id=" << bet_id
                  << "\n          roll=" << s.roll << "  " << outcome_str(s.outcome)
                  << "  payout=" << s.payout << "  house_delta=" << s.house_delta
                  << "\n          credit=" << engine.credit_of(miner)
                  << "  house=" << engine.house_balance();

        VerifyResult v = verify(chain[i - 1], chain[i], bet_id, tier, s.roll, s.outcome);
        std::cout << "  [verify " << (v.ok ? "OK" : "FAIL") << "]\n\n";
    }

    std::cout << "final player credit : " << engine.credit_of(miner) << " (play)\n";
    std::cout << "final house pot      : " << engine.house_balance() << " (play)\n";
    std::cout << "\nNOTE: play-money only. No PPLNS / donation / coinbase / consensus "
                 "was touched; no real value was settled.\n";
    return 0;
}
