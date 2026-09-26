// share-dice: provably-fair commit-reveal engine + verifier + play-money overlay.
//
// STANDALONE / DEFAULT-OFF / PLAY-MONEY ONLY.
//
// This module is a self-contained tool. It does NOT compile into the c2pool
// pool node, and it deliberately touches NONE of the money path: no PPLNS
// accounting (src/impl/**/pplns*), no donation script (src/core/donation.hpp),
// no coinbase construction, no share validation, and no consensus surface.
//
// It implements only the SAFE, decision-independent fairness primitive from
// docs/design/share-dice.md (design/share-dice, PR #1630): the provably-fair
// commit-reveal roll (design section 3.1), the SatoshiDice game table
// (section 1.1, grounded in frstrtr/satoshidice main.py), the standalone
// verifier (section 4), and the solvency/bounds math (section 3.3) exercised
// against a PLAY-MONEY overlay ledger only.
//
// The real-pot hook (reading a miner's pending PPLNS credit as the bet ceiling,
// and settling net winnings from the operator-controlled donation pot, design
// section 3.2 option A) is intentionally UNWIRED. See the clearly-named seam
// `RealPotBinding` at the bottom of this header. Nothing here connects it.

#ifndef SHARE_DICE_ENGINE_HPP
#define SHARE_DICE_ENGINE_HPP

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace share_dice {

// ---------------------------------------------------------------------------
// Game table (design section 1.1, verbatim from frstrtr/satoshidice main.py).
// A roll is an integer in [0, 65535]; total_outcomes = 65536.
// A bet WINS iff roll <= winning_thresholds[tier].
// ---------------------------------------------------------------------------
inline constexpr int kNumTiers = 11;
inline constexpr uint32_t kTotalOutcomes = 65536;

// winning_thresholds = [65,649,1289,2596,6488,21627,32440,43253,48103,58982,61790]
extern const uint32_t kWinningThresholds[kNumTiers];

// multipliers = [1000,100,50,25,10,3,2,1.5,1.33,1.1,1.05]
// Stored scaled by 100 for exact integer-satoshi math (design section 3.3
// mandates integer-satoshi math with banker-safe rounding). No floating point
// touches any settlement number.
extern const int64_t kMultiplierX100[kNumTiers];

// Domain-separation prefix for the roll (design section 3.1).
inline constexpr const char* kRollDomain = "c2pool-share-dice/v1";

// ---------------------------------------------------------------------------
// SHA-256 helpers. These wrap c2pool's vendored CSHA256
// (src/btclibs/crypto/sha256) - SHA is never hand-rolled here.
// ---------------------------------------------------------------------------
std::vector<uint8_t> sha256_raw(const uint8_t* data, size_t len);
std::vector<uint8_t> sha256_raw(const std::string& data);      // over the string's bytes
std::string sha256_hex(const std::string& data);               // hex(SHA256(bytes))
std::string hex_encode(const std::vector<uint8_t>& bytes);
std::vector<uint8_t> hex_decode(const std::string& hex);        // throws std::invalid_argument on bad hex

// ---------------------------------------------------------------------------
// Provably-fair primitives (design section 3.1 + reference verifier section 4).
// ---------------------------------------------------------------------------

// Server-seed hash chain: S_{i-1} = SHA256(S_i), hashing the seed's RAW bytes.
// Given a terminal seed S_N (hex of 32 bytes), returns the chain
// [S_0, S_1, ..., S_N] as hex strings, so chain[i] == S_i and the published
// head is chain[0]. (Design section 3.1: "S_{i-1} = SHA256(S_i)".)
std::vector<std::string> build_seed_chain(const std::string& terminal_seed_hex, int n);

// Verify a reveal against the previously published commitment:
//   SHA256(raw(seed_i)) hex == commit_prev_hex   (== S_{i-1}).
// (Reference verifier check_chain, design section 4.)
bool verify_chain_link(const std::string& commit_prev_hex, const std::string& seed_i_hex);

// bet_id = SHA256("{client_seed}|{miner_id}|{round_index}|{per_round_seq}") hex.
// (Design section 3.1 line: bet_id = SHA256(client_seed || miner_id ||
// round_index || per_round_seq); reference verifier pins the "|"-joined
// decimal encoding.) The share hash is deliberately NOT an input.
std::string make_bet_id(const std::string& client_seed,
                        const std::string& miner_id,
                        uint64_t round_index,
                        uint64_t per_round_seq);

// roll = int(SHA256("c2pool-share-dice/v1" || S_i_hex || ":" || bet_id_hex)[0:4], big) % 65536.
// S_i_hex and bet_id_hex are the ASCII hex strings (design section 3.1 / section 4
// reference: S_i_hex.encode(), bet_id_hex.encode()). The share hash is NOT an
// input, which closes the pool-specific grinding vector (design section 3.1).
uint32_t compute_roll(const std::string& seed_i_hex, const std::string& bet_id_hex);

// ---------------------------------------------------------------------------
// Outcome & settlement math (design section 3.3). Pure functions, satoshi ints.
// ---------------------------------------------------------------------------
enum class Outcome { Lose = 0, Win = 1 };

// win iff roll <= winning_thresholds[tier].
Outcome outcome_for_roll(int tier, uint32_t roll);

// Net winnings the house pays a winner: round((mult - 1) * amount), banker's
// (round-half-to-even) rounding on the /100 scale.
int64_t net_house_payout(int tier, int64_t amount);

// Total credited back to a winner: stake returned + net winnings == mult*amount
// (exact for integer multipliers). Conserves value with net_house_payout.
int64_t payout_on_win(int tier, int64_t amount);

// Solvency cap (design section 3.3 invariant 2):
//   max_bet(tier, house_balance) = floor(house_balance / (mult - 1)).
// Guarantees the maximum possible payout is fully covered by the current pot.
int64_t max_bet(int tier, int64_t house_balance);

// ---------------------------------------------------------------------------
// Standalone verifier (design section 4). Anyone can re-run this on a past bet
// using only public data. Depends only on SHA-256.
// ---------------------------------------------------------------------------
struct VerifyResult {
    bool commitment_ok = false;  // SHA256(raw(seed_i)) == commitment
    bool roll_ok = false;        // recomputed roll == claimed_roll
    bool outcome_ok = false;     // recomputed win/lose == claimed_outcome
    bool ok = false;             // all three
    uint32_t roll = 0;           // recomputed roll
};

VerifyResult verify(const std::string& commitment_hex,
                    const std::string& seed_i_hex,
                    const std::string& bet_id_hex,
                    int tier,
                    uint32_t claimed_roll,
                    Outcome claimed_outcome);

// ---------------------------------------------------------------------------
// Play-money overlay engine. A pool-local ledger analog of design section 3.2,
// but seeded with PLAY-MONEY only. It never reads real PPLNS credit and never
// settles into a real pot (see RealPotBinding seam below).
// ---------------------------------------------------------------------------
struct BetRecord {
    std::string miner_id;
    int tier = 0;
    int64_t amount = 0;
    std::string bet_id;
    uint64_t per_round_seq = 0;
};

struct BetSettlement {
    std::string miner_id;
    std::string bet_id;
    int tier = 0;
    int64_t amount = 0;
    uint32_t roll = 0;
    Outcome outcome = Outcome::Lose;
    int64_t payout = 0;          // credited back to miner (0 on lose)
    int64_t house_delta = 0;     // change to house_balance for this bet
};

class DiceEngine {
public:
    explicit DiceEngine(int64_t house_balance = 0);

    // Play-money account management (NOT a real ledger).
    void fund_house(int64_t amount);
    void credit_miner(const std::string& miner_id, int64_t amount);
    int64_t house_balance() const { return house_balance_; }
    int64_t credit_of(const std::string& miner_id) const;

    // Round lifecycle. `commitment_hex` is S_{i-1}, published before any bet.
    void open_round(const std::string& commitment_hex, uint64_t round_index);
    bool round_open() const { return round_open_; }
    const std::string& round_commitment() const { return round_commitment_; }

    // place_bet(tier, amount, bet_id) records a commitment for `miner_id`.
    // Rejects (throws std::invalid_argument): amount <= 0, amount > miner credit,
    // or amount > max_bet(tier, house_balance) (solvency, design section 3.3).
    // Escrows the stake by debiting miner credit at accept time.
    // Returns the per-round sequence number assigned to the bet.
    uint64_t place_bet(const std::string& miner_id, int tier, int64_t amount,
                       const std::string& bet_id);

    // reveal(seed_i): verifies SHA256(raw(seed_i)) == round commitment, computes
    // the roll for every bet in published sequence order, and settles each into
    // the play-money overlay. Throws std::runtime_error if the reveal does not
    // match the commitment (all stakes remain escrowed; caller may void round).
    std::vector<BetSettlement> reveal(const std::string& seed_i_hex);

    const std::vector<BetRecord>& bets() const { return bets_; }

private:
    int64_t house_balance_;
    std::map<std::string, int64_t> credit_;
    std::string round_commitment_;
    uint64_t round_index_ = 0;
    bool round_open_ = false;
    uint64_t next_seq_ = 0;
    std::vector<BetRecord> bets_;
};

// ---------------------------------------------------------------------------
// UNWIRED SEAM - do not connect without operator legal + settlement sign-off.
//
// In production (design section 3.2 option A) the bet ceiling would be a
// miner's pending PPLNS credit (read-only, from src/impl/dash/dashboard_pplns),
// and net winnings would be settled from the operator-controlled donation pot
// (src/core/donation.hpp). Both are money-path/consensus-adjacent and are the
// operator-gated part of the feature. This interface is declared but NOT
// implemented and NOT called anywhere. Wiring it is a separate, reviewed,
// default-OFF, operator-armed change - never done by this slice.
// ---------------------------------------------------------------------------
struct RealPotBinding {
    // int64_t pending_pplns_credit(const std::string& miner_id) const; // UNWIRED
    // int64_t donation_pot_balance() const;                            // UNWIRED
    // void settle_winnings(const std::string& miner_id, int64_t sats); // UNWIRED
};

}  // namespace share_dice

#endif  // SHARE_DICE_ENGINE_HPP
