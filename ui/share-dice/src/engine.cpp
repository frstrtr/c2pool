// share-dice provably-fair engine implementation. PLAY-MONEY / STANDALONE only.
// See include/share_dice/engine.hpp for the full standalone/default-OFF notice.
// SHA-256 is reused from c2pool's vendored CSHA256; it is never hand-rolled.

#include "share_dice/engine.hpp"

#include <btclibs/crypto/sha256.h>

#include <cstdio>
#include <stdexcept>

namespace share_dice {

const uint32_t kWinningThresholds[kNumTiers] = {
    65, 649, 1289, 2596, 6488, 21627, 32440, 43253, 48103, 58982, 61790};

// multipliers = [1000,100,50,25,10,3,2,1.5,1.33,1.1,1.05] scaled by 100.
const int64_t kMultiplierX100[kNumTiers] = {
    100000, 10000, 5000, 2500, 1000, 300, 200, 150, 133, 110, 105};

namespace {

void require_tier(int tier) {
    if (tier < 0 || tier >= kNumTiers)
        throw std::invalid_argument("share_dice: tier out of range [0,10]");
}

// Round-half-to-even division of a non-negative numerator by a positive scale.
// (Banker-safe rounding, design section 3.3.)
int64_t round_half_even(int64_t numer, int64_t scale) {
    int64_t q = numer / scale;
    int64_t r = numer % scale;
    int64_t twice = 2 * r;
    if (twice < scale) return q;
    if (twice > scale) return q + 1;
    return (q % 2 == 0) ? q : q + 1;  // exact tie -> nearest even
}

}  // namespace

std::vector<uint8_t> sha256_raw(const uint8_t* data, size_t len) {
    unsigned char out[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(data, len).Finalize(out);
    return std::vector<uint8_t>(out, out + CSHA256::OUTPUT_SIZE);
}

std::vector<uint8_t> sha256_raw(const std::string& data) {
    return sha256_raw(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::string hex_encode(const std::vector<uint8_t>& bytes) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        s.push_back(d[b >> 4]);
        s.push_back(d[b & 0x0f]);
    }
    return s;
}

std::string sha256_hex(const std::string& data) { return hex_encode(sha256_raw(data)); }

std::vector<uint8_t> hex_decode(const std::string& hex) {
    if (hex.size() % 2 != 0)
        throw std::invalid_argument("share_dice: hex length must be even");
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0)
            throw std::invalid_argument("share_dice: invalid hex digit");
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::vector<std::string> build_seed_chain(const std::string& terminal_seed_hex, int n) {
    if (n < 0) throw std::invalid_argument("share_dice: chain length must be >= 0");
    std::vector<std::string> chain(static_cast<size_t>(n) + 1);
    chain[n] = terminal_seed_hex;  // S_N = terminal seed
    for (int i = n; i >= 1; --i) {
        // S_{i-1} = SHA256(raw bytes of S_i)
        std::vector<uint8_t> raw = hex_decode(chain[i]);
        chain[i - 1] = hex_encode(sha256_raw(raw.data(), raw.size()));
    }
    return chain;
}

bool verify_chain_link(const std::string& commit_prev_hex, const std::string& seed_i_hex) {
    std::vector<uint8_t> raw = hex_decode(seed_i_hex);
    return hex_encode(sha256_raw(raw.data(), raw.size())) == commit_prev_hex;
}

std::string make_bet_id(const std::string& client_seed,
                        const std::string& miner_id,
                        uint64_t round_index,
                        uint64_t per_round_seq) {
    std::string pre = client_seed + "|" + miner_id + "|" +
                      std::to_string(round_index) + "|" +
                      std::to_string(per_round_seq);
    return sha256_hex(pre);
}

uint32_t compute_roll(const std::string& seed_i_hex, const std::string& bet_id_hex) {
    // SHA256("c2pool-share-dice/v1" || S_i_hex || ":" || bet_id_hex), ASCII hex.
    std::string pre = std::string(kRollDomain) + seed_i_hex + ":" + bet_id_hex;
    std::vector<uint8_t> h = sha256_raw(pre);
    uint32_t v = (static_cast<uint32_t>(h[0]) << 24) |
                 (static_cast<uint32_t>(h[1]) << 16) |
                 (static_cast<uint32_t>(h[2]) << 8) |
                 (static_cast<uint32_t>(h[3]));
    return v % kTotalOutcomes;
}

Outcome outcome_for_roll(int tier, uint32_t roll) {
    require_tier(tier);
    return (roll <= kWinningThresholds[tier]) ? Outcome::Win : Outcome::Lose;
}

int64_t net_house_payout(int tier, int64_t amount) {
    require_tier(tier);
    if (amount < 0) throw std::invalid_argument("share_dice: negative amount");
    // round((mult - 1) * amount) = round((multX100 - 100) * amount / 100)
    return round_half_even((kMultiplierX100[tier] - 100) * amount, 100);
}

int64_t payout_on_win(int tier, int64_t amount) {
    // stake returned + net winnings (== mult*amount for integer multipliers)
    return amount + net_house_payout(tier, amount);
}

int64_t max_bet(int tier, int64_t house_balance) {
    require_tier(tier);
    if (house_balance < 0) throw std::invalid_argument("share_dice: negative pot");
    // floor(house_balance / (mult - 1)) = floor(house_balance * 100 / (multX100 - 100))
    int64_t denom = kMultiplierX100[tier] - 100;  // > 0 for all tiers
    return (house_balance * 100) / denom;
}

VerifyResult verify(const std::string& commitment_hex,
                    const std::string& seed_i_hex,
                    const std::string& bet_id_hex,
                    int tier,
                    uint32_t claimed_roll,
                    Outcome claimed_outcome) {
    require_tier(tier);
    VerifyResult r;
    r.commitment_ok = verify_chain_link(commitment_hex, seed_i_hex);
    r.roll = compute_roll(seed_i_hex, bet_id_hex);
    r.roll_ok = (r.roll == claimed_roll);
    Outcome recomputed = outcome_for_roll(tier, r.roll);
    r.outcome_ok = (recomputed == claimed_outcome);
    r.ok = r.commitment_ok && r.roll_ok && r.outcome_ok;
    return r;
}

// ---------------------------------------------------------------------------
// DiceEngine (play-money overlay).
// ---------------------------------------------------------------------------
DiceEngine::DiceEngine(int64_t house_balance) : house_balance_(house_balance) {
    if (house_balance < 0) throw std::invalid_argument("share_dice: negative pot");
}

void DiceEngine::fund_house(int64_t amount) {
    if (amount < 0) throw std::invalid_argument("share_dice: negative fund");
    house_balance_ += amount;
}

void DiceEngine::credit_miner(const std::string& miner_id, int64_t amount) {
    if (amount < 0) throw std::invalid_argument("share_dice: negative credit");
    credit_[miner_id] += amount;
}

int64_t DiceEngine::credit_of(const std::string& miner_id) const {
    auto it = credit_.find(miner_id);
    return it == credit_.end() ? 0 : it->second;
}

void DiceEngine::open_round(const std::string& commitment_hex, uint64_t round_index) {
    round_commitment_ = commitment_hex;
    round_index_ = round_index;
    round_open_ = true;
    next_seq_ = 0;
    bets_.clear();
}

uint64_t DiceEngine::place_bet(const std::string& miner_id, int tier, int64_t amount,
                               const std::string& bet_id) {
    require_tier(tier);
    if (!round_open_) throw std::invalid_argument("share_dice: no open round");
    if (amount <= 0) throw std::invalid_argument("share_dice: bet must be > 0");
    if (amount > credit_of(miner_id))
        throw std::invalid_argument("share_dice: bet exceeds miner credit");
    if (amount > max_bet(tier, house_balance_))
        throw std::invalid_argument("share_dice: bet exceeds solvency cap (max_bet)");

    credit_[miner_id] -= amount;  // escrow stake at accept
    BetRecord rec;
    rec.miner_id = miner_id;
    rec.tier = tier;
    rec.amount = amount;
    rec.bet_id = bet_id;
    rec.per_round_seq = next_seq_++;
    bets_.push_back(rec);
    return rec.per_round_seq;
}

std::vector<BetSettlement> DiceEngine::reveal(const std::string& seed_i_hex) {
    if (!round_open_) throw std::runtime_error("share_dice: no open round to reveal");
    if (!verify_chain_link(round_commitment_, seed_i_hex))
        throw std::runtime_error(
            "share_dice: reveal does not match commitment (round should be voided)");

    std::vector<BetSettlement> out;
    out.reserve(bets_.size());
    // Settle in published sequence order (design section 3.3 invariant 5).
    for (const BetRecord& b : bets_) {
        BetSettlement s;
        s.miner_id = b.miner_id;
        s.bet_id = b.bet_id;
        s.tier = b.tier;
        s.amount = b.amount;
        s.roll = compute_roll(seed_i_hex, b.bet_id);
        s.outcome = outcome_for_roll(b.tier, s.roll);
        if (s.outcome == Outcome::Win) {
            int64_t winnings = net_house_payout(b.tier, b.amount);
            // Defense-in-depth solvency re-check against the running pot.
            if (winnings > house_balance_)
                throw std::runtime_error("share_dice: solvency breach at settle");
            s.payout = b.amount + winnings;   // stake returned + winnings
            s.house_delta = -winnings;
            credit_[b.miner_id] += s.payout;
            house_balance_ -= winnings;
        } else {
            s.payout = 0;
            s.house_delta = b.amount;         // escrowed stake goes to house
            house_balance_ += b.amount;
        }
        out.push_back(s);
    }
    round_open_ = false;
    return out;
}

}  // namespace share_dice
