#pragma once
// G2 fill budgets (c2pool LTC + DOGE aux) -- faithful C++ port of
// p2pool-merged-v36 p2pool/fillbudget.py (G2 KAT green @fd13721d).
//
// One token bucket per parent chain, metering NEW-to-sharechain-window
// transaction bytes committed into OUR block/share candidates. LOCAL
// POLICY, NOT CONSENSUS: v34+ shares carry no tx-hash lists on the wire,
// so peers accept our shares regardless; this only shapes what THIS node
// commits. The bucket governs how far ABOVE the legacy 50 kB envelope a
// share may go -- worst case is exact v35 behaviour by construction.
//
// Two-phase contract:
//   grant()          pure read (get_work/template build; fires per miner
//                    request -- must NOT drain the budget).
//   settle(spent)    the ONE debit, when a share is actually FOUND (DOA/
//                    orphaned shares settle too -- bytes hit the wire).
//   on_block_reset() parent chain found a block: refill to burst
//                    (catch-up bonus) + restart the ramp at the legacy floor.
//
// Integer arithmetic on the ramp (deterministic for the KATs); tokens/rate
// carried as double, exact for the derived LTC/DOGE constants.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace ltc::coin {

// Exact legacy generation-side constant (forrestv-era
// "only allow 50 kB of new txns/share"). The ramp floor.
inline constexpr int64_t LEGACY_NEWTX_CAP = 50000;

class FillBudget {
public:
    using Clock = std::function<double()>;

    FillBudget(std::string name, double rate, int64_t burst,
               int64_t floor = LEGACY_NEWTX_CAP, int64_t ramp_shares = 4,
               Clock clock = {})
        : name_(std::move(name)),
          rate_(rate),
          burst_(burst),
          floor_(floor),
          ramp_shares_(std::max<int64_t>(1, ramp_shares)),
          clock_(clock ? std::move(clock) : default_clock()) {
        // runtime checks, not asserts: must survive -DNDEBUG
        if (!(0 < floor_ && floor_ <= burst_))
            throw std::invalid_argument(
                "FillBudget " + name_ + ": need 0 < floor <= burst");
        if (rate_ <= 0)
            throw std::invalid_argument(
                "FillBudget " + name_ + ": rate must be > 0");
        tokens_ = static_cast<double>(burst_);       // boot full: catch-up
        last_refill_ = clock_();
        shares_since_reset_ = ramp_shares_;          // boot: ramp complete
    }

    void refill(double now) {
        double dt = now - last_refill_;
        last_refill_ = now;
        if (dt > 0)
            tokens_ = std::min(static_cast<double>(burst_),
                               tokens_ + rate_ * dt);
    }
    void refill() { refill(clock_()); }

    // Linear ramp: exactly `floor` on the first share after a reset
    // (worst case == v35), reaching `burst` after ramp_shares shares.
    int64_t current_cap() const {
        int64_t k = shares_since_reset_;
        if (k >= ramp_shares_)
            return burst_;
        return floor_ + (burst_ - floor_) * k / ramp_shares_;
    }

    // Max new-tx bytes the template being built may commit. Pure read;
    // never below floor.
    int64_t grant(double now) {
        refill(now);
        double v = std::max(static_cast<double>(floor_),
                            std::min(static_cast<double>(current_cap()), tokens_));
        return static_cast<int64_t>(v);   // truncate toward zero (v >= 0)
    }
    int64_t grant() { return grant(clock_()); }

    // A share was FOUND committing spent_bytes of new txs: the one debit.
    void settle(double spent_bytes, double now) {
        refill(now);
        tokens_ = std::max(0.0, tokens_ - spent_bytes);
        ++shares_since_reset_;
    }
    void settle(double spent_bytes) { settle(spent_bytes, clock_()); }

    // Parent (or ridden) chain found a block: catch-up bonus + ramp restart.
    void on_block_reset(double now) {
        refill(now);
        tokens_ = static_cast<double>(burst_);
        shares_since_reset_ = 0;
    }
    void on_block_reset() { on_block_reset(clock_()); }

    // accessors (KATs / T1 metric emitter)
    const std::string& name() const { return name_; }
    double tokens() const { return tokens_; }
    int64_t shares_since_reset() const { return shares_since_reset_; }
    int64_t burst() const { return burst_; }
    int64_t floor() const { return floor_; }
    double rate() const { return rate_; }

private:
    static Clock default_clock() {
        return [] {
            using namespace std::chrono;
            return duration<double>(
                       steady_clock::now().time_since_epoch()).count();
        };
    }
    std::string name_;
    double rate_;
    int64_t burst_;
    int64_t floor_;
    int64_t ramp_shares_;
    Clock clock_;
    double tokens_ = 0.0;
    double last_refill_ = 0.0;
    int64_t shares_since_reset_ = 0;
};

// Registry + rider wiring ("DOGE rides litecoin"): aux buckets reset on the
// parent chain's events -- one clock, N buckets. v36 DOGE is daemon-assembled
// auxpow (only the aux hash is committed in our coinbase; no aux tx bytes in
// OUR shares), so today only the parent bucket is registered and riders are
// dormant machinery for a future local-aux-assembly path.
class FillBudgetBook {
public:
    // Note: unordered_map references/pointers survive rehash (only iterators
    // are invalidated), so the returned reference stays valid across later
    // registrations -- riders can be wired after the parent.
    FillBudget& register_bucket(const std::string& tag, FillBudget bucket,
                                const std::string& rides = {}) {
        auto it = buckets_.insert_or_assign(tag, std::move(bucket)).first;
        if (!rides.empty())
            riders_[rides].push_back(tag);
        return it->second;
    }
    FillBudget& get(const std::string& tag) { return buckets_.at(tag); }

    void on_block_reset(const std::string& tag, double now) {
        buckets_.at(tag).on_block_reset(now);
        auto it = riders_.find(tag);
        if (it != riders_.end())
            for (const auto& aux : it->second)
                buckets_.at(aux).on_block_reset(now);
    }

private:
    std::unordered_map<std::string, FillBudget> buckets_;
    std::unordered_map<std::string, std::vector<std::string>> riders_;
};

} // namespace ltc::coin
