#pragma once
// S4 — settlement over k roundabouts against the ONE replicated ledger (D1).
//
//   E_b = split_reward(R_b, Σ_i payout_map_i)        (key-wise U256 sum)
//
// reusing the consensus largest-remainder split VERBATIM
// (w4_settlement.hpp:166-195: floor + leftover to the largest remainders, ties
// by canonical key ASC; Σ E_b == R_b by construction). Because the combination
// is a KEY-WISE sum, E_b is invariant under any relocation of a key's weight
// between roundabouts (split, merge, stripe move, legacy ring still draining):
// only Σ_i w_i(key) matters. With k = 1 (gate OFF) this is exactly
// settle::settle_block() on the single lane map — byte-identical E_b, hence
// byte-identical owed_digest.

#include <cstdint>
#include <map>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>   // settle::split_reward, WeightedPayee (read-only)

#include "rb_checkpoint.hpp"
#include "rb_params.hpp"

namespace c2pool::v37n::rb {

using PayoutMap = std::map<bytes32, U256>;

// Key-wise Σ over the roundabouts' payout maps; zero weights dropped.
inline PayoutMap combine_payout_maps(const std::vector<const PayoutMap*>& maps) {
    PayoutMap out;
    for (const PayoutMap* m : maps) {
        if (!m) continue;
        for (const auto& [k, w] : *m) {
            if (w.is_zero()) continue;
            out[k] += w;
        }
    }
    return out;
}

inline PayoutMap combine_summaries(const std::vector<Summary>& s) {
    std::vector<const PayoutMap*> v;
    v.reserve(s.size());
    for (const auto& x : s) v.push_back(&x.payout_map);
    return combine_payout_maps(v);
}

// E_b over a combined map, key-keyed (key ASC order of payees; split_reward is
// order-independent in value, so any order yields the same map).
inline std::map<bytes32, u64> settle_combined(u64 reward, const PayoutMap& combined) {
    std::vector<settle::WeightedPayee> payees;
    payees.reserve(combined.size());
    for (const auto& [k, w] : combined) {
        if (w.is_zero()) continue;
        settle::WeightedPayee p;
        p.key = k;
        p.weight = w;
        payees.push_back(p);
    }
    const std::vector<u64> amt = settle::split_reward(reward, payees);
    std::map<bytes32, u64> e;
    for (std::size_t i = 0; i < payees.size(); ++i)
        if (amt[i] > 0) e[payees[i].key] += amt[i];
    return e;
}

inline std::map<bytes32, u64> settle_roundabouts(u64 reward, const std::vector<Summary>& s) {
    return settle_combined(reward, combine_summaries(s));
}

inline u64 sum_amounts(const std::map<bytes32, u64>& e) {
    u64 t = 0;
    for (const auto& kv : e) t += kv.second;
    return t;
}

inline U256 sum_weights(const PayoutMap& m) {
    U256 t;
    for (const auto& kv : m) t += kv.second;
    return t;
}

}  // namespace c2pool::v37n::rb
