#pragma once
// D2 — stripes + extendible-hashing prefix (pure, integer-only).
//
//   u        = H_ref / S                         (reference work per stripe)
//   h_obs    = finalized raw work of id over the prior map period
//   n(id)    = 2^ceil(log2(max(1, h_obs / u)))   changes only on x2 / /2
//   stripe_key(id, s) = H('V37RB' || chain_id || id_key || u16 s)   NO salt
//   rb_home  = top m bits of stripe_key          (k = 2^m roundabouts)
//
// Because rb_home is a key PREFIX and stripe_key carries no epoch/salt, a
// split k -> 2k sends every stripe homed at j to 2j or 2j+1 (the next key bit)
// and a merge sends 2j, 2j+1 back to j — extendible hashing. Fresh identities
// (no finalized work yet) have n = 1.

#include <cstdint>

#include "rb_gate.hpp"
#include "rb_params.hpp"

namespace c2pool::v37n::rb {

// H = sha256d over the domain-tagged canonical bytes. H is fixed as sha256d to
// match every other v37 consensus hash (v37_hash.hpp:123).
inline bytes32 stripe_key(ChainId chain_id, const bytes32& id_key, Stripe s) {
    std::vector<std::uint8_t> b;
    b.reserve(5 + 4 + 32 + 2);
    put_tag(b, TAG_STRIPE);
    put_u32(b, chain_id);
    put_b32(b, id_key);
    put_u16(b, s);
    return hash_bytes(b);
}

// Home roundabout of a stripe under k = 2^m.
inline RbIndex rb_home(const bytes32& skey, unsigned m) { return top_bits(skey, m); }

// Reference work of ONE stripe over one map period, times S (kept multiplied
// by S so the division u = H_ref / S never truncates):
//   S * u * T = H_ref * T,   T = period seconds.
inline u128 ref_work_per_period(const RoundaboutGate& g) {
    return u128(g.H_ref_per_s) * g.period_seconds();
}

// n(id): the smallest power of two p >= 1 with p * u * T >= h_obs, i.e.
//   p * H_ref * T >= h_obs * S,
// capped at S (a single identity never holds more than S stripes). OFF / ill-
// formed gate -> 1. Integer-only; the h_obs * S product saturates to the cap.
inline std::uint32_t n_of(u128 h_obs, const RoundaboutGate& g) {
    if (g.is_off() || !g.well_formed()) return 1;
    if (h_obs == 0) return 1;                         // fresh identity
    const u128 U = ref_work_per_period(g);            // = S * u * T
    const u128 lim = ~u128(0) / g.S;
    if (h_obs > lim) return g.S;                      // saturate -> cap
    const u128 need = h_obs * g.S;
    for (std::uint32_t p = 1; p < g.S; p <<= 1)
        if (u128(p) * U >= need) return p;
    return g.S;
}

// Load of stripe s of an identity with n stripes: h_obs split into n integer
// parts, the remainder spread one unit each over the lowest stripe indices.
// Σ_s stripe_load == h_obs exactly.
inline u128 stripe_load(u128 h_obs, std::uint32_t n, Stripe s) {
    if (n == 0) return 0;
    const u128 q = h_obs / n, r = h_obs % n;
    return q + (u128(s) < r ? 1 : 0);
}

}  // namespace c2pool::v37n::rb
