// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin::SeedTier KAT -- pins the two PURE, network-free primitives the
// Option-A embedded peer-discovery ladder relies on:
//
//   1) should_run_ladder(explicit_peer_port, has_seeds) -- the reward-safe
//      gate. The ladder is consulted ONLY when NO explicit peer is configured
//      (port == 0) AND at least one tier is populated. An explicit peer
//      (port != 0) ALWAYS bypasses it, so the configured-peer / RPC-only
//      default is untouched.
//
//   2) build_ladder(dns_resolved, fixed, http_resolved) -- ordered, deduped
//      tier assembly. DNS is the primary tier; fixed SUBSTITUTES for it only
//      when DNS resolved nothing; the HTTP-peer (tier-3) list is appended AFTER
//      the primary tier. Dedup preserves FIRST occurrence, so the order is
//      [DNS or fixed] then [http].
//
// Harness: plain int main() + assert-style CHECK (CTest treats exit 0 as PASS),
// matching the sibling bch KAT tests. Header-only over coin/seed_tier.hpp +
// <core/netaddress.hpp>; no coin lib link -> per-coin isolation stays clean.
// The async resolve_candidates()/http_fetch_coin_peers() paths (network) are
// NOT exercised here -- only the pure static tier logic.
// ---------------------------------------------------------------------------

#include <iostream>
#include <vector>

#include <core/netaddress.hpp>
#include "../coin/seed_tier.hpp"

namespace {
int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

using bch::coin::SeedTier;

NetService ns(const std::string& ip, uint16_t port) { return NetService(ip, port); }
} // namespace

int main()
{
    // ---- 1) should_run_ladder gate --------------------------------------
    // No explicit peer (port 0) + seeds present -> ladder runs.
    CHECK(SeedTier::should_run_ladder(/*port=*/0, /*has_seeds=*/true) == true);
    // No explicit peer but NO seeds -> RPC-only (ladder skipped).
    CHECK(SeedTier::should_run_ladder(/*port=*/0, /*has_seeds=*/false) == false);
    // EXPLICIT peer configured -> ALWAYS bypass the ladder, seeds or not.
    CHECK(SeedTier::should_run_ladder(/*port=*/28333, /*has_seeds=*/true) == false);
    CHECK(SeedTier::should_run_ladder(/*port=*/8333,  /*has_seeds=*/true) == false);
    CHECK(SeedTier::should_run_ladder(/*port=*/28333, /*has_seeds=*/false) == false);

    // has_seeds() reflects any populated tier.
    {
        SeedTier t;
        CHECK(t.has_seeds() == false);
        t.set_http_peer_seeds({{"voidbind.com", 8080}});
        CHECK(t.has_seeds() == true);
    }

    // ---- 2) build_ladder ordering: DNS primary, then HTTP tier-3 --------
    {
        std::vector<NetService> dns   = { ns("1.1.1.1", 8333), ns("2.2.2.2", 8333) };
        std::vector<NetService> fixed = { ns("9.9.9.9", 8333) };
        std::vector<NetService> http  = { ns("3.3.3.3", 8333) };
        auto out = SeedTier::build_ladder(dns, fixed, http);
        // DNS non-empty -> fixed is NOT used; order is [dns...] then [http].
        CHECK(out.size() == 3);
        CHECK(out[0] == ns("1.1.1.1", 8333));
        CHECK(out[1] == ns("2.2.2.2", 8333));
        CHECK(out[2] == ns("3.3.3.3", 8333));       // http appended AFTER dns
        // fixed seed must NOT appear when DNS resolved something.
        for (const auto& e : out) CHECK(e != ns("9.9.9.9", 8333));
    }

    // ---- 2b) DNS empty -> fixed SUBSTITUTES as primary, then HTTP -------
    {
        std::vector<NetService> dns;                 // resolved nothing
        std::vector<NetService> fixed = { ns("9.9.9.9", 8333) };
        std::vector<NetService> http  = { ns("3.3.3.3", 8333) };
        auto out = SeedTier::build_ladder(dns, fixed, http);
        CHECK(out.size() == 2);
        CHECK(out[0] == ns("9.9.9.9", 8333));        // fixed substitutes for DNS
        CHECK(out[1] == ns("3.3.3.3", 8333));        // http tier-3 appended
    }

    // ---- 2c) dedup preserves FIRST occurrence --------------------------
    {
        // Duplicate within the primary tier + a http entry that already
        // appeared in the primary -> each kept exactly once, first-seen order.
        std::vector<NetService> dns  = { ns("1.1.1.1", 8333),
                                         ns("1.1.1.1", 8333),   // dup in primary
                                         ns("2.2.2.2", 8333) };
        std::vector<NetService> http = { ns("1.1.1.1", 8333),   // dup of dns[0]
                                         ns("4.4.4.4", 8333) };
        auto out = SeedTier::build_ladder(dns, {}, http);
        CHECK(out.size() == 3);
        CHECK(out[0] == ns("1.1.1.1", 8333));
        CHECK(out[1] == ns("2.2.2.2", 8333));
        CHECK(out[2] == ns("4.4.4.4", 8333));
    }

    // ---- 2d) port participates in identity (same ip, different port) ---
    {
        std::vector<NetService> dns  = { ns("5.5.5.5", 8333) };
        std::vector<NetService> http = { ns("5.5.5.5", 28333) }; // diff port -> distinct
        auto out = SeedTier::build_ladder(dns, {}, http);
        CHECK(out.size() == 2);
        CHECK(out[0] == ns("5.5.5.5", 8333));
        CHECK(out[1] == ns("5.5.5.5", 28333));
    }

    // ---- 2e) all tiers empty -> empty ladder ---------------------------
    {
        auto out = SeedTier::build_ladder({}, {}, {});
        CHECK(out.empty());
    }

    if (failures == 0) {
        std::cout << "seed_tier_kat_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "seed_tier_kat_test: " << failures << " FAILURE(S)\n";
    return 1;
}
