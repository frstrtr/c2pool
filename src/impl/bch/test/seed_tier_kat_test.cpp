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
//   3) CandidateWalk -- the peer-loss tail-walk + re-arm cursor. On master a
//      single dial of candidates.front() re-dialed the dead front forever;
//      the walk MUST advance front -> tail on each peer loss and raise its
//      wrap signal (re-arm) once the ladder is exhausted. This KAT pins that
//      rotation contract; a front-forever transport fails the tail asserts.
//
//   2) build_ladder(dns_resolved, fixed, http_resolved) -- ordered, deduped
//      tier assembly. DNS is the primary tier; fixed SUBSTITUTES for it only
//      when DNS resolved nothing; the HTTP-peer (tier-3) list is appended AFTER
//      the primary tier. Dedup preserves FIRST occurrence, so the order is
//      [DNS or fixed] then [http].
//
//   4) EmergencyReArm -- the fleet-canonical never-re-arm fix (the/docs/
//      coin-peer-manager-rearm.md sections 2.1-2.4), BCH single-peer locus.
//      Pins the THREE MANDATORY properties network-free: (4.1) saturating
//      exponential backoff min(base<<n,max) that never overflows, (4.2) the
//      re-entry latch that collapses N starved ticks into ONE re-arm, and
//      (4.3) the recovery reset that re-arms from base, not the ceiling.
//
// Harness: plain int main() + assert-style CHECK (CTest treats exit 0 as PASS),
// matching the sibling bch KAT tests. Header-only over coin/seed_tier.hpp +
// <core/netaddress.hpp>; no coin lib link -> per-coin isolation stays clean.
// The async resolve_candidates()/http_fetch_coin_peers() paths (network) are
// NOT exercised here -- only the pure static tier logic.
// ---------------------------------------------------------------------------

#include <cstdint>
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

    // ---- 3) CandidateWalk: tail-walk on peer loss, wrap -> re-arm -------
    {
        // Ordered ladder: front, then tail tiers (fixed / http). On master the
        // transport re-dialed candidates.front() forever, so a permanently-dead
        // front seed NEVER reached the tail. The walk MUST visit the tail.
        SeedTier::CandidateWalk w;
        w.rearm({ ns("1.1.1.1", 8333),    // front (modelled permanently dead)
                  ns("2.2.2.2", 8333),    // tail / fixed tier
                  ns("3.3.3.3", 8333) }); // http tier-3
        CHECK(!w.empty());
        CHECK(w.size() == 3);

        // Initial dial + a run of peer-loss reconnect ticks -> dialed sequence.
        std::vector<NetService> dialed;
        std::vector<bool>       wraps;
        for (int i = 0; i < 5; ++i) {
            bool wrapped = false;
            dialed.push_back(w.next(wrapped));
            wraps.push_back(wrapped);
        }
        // Front, then WALK the tail -- not front-forever (the master defect).
        CHECK(dialed[0] == ns("1.1.1.1", 8333));   // initial dial
        CHECK(dialed[1] == ns("2.2.2.2", 8333));   // peer loss -> tail, NOT front
        CHECK(dialed[2] == ns("3.3.3.3", 8333));   // peer loss -> http tier-3
        CHECK(dialed[1] != dialed[0]);             // reached the tail...
        CHECK(dialed[2] != dialed[0]);             // ...every tier, not front-forever
        // Wrap detection: ticks 0..2 in-range; tick 3 wraps past the last -> the
        // re-arm signal; cursor then advances normally again.
        CHECK(wraps[0] == false);
        CHECK(wraps[1] == false);
        CHECK(wraps[2] == false);
        CHECK(wraps[3] == true);                   // exhausted -> re-arm signal
        CHECK(dialed[3] == ns("1.1.1.1", 8333));   // wrapped back to front
        CHECK(wraps[4] == false);
        CHECK(dialed[4] == ns("2.2.2.2", 8333));
    }

    // ---- 3b) rearm() replaces the list + rewinds the cursor ------------
    {
        SeedTier::CandidateWalk w;
        w.rearm({ ns("1.1.1.1", 8333), ns("2.2.2.2", 8333) });
        bool wrapped = false;
        CHECK(w.next(wrapped) == ns("1.1.1.1", 8333));   // cursor -> 1
        // Fresh resolve delivers a new ladder: cursor MUST rewind to its front.
        w.rearm({ ns("7.7.7.7", 8333), ns("8.8.8.8", 8333) });
        CHECK(w.next(wrapped) == ns("7.7.7.7", 8333));   // rewound to new front
        CHECK(wrapped == false);
        // Empty refresh is IGNORED -- keep walking the last good ladder.
        w.rearm({});
        CHECK(w.size() == 2);
        CHECK(w.next(wrapped) == ns("8.8.8.8", 8333));
    }

    // ---- 3c) empty walk -> empty() gates the caller (no next()) --------
    {
        SeedTier::CandidateWalk w;
        CHECK(w.empty());
        CHECK(w.size() == 0);
    }

    // ---- 4) EmergencyReArm: the three MANDATORY re-arm properties -------
    // Fleet-canonical never-re-arm spec (coin-peer-manager-rearm.md 2.1-2.4),
    // BCH single-peer locus. On master these entry points do not exist, so this
    // section fails to COMPILE there -- the required red.
    using ER = SeedTier::EmergencyReArm;

    // 4.1 BACKOFF (spec 2.1): delay(n) = min(base<<n, max); saturating shift,
    //     never overflows for large n. base=60, max=3600 (BCH-local consts).
    {
        CHECK(ER::base_backoff_sec == 60);
        CHECK(ER::max_backoff_sec  == 3600);
        // base, 2*base, 4*base, ... doubling until the clamp.
        CHECK(ER::delay_for(0) == 60);
        CHECK(ER::delay_for(1) == 120);
        CHECK(ER::delay_for(2) == 240);
        CHECK(ER::delay_for(3) == 480);
        CHECK(ER::delay_for(4) == 960);
        CHECK(ER::delay_for(5) == 1920);
        // 60<<6 = 3840 >= 3600 -> saturates at the ceiling from n=6 on.
        CHECK(ER::delay_for(6) == 3600);
        CHECK(ER::delay_for(7) == 3600);
        CHECK(ER::delay_for(20) == 3600);
        // Saturating helper must NOT overflow / wrap for large n (a bare
        // `base << n` is UB at n>=32 and wraps to a small/zero delay -> storm).
        CHECK(ER::delay_for(31) == 3600);
        CHECK(ER::delay_for(32) == 3600);
        CHECK(ER::delay_for(63) == 3600);
        CHECK(ER::delay_for(1000) == 3600);
        // Monotonic non-decreasing, always within [base, max] -- never 0.
        uint32_t prev = 0;
        for (uint32_t n = 0; n <= 40; ++n) {
            uint32_t d = ER::delay_for(n);
            CHECK(d >= ER::base_backoff_sec);
            CHECK(d <= ER::max_backoff_sec);
            CHECK(d >= prev);
            prev = d;
        }
    }

    // 4.2 RE-ENTRY GUARD (spec 2.2): N consecutive starved ticks BETWEEN two
    //     timer firings schedule EXACTLY ONE re-arm -- attempt advances by 1,
    //     not N. The latch collapses the storm.
    {
        ER e;
        CHECK(e.attempt == 0);
        CHECK(e.active  == false);
        // First starved tick -> arm: returns the base delay, latch set, n=1.
        auto d0 = e.on_starved_tick();
        CHECK(d0.has_value());
        CHECK(*d0 == 60);
        CHECK(e.attempt == 1);
        CHECK(e.active  == true);
        // 100 more starved ticks BEFORE the timer fires -> all no-ops (latched).
        for (int i = 0; i < 100; ++i)
            CHECK(!e.on_starved_tick().has_value());
        CHECK(e.attempt == 1);            // advanced by 1, NOT 101 -> no storm
        CHECK(e.active  == true);
        // Timer fires (delay elapsed) -> latch released at the top of the handler.
        e.on_timer_fire();
        CHECK(e.active == false);
        // Still starved -> next arm escalates to 2*base, attempt -> 2.
        auto d1 = e.on_starved_tick();
        CHECK(d1.has_value());
        CHECK(*d1 == 120);                // 2*base -- backoff grew
        CHECK(e.attempt == 2);
        CHECK(e.active  == true);
    }

    // 4.3 RECOVERY RESET (spec 2.3): a tick observing connected >= min zeroes
    //     the counter; the SUBSEQUENT starvation re-arms from base, not the
    //     ceiling reached before recovery.
    {
        ER e;
        // Drive the backoff up near the ceiling (arm/fire several cycles).
        for (int i = 0; i < 8; ++i) { e.on_starved_tick(); e.on_timer_fire(); }
        CHECK(e.attempt == 8);
        CHECK(ER::delay_for(e.attempt) == 3600);   // at the ceiling
        // Recovery: connected peer -> reset counter + clear latch.
        e.clear();
        CHECK(e.attempt == 0);
        CHECK(e.active  == false);
        // Next drop must re-arm from BASE, not resume at the ceiling.
        auto d = e.on_starved_tick();
        CHECK(d.has_value());
        CHECK(*d == 60);                            // base, NOT 3600
        CHECK(e.attempt == 1);
    }

    if (failures == 0) {
        std::cout << "seed_tier_kat_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "seed_tier_kat_test: " << failures << " FAILURE(S)\n";
    return 1;
}
