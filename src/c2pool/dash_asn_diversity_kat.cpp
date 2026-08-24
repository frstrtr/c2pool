// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT: PR-4 ASN / GEO DIVERSITY (dashd-cut coin-P2P racing tier).
//
// Locks the two invariants the --embedded-asn-diversity racing objective needs:
//   (1) ASN GROUP ASSIGNMENT is correct — the bundled longest-prefix table
//       maps representative provider IPs to the expected ASN bucket, and any
//       address outside the table falls back to a /16 netgroup bucket
//       ("ng:a.b") rather than collapsing every unknown into one bucket.
//   (2) The RACE SET SPANS >= 2 ASNs — enforce_asn_diversity() reorders an
//       already-score-ranked candidate list so the top `slots` entries span at
//       least `min_asns` distinct buckets WHENEVER the pool allows it, is a
//       no-op when the head is already diverse, and preserves score order when
//       the pool cannot satisfy the objective (single-provider set).
//
// Pure red/green over ONE header-only unit, NO node and NO daemon. Header-only
// so it builds under -DC2POOL_DASH_BLS=ON without the c2pool-dash object graph.

#include <impl/dash/coin/asn_diversity.hpp>

#include <cstdio>
#include <string>
#include <vector>

using dash::coin::enforce_asn_diversity;
using dash::coin::peer_asn;
using dash::coin::peer_asn_group;
using dash::coin::race_set_distinct_asns;
using dash::coin::race_set_spans_min_asns;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// A dial candidate stand-in: an endpoint host string carried in score order.
struct Cand { std::string host; };

static std::string group_of(const Cand& c) { return peer_asn_group(c.host); }

int main()
{
    // ── (1) ASN GROUP ASSIGNMENT ─────────────────────────────────────────────
    // Representative provider IPs resolve to the bundled ASN. These anchor the
    // table: a regeneration that breaks one of these fails CI (see UPDATE PATH).
    CHECK(peer_asn("109.161.57.3") == 51167);   // Contabo (hotel host /16)
    CHECK(peer_asn("88.198.5.10")  == 24940);   // Hetzner
    CHECK(peer_asn("159.65.1.1")   == 14061);   // DigitalOcean
    CHECK(peer_asn("3.5.6.7")      == 16509);   // Amazon AWS (3.0.0.0/9)
    CHECK(peer_asn("54.36.0.9")    == 16276);   // OVH (54.36.0.0/15)
    CHECK(peer_asn("34.64.1.1")    == 396982);  // Google Cloud (34.64.0.0/10)
    CHECK(peer_asn("45.32.9.9")    == 20473);   // Vultr/Choopa

    // Group LABELS mirror the ASN, and unknowns fall back to a /16 netgroup
    // bucket (NOT a single shared "unknown").
    CHECK(peer_asn_group("109.161.57.3") == "AS51167");
    CHECK(peer_asn_group("88.198.5.10")  == "AS24940");
    CHECK(peer_asn("192.0.2.1")          == 0);          // TEST-NET-1: no ASN
    CHECK(peer_asn_group("192.0.2.1")    == "ng:192.0"); // /16 fallback
    CHECK(peer_asn_group("198.51.100.4") == "ng:198.51");// distinct fallback bucket
    // Two unknowns on different /16s are DIFFERENT buckets (correct);
    // two unknowns on the same /16 share a bucket (safe over-grouping).
    CHECK(peer_asn_group("192.0.2.1")   != peer_asn_group("198.51.100.4"));
    CHECK(peer_asn_group("192.0.2.1")   == peer_asn_group("192.0.2.99"));

    // ── (2) RACE SET SPANS >= 2 ASNs ─────────────────────────────────────────
    const int SLOTS = 2, MIN = 2;

    // (2a) Head is all one provider; a second-provider candidate sits lower in
    // score order. enforce must PROMOTE it so the top-2 span 2 ASNs.
    {
        std::vector<Cand> ranked = {
            {"109.161.57.3"},  // Contabo   (best score)
            {"109.161.58.9"},  // Contabo   (same ASN)
            {"109.161.59.4"},  // Contabo   (same ASN)
            {"88.198.5.10"},   // Hetzner   (the diversifier, lower score)
        };
        CHECK(!race_set_spans_min_asns(ranked, group_of, SLOTS, MIN)); // top-2 == 1 ASN
        auto out = enforce_asn_diversity(ranked, group_of, SLOTS, MIN);
        CHECK(out.size() == ranked.size());                            // nothing dropped
        CHECK(race_set_spans_min_asns(out, group_of, SLOTS, MIN));     // objective met
        CHECK(race_set_distinct_asns(out, group_of, SLOTS) == 2);
        // Fast path keeps the best-scored peer; backup is the diversifier.
        CHECK(out[0].host == "109.161.57.3");
        CHECK(peer_asn(out[1].host) == 24940);                         // Hetzner promoted
    }

    // (2b) Head is ALREADY diverse: enforce is a strict no-op (byte-identical
    // order), so the flag-on path costs nothing when the pool is already good.
    {
        std::vector<Cand> ranked = {
            {"109.161.57.3"},  // Contabo
            {"88.198.5.10"},   // Hetzner
            {"159.65.1.1"},    // DigitalOcean
        };
        CHECK(race_set_spans_min_asns(ranked, group_of, SLOTS, MIN));
        auto out = enforce_asn_diversity(ranked, group_of, SLOTS, MIN);
        CHECK(out.size() == ranked.size());
        for (std::size_t i = 0; i < ranked.size(); ++i)
            CHECK(out[i].host == ranked[i].host);                      // order preserved
    }

    // (2c) Pool CANNOT satisfy diversity (single provider): enforce preserves
    // score order and reports the honest span (1) — it never fabricates a peer.
    {
        std::vector<Cand> ranked = {
            {"109.161.57.3"}, {"109.161.58.9"}, {"109.161.59.4"},
        };
        CHECK(!race_set_spans_min_asns(ranked, group_of, SLOTS, MIN));
        auto out = enforce_asn_diversity(ranked, group_of, SLOTS, MIN);
        CHECK(out.size() == ranked.size());
        for (std::size_t i = 0; i < ranked.size(); ++i)
            CHECK(out[i].host == ranked[i].host);                      // unchanged
        CHECK(race_set_distinct_asns(out, group_of, SLOTS) == 1);
    }

    // (2d) Unknown-provider peers on distinct /16s DO count as diverse, so the
    // racing objective works for peers outside the bundled table too.
    {
        std::vector<Cand> ranked = {
            {"192.0.2.1"},     // ng:192.0
            {"192.0.2.9"},     // ng:192.0 (same bucket)
            {"198.51.100.4"},  // ng:198.51 (diversifier)
        };
        CHECK(!race_set_spans_min_asns(ranked, group_of, SLOTS, MIN));
        auto out = enforce_asn_diversity(ranked, group_of, SLOTS, MIN);
        CHECK(race_set_spans_min_asns(out, group_of, SLOTS, MIN));
        CHECK(out[0].host == "192.0.2.1");                             // best kept
        CHECK(peer_asn_group(out[1].host) == "ng:198.51");            // diversifier promoted
    }

    // (2e) Degenerate guards: min_asns<=1, empty, single-element => input as-is.
    {
        std::vector<Cand> ranked = {{"109.161.57.3"}, {"88.198.5.10"}};
        auto a = enforce_asn_diversity(ranked, group_of, SLOTS, /*min*/1);
        CHECK(a.size() == 2 && a[0].host == ranked[0].host && a[1].host == ranked[1].host);
        std::vector<Cand> empty;
        CHECK(enforce_asn_diversity(empty, group_of, SLOTS, MIN).empty());
        std::vector<Cand> one = {{"109.161.57.3"}};
        auto o = enforce_asn_diversity(one, group_of, SLOTS, MIN);
        CHECK(o.size() == 1 && o[0].host == "109.161.57.3");
    }

    if (g_fail == 0) std::printf("dash_asn_diversity_kat: ALL PASS\n");
    else             std::printf("dash_asn_diversity_kat: %d FAILURE(S)\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
