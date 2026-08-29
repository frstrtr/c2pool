// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT: PR-2 RACE THE FRESHEST DATUM (dashd-cut coin-P2P stack).
//
// Locks the two invariants the racing wiring in p2p_client.hpp (the K-way send)
// and mn_checkpoint_lane.hpp (the reply demux) rely on:
//
//   (1) select_race_targets() names the K fastest-scored CanServeBlocks peers in
//       DISTINCT netgroups. width<=1 is single-carrier (today). Non-serving,
//       non-eligible peers are never named; two peers in one /16 count once.
//
//   (2) FreshDatumRaceInflight enforces first-VALID-wins + single-flight dedup:
//       TWO replies, one slow/invalid => the FIRST valid reply Folds (self-check
//       licensed EXACTLY ONCE), the duplicate is DropDuplicate, an invalid copy
//       with a sibling still outstanding is DropKeepRacing (NOT fail-closed),
//       and the LAST racer failing is Exhausted (fail-closed, == today at K=1).
//
// Pure red/green over ONE header-only unit, NO node and NO daemon — builds under
// -DC2POOL_DASH_BLS=ON without the c2pool-dash object graph, like PR-0's KAT.

#include <impl/dash/coin/fresh_datum_race.hpp>

#include <cstdio>
#include <string>
#include <vector>

using dash::coin::FreshDatumRaceInflight;
using dash::coin::RaceCandidate;
using dash::coin::RaceReplyAction;
using dash::coin::select_race_targets;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static RaceCandidate cand(const std::string& key, const std::string& grp,
                          int score, bool can_serve, bool eligible)
{
    RaceCandidate c;
    c.key = key; c.netgroup = grp; c.score = score;
    c.can_serve = can_serve; c.eligible = eligible;
    return c;
}

int main()
{
    // ── (1) TARGET SELECTION ────────────────────────────────────────────────

    // Flag/K defaults: OFF, K=2, width==1 while OFF (byte-identical to master).
    CHECK(dash::coin::fresh_datum_race_enabled() == false);
    CHECK(dash::coin::fresh_datum_race_k() == 2);
    CHECK(dash::coin::fresh_datum_race_width() == 1);   // OFF => single carrier
    dash::coin::set_fresh_datum_race_enabled(true);
    CHECK(dash::coin::fresh_datum_race_width() == 2);   // ON  => K
    dash::coin::set_fresh_datum_race_k(3);
    CHECK(dash::coin::fresh_datum_race_width() == 3);
    dash::coin::set_fresh_datum_race_k(0);              // floored at 1
    CHECK(dash::coin::fresh_datum_race_k() == 1);
    dash::coin::set_fresh_datum_race_enabled(false);
    CHECK(dash::coin::fresh_datum_race_width() == 1);
    dash::coin::set_fresh_datum_race_k(2);              // restore default

    // A healthy pool: pick the top-K by score, one per netgroup.
    {
        std::vector<RaceCandidate> pool = {
            cand("a1", "10.0", 100, true,  true),
            cand("a2", "10.0",  90, true,  true),   // same group as a1 -> skipped
            cand("b1", "20.0",  80, true,  true),
            cand("c1", "30.0",  70, true,  true),
        };
        auto t2 = select_race_targets(pool, 2);
        CHECK(t2.size() == 2);
        CHECK(t2[0] == "a1");                 // best score
        CHECK(t2[1] == "b1");                 // next DISTINCT group (a2 skipped)

        auto t3 = select_race_targets(pool, 3);
        CHECK(t3.size() == 3);
        CHECK(t3[0] == "a1"); CHECK(t3[1] == "b1"); CHECK(t3[2] == "c1");

        // width==1 is exactly today's single best carrier.
        auto t1 = select_race_targets(pool, 1);
        CHECK(t1.size() == 1);
        CHECK(t1[0] == "a1");

        // width==0 floors to 1 (never zero requests).
        CHECK(select_race_targets(pool, 0).size() == 1);
    }

    // Non-serving / non-eligible carriers are never raced.
    {
        std::vector<RaceCandidate> pool = {
            cand("hi",  "10.0", 200, false, true),   // NOT CanServeBlocks
            cand("dem", "20.0", 190, true,  false),  // demoted/unhandshaked
            cand("ok",  "30.0",  50, true,  true),   // the only real carrier
        };
        auto t = select_race_targets(pool, 3);
        CHECK(t.size() == 1);
        CHECK(t[0] == "ok");
    }

    // Distinct-netgroup cap: three high scorers in ONE /16 yield ONE target.
    {
        std::vector<RaceCandidate> pool = {
            cand("s1", "42.42", 100, true, true),
            cand("s2", "42.42",  99, true, true),
            cand("s3", "42.42",  98, true, true),
        };
        auto t = select_race_targets(pool, 3);
        CHECK(t.size() == 1);
        CHECK(t[0] == "s1");
    }

    // Empty group string => the key is its own group (each raced separately).
    {
        std::vector<RaceCandidate> pool = {
            cand("x", "", 10, true, true),
            cand("y", "", 20, true, true),
        };
        auto t = select_race_targets(pool, 2);
        CHECK(t.size() == 2);
        CHECK(t[0] == "y");   // higher score first
        CHECK(t[1] == "x");
    }

    // No eligible carrier => empty => caller keeps its single-carrier fallback.
    {
        std::vector<RaceCandidate> pool = { cand("bad", "1.1", 5, false, false) };
        CHECK(select_race_targets(pool, 2).empty());
        CHECK(select_race_targets({}, 2).empty());
    }

    // ── (2) FIRST-VALID-WINS + SINGLE-FLIGHT DEDUP ──────────────────────────

    // THE HEADLINE KAT: two replies, one slow/invalid. First valid wins, the
    // duplicate is discarded, the fold self-check is licensed EXACTLY ONCE.
    {
        FreshDatumRaceInflight<std::string> r;
        r.arm("H", 2);                       // raced to 2 carriers
        CHECK(r.have());
        CHECK(!r.satisfied());
        CHECK(r.outstanding() == 2);

        // Carrier A answers first with a VALID (self-checked) copy -> Fold once.
        int folds = 0;
        auto a = r.on_reply("H", /*valid=*/true);
        if (a == RaceReplyAction::Fold) ++folds;
        CHECK(a == RaceReplyAction::Fold);
        CHECK(r.satisfied());
        CHECK(r.outstanding() == 1);         // B is still notionally in flight

        // Carrier B's (slower) copy of the SAME object arrives -> duplicate.
        auto b = r.on_reply("H", /*valid=*/true);
        if (b == RaceReplyAction::Fold) ++folds;
        CHECK(b == RaceReplyAction::DropDuplicate);

        // Even a THIRD stray copy is a duplicate, never a second fold.
        CHECK(r.on_reply("H", true) == RaceReplyAction::DropDuplicate);
        CHECK(folds == 1);                    // self-check/fold ran EXACTLY once
    }

    // Variant: the SLOW one is the INVALID one, and it arrives FIRST. The
    // invalid copy does NOT fail-close (a sibling is outstanding) and does NOT
    // fold; the later valid copy wins. Self-check still folds exactly once.
    {
        FreshDatumRaceInflight<std::string> r;
        r.arm("H", 2);
        int folds = 0;

        auto bad = r.on_reply("H", /*valid=*/false);   // garbage from a racer
        CHECK(bad == RaceReplyAction::DropKeepRacing);  // wait, do not fail-close
        CHECK(!r.satisfied());
        CHECK(r.outstanding() == 1);

        auto good = r.on_reply("H", /*valid=*/true);
        if (good == RaceReplyAction::Fold) ++folds;
        CHECK(good == RaceReplyAction::Fold);
        CHECK(folds == 1);
    }

    // K==1 single-carrier: a valid reply folds; the SAME arm, when the one
    // reply is invalid, is Exhausted immediately (fail-closed == today).
    {
        FreshDatumRaceInflight<std::string> r;
        r.arm("H", 1);
        CHECK(r.on_reply("H", true) == RaceReplyAction::Fold);
    }
    {
        FreshDatumRaceInflight<std::string> r;
        r.arm("H", 1);
        CHECK(r.on_reply("H", false) == RaceReplyAction::Exhausted);
        CHECK(!r.satisfied());
    }

    // ALL racers fail: each drop keeps racing until the LAST, which exhausts.
    {
        FreshDatumRaceInflight<std::string> r;
        r.arm("H", 3);
        CHECK(r.on_reply("H", false) == RaceReplyAction::DropKeepRacing);
        CHECK(r.on_reply("H", false) == RaceReplyAction::DropKeepRacing);
        CHECK(r.on_reply("H", false) == RaceReplyAction::Exhausted);
    }

    // A reply for an object we are NOT racing is NotArmed (handled as pre-PR-2).
    {
        FreshDatumRaceInflight<std::string> r;
        CHECK(r.on_reply("H", true) == RaceReplyAction::NotArmed);   // never armed
        r.arm("H", 2);
        CHECK(r.on_reply("OTHER", true) == RaceReplyAction::NotArmed); // wrong key
        // The armed race is untouched by the foreign reply.
        CHECK(r.outstanding() == 2);
        CHECK(!r.satisfied());
    }

    // clear() forgets the race entirely (a new begin_fold for a new height).
    {
        FreshDatumRaceInflight<std::string> r;
        r.arm("H", 2);
        r.on_reply("H", true);
        r.clear();
        CHECK(!r.have());
        CHECK(r.on_reply("H", true) == RaceReplyAction::NotArmed);
    }

    // Works over an integer key too (the template is key-agnostic; the lane
    // instantiates it on uint256).
    {
        FreshDatumRaceInflight<int> r;
        r.arm(7, 2);
        CHECK(r.on_reply(7, true) == RaceReplyAction::Fold);
        CHECK(r.on_reply(7, true) == RaceReplyAction::DropDuplicate);
        CHECK(r.on_reply(9, true) == RaceReplyAction::NotArmed);
    }

    if (g_fail == 0) { std::printf("dash_fresh_datum_race_kat PASS\n"); return 0; }
    std::printf("dash_fresh_datum_race_kat FAIL (%d)\n", g_fail);
    return 1;
}
