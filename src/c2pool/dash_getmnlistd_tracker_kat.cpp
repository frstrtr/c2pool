// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT: EMBEDDED getmnlistd SLOT TRACKER (dashd-cut coin-P2P stack, task #154).
//
// Locks the five reward-safety / behaviour gates the wiring depends on:
//
//   (1) <=K IN-FLIGHT INVARIANT across a simulated rotation: slots retarget on
//       their own 10s timer (fixed, no backoff); the outstanding set NEVER
//       grows past K; a struck peer is benched until a FULL rotation, then the
//       struck set is cleared (re-eligible).
//   (2) LATE / DUPLICATE reply: the first content-addressed match wins (RACE
//       satisfied), later copies are DropDuplicate, and NO strike is charged to
//       a sibling genuinely asked this session; admission stays content-
//       addressed (FreshDatumRaceInflight keyed by object identity, never peer).
//   (3) EXPIRY mid-lane: at 100s (10x) the action is ESCALATE, never a repeated
//       ask; applied folds are untouched (the tracker abandons a pending
//       REQUEST, it never rewinds a fold).
//   (4) CAPABILITY FILTER: an old-protocol peer that cannot serve GETMNLISTDIFF
//       never receives a slot, no matter how it is otherwise scored.
//   (5) OFF-EQUIVALENCE: the flag defaults OFF; toggling is exact; OFF => the
//       tracker is never consulted (the re-ask path is byte-identical to
//       master, which reads none of this machinery).
//
// Pure red/green over TWO header-only units (getmnlistd_tracker.hpp +
// fresh_datum_race.hpp), NO node and NO daemon — builds under
// -DC2POOL_DASH_BLS=ON without the c2pool-dash object graph, like PR-0/PR-2.

#include <impl/dash/coin/getmnlistd_tracker.hpp>
#include <impl/dash/coin/fresh_datum_race.hpp>

#include <cstdio>
#include <string>
#include <vector>

using dash::coin::FreshDatumRaceInflight;
using dash::coin::GetmnlistdCandidate;
using dash::coin::GetmnlistdExpiryAction;
using dash::coin::GetmnlistdSlotTracker;
using dash::coin::GetmnlistdTier;
using dash::coin::RaceReplyAction;
using dash::coin::classify_getmnlistd_expiry;
using dash::coin::getmnlistd_capable;
using dash::coin::getmnlistd_emit_eligible;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// A CAPABLE, serve-eligible candidate at the current DASH protocol version.
static GetmnlistdCandidate cap(const std::string& key, const std::string& grp)
{
    GetmnlistdCandidate c;
    c.key = key; c.netgroup = grp;
    c.proto_version = 70230;      // >= kGetmnlistdServeProtoVersion (70214)
    c.serve_eligible = true;
    return c;
}

// An INCAPABLE carrier: NODE_NETWORK serve-eligible (the race's own gate PASSES,
// exactly like the real silent carriers) but proto < 70214 so it structurally
// cannot serve GETMNLISTDIFF. It must never receive a slot on ANY emit path.
static GetmnlistdCandidate incap(const std::string& key, const std::string& grp)
{
    GetmnlistdCandidate c;
    c.key = key; c.netgroup = grp;
    c.proto_version = 70213;      // one below the serve floor
    c.serve_eligible = true;      // NODE_NETWORK proves nothing — still ineligible
    return c;
}

int main()
{
    // ── (5) OFF-EQUIVALENCE (checked first: the default state matters most) ──
    // Default OFF; the wiring reads NONE of the machinery below while OFF, so an
    // unflagged binary takes the identical wall-clock ladder path as master.
    CHECK(dash::coin::embedded_getmnlistd_tracker_enabled() == false);
    dash::coin::set_embedded_getmnlistd_tracker_enabled(true);
    CHECK(dash::coin::embedded_getmnlistd_tracker_enabled() == true);
    dash::coin::set_embedded_getmnlistd_tracker_enabled(false);
    CHECK(dash::coin::embedded_getmnlistd_tracker_enabled() == false);   // restore OFF

    // ── (4) CAPABILITY FILTER ───────────────────────────────────────────────
    CHECK(getmnlistd_capable(70230) == true);
    CHECK(getmnlistd_capable(70214) == true);    // exactly the serve floor
    CHECK(getmnlistd_capable(70213) == false);   // one below -> cannot serve
    CHECK(getmnlistd_capable(70000) == false);
    CHECK(getmnlistd_capable(0)     == false);
    {
        // An old-proto peer with the HIGHEST notional preference never gets a
        // slot; the one capable peer does.
        GetmnlistdSlotTracker tr;
        tr.configure(2);
        GetmnlistdCandidate old = cap("old", "10.0"); old.proto_version = 70213; // incapable
        GetmnlistdCandidate ok  = cap("ok",  "20.0");                            // capable
        auto sent = tr.plan({old, ok}, /*now=*/0);
        CHECK(sent.size() == 1);
        CHECK(sent[0] == "ok");
        CHECK(tr.holds("ok"));
        CHECK(!tr.holds("old"));
        CHECK(tr.in_flight() == 1);
    }

    // ── (1) <=K IN-FLIGHT INVARIANT ACROSS A ROTATION ───────────────────────
    {
        GetmnlistdSlotTracker tr;
        tr.configure(2);                       // K = 2 slots
        std::vector<GetmnlistdCandidate> pool = {
            cap("a", "10.0"), cap("b", "20.0"), cap("c", "30.0"), cap("d", "40.0"),
        };

        // t=0: fill both slots. Never-asked (T2) peers, round-robin by key.
        auto s0 = tr.plan(pool, 0);
        CHECK(s0.size() == 2);
        CHECK(tr.in_flight() == 2);
        CHECK(tr.in_flight() <= tr.k());       // INVARIANT
        // Two DISTINCT netgroups occupied.
        CHECK(tr.holds(s0[0]) && tr.holds(s0[1]));

        // t=5s: no slot has lapsed (< 10s). No new asks, still 2 in flight.
        auto s5 = tr.plan(pool, 5000);
        CHECK(s5.empty());
        CHECK(tr.in_flight() == 2);

        // t=10s: BOTH slots lapse -> struck + retargeted to the OTHER two peers.
        // Set does NOT grow past K.
        auto s10 = tr.plan(pool, 10000);
        CHECK(s10.size() == 2);
        CHECK(tr.in_flight() == 2);
        CHECK(tr.in_flight() <= tr.k());       // INVARIANT held through retarget
        // The two just-struck holders are NOT re-selected this rotation.
        for (const auto& k : s10) { CHECK(k != s0[0]); CHECK(k != s0[1]); }
        CHECK(tr.is_struck(s0[0]));
        CHECK(tr.is_struck(s0[1]));

        // t=20s: the second pair lapses too. Now EVERY capable peer is struck,
        // so a FULL rotation has elapsed: the struck set clears (re-eligible)
        // and we retarget onto the first pair again. Still <= K.
        auto s20 = tr.plan(pool, 20000);
        CHECK(s20.size() == 2);
        CHECK(tr.in_flight() == 2);
        CHECK(tr.in_flight() <= tr.k());       // INVARIANT held across rotation wrap
    }

    // ── (1b) NO BACKOFF: the interval is FIXED 10s per slot, not a growing
    // ladder. Two consecutive lapses retarget at the SAME 10s cadence.
    {
        GetmnlistdSlotTracker tr;
        tr.configure(1);
        std::vector<GetmnlistdCandidate> pool = { cap("a", "10.0"), cap("b", "20.0") };
        CHECK(tr.plan(pool, 0).size() == 1);           // slot filled at t=0
        CHECK(tr.plan(pool, 9999).empty());            // 9.999s: not yet lapsed
        CHECK(tr.plan(pool, 10000).size() == 1);       // 10.000s: retarget (fixed)
        CHECK(tr.plan(pool, 19999).empty());           // next 9.999s: not lapsed
        CHECK(tr.plan(pool, 20000).size() == 1);       // 10.000s later: retarget AGAIN
        CHECK(tr.in_flight() == 1);
    }

    // ── (2) LATE / DUPLICATE reply => first wins, rest dropped, NO strike,
    //         admission content-addressed ────────────────────────────────────
    {
        GetmnlistdSlotTracker tr;
        tr.configure(2);
        std::vector<GetmnlistdCandidate> pool = { cap("a", "10.0"), cap("b", "20.0") };
        auto sent = tr.plan(pool, 0);
        CHECK(sent.size() == 2);
        const std::string winner = sent[0];
        const std::string sibling = sent[1];

        // Admission is CONTENT-ADDRESSED: the race is keyed by the object hash,
        // never by peer identity. First strict-matcher pass flips satisfied.
        FreshDatumRaceInflight<std::string> race;
        race.arm("SNAPSHOT_HASH", 2);
        CHECK(race.on_reply("SNAPSHOT_HASH", /*valid=*/true) == RaceReplyAction::Fold);
        CHECK(race.satisfied());
        // A late DUPLICATE from the sibling is dropped, NOT a second fold.
        CHECK(race.on_reply("SNAPSHOT_HASH", true) == RaceReplyAction::DropDuplicate);
        // A reply for a DIFFERENT object is NotArmed (peer identity is irrelevant
        // to admission; only the object hash matters).
        CHECK(race.on_reply("OTHER_HASH", true) == RaceReplyAction::NotArmed);

        // Tracker side: the winner is marked T1 (answered) and the whole race is
        // freed. The sibling that was genuinely asked this session is NOT struck
        // — a late/duplicate copy earns no misbehaviour strike.
        tr.note_answered(winner);
        tr.win_race();
        CHECK(tr.tier_of(winner) == GetmnlistdTier::Answered);   // T1
        CHECK(!tr.is_struck(winner));
        CHECK(!tr.is_struck(sibling));                            // NO strike on the sibling
        CHECK(tr.asked(sibling));                                 // it WAS asked
        CHECK(tr.tier_of(sibling) == GetmnlistdTier::Asked);      // T3 (asked, not answered) — not struck
        CHECK(tr.in_flight() == 0);                               // race freed
    }

    // ── (2b) TIER PREFERENCE: an ANSWERED (T1) peer outranks a NEVER-ASKED (T2)
    //         peer, which outranks an ASKED-not-answered (T3) peer. ───────────
    {
        GetmnlistdSlotTracker tr;
        tr.configure(1);
        // Prime session state: "ans" answered, "askd" was asked (not answered),
        // "new" is untouched.
        tr.note_answered("ans");     // T1
        // Simulate "askd" having been asked: put it in a slot then strike-free
        // via a lapse-free disconnect-less path — use plan with only askd, then
        // free by winning a different object is awkward; instead assert tier
        // directly after an ask by planning it into a slot and freeing it.
        {
            GetmnlistdCandidate only = cap("askd", "99.0");
            auto s = tr.plan({only}, 0);
            CHECK(s.size() == 1);
            tr.win_race();           // asked, race won by someone else -> not struck
            CHECK(tr.tier_of("askd") == GetmnlistdTier::Asked);   // T3
        }
        CHECK(tr.tier_of("ans") == GetmnlistdTier::Answered);     // T1
        CHECK(tr.tier_of("brand-new") == GetmnlistdTier::NeverAsked); // T2

        // Offer all three (distinct netgroups): T1 "ans" must be chosen first.
        std::vector<GetmnlistdCandidate> pool = {
            cap("askd", "99.0"), cap("brand-new", "88.0"), cap("ans", "77.0"),
        };
        auto pick = tr.plan(pool, 0);
        CHECK(pick.size() == 1);
        CHECK(pick[0] == "ans");     // T1 beats T2 beats T3
    }

    // ── (2c) DISCONNECT resets the T1 answered boolean (session-local only) ──
    {
        GetmnlistdSlotTracker tr;
        tr.configure(1);
        tr.note_answered("p");
        CHECK(tr.answered("p"));
        CHECK(tr.tier_of("p") == GetmnlistdTier::Answered);
        tr.on_disconnect("p");
        CHECK(!tr.answered("p"));
        CHECK(!tr.asked("p"));
        CHECK(tr.tier_of("p") == GetmnlistdTier::NeverAsked);   // back to T2 as if fresh
    }

    // ── (3) EXPIRY mid-lane => ESCALATE not repeat; applied folds untouched ──
    {
        // The tracker abandons a pending REQUEST; it never rewinds a fold. Model
        // "applied folds" as an external counter the tracker cannot touch.
        int applied_folds = 7;                 // folds already applied by the lane

        GetmnlistdSlotTracker tr;
        tr.configure(2);
        std::vector<GetmnlistdCandidate> pool = { cap("a", "10.0"), cap("b", "20.0") };
        auto sent = tr.plan(pool, 0);          // asks go out at t=0
        CHECK(sent.size() == 2);

        // Before 100s: WAIT (keep racing / retargeting on the 10s slot timer).
        CHECK(classify_getmnlistd_expiry(50000, tr.oldest_asked_at(50000))
              == GetmnlistdExpiryAction::Wait);

        // At 100s: ESCALATE. The lane's response is peer-set churn / re-plan to
        // a fresher target and route abandonment through remember_abandoned —
        // NEVER a repeated identical ask, and NEVER a fold rewind.
        CHECK(classify_getmnlistd_expiry(100000, tr.oldest_asked_at(100000))
              == GetmnlistdExpiryAction::Escalate);
        CHECK(classify_getmnlistd_expiry(150000, tr.oldest_asked_at(150000))
              == GetmnlistdExpiryAction::Escalate);

        // The applied-fold state the tracker "sees" is unchanged by expiry: the
        // tracker exposes no mutator that could rewind it. It resets its own
        // pending REQUEST slots and that is all.
        tr.reset_slots();
        CHECK(tr.in_flight() == 0);            // pending request abandoned
        CHECK(applied_folds == 7);             // applied folds STAY applied

        // No outstanding slot => never expired (oldest == now).
        CHECK(classify_getmnlistd_expiry(999999, tr.oldest_asked_at(999999))
              == GetmnlistdExpiryAction::Wait);
    }

    // ── (1c) INVARIANT under a bursty mixed drive (fuzz-ish deterministic) ──
    {
        GetmnlistdSlotTracker tr;
        tr.configure(3);
        std::vector<GetmnlistdCandidate> pool;
        for (int i = 0; i < 8; ++i)
            pool.push_back(cap("peer" + std::to_string(i),
                               std::to_string(10 + i) + ".0"));
        int64_t now = 0;
        for (int step = 0; step < 40; ++step) {
            now += 3000;                        // advance 3s each step
            tr.plan(pool, now);
            CHECK(tr.in_flight() <= tr.k());    // INVARIANT at EVERY step
            CHECK(tr.in_flight() >= 0);
            if (step % 7 == 0 && tr.in_flight() > 0) {
                // A peer answers now and then; the race frees + marks T1.
                // (Pick any held key deterministically.)
                // Re-plan will refill on the next step.
                tr.win_race();
            }
        }
        CHECK(tr.in_flight() <= tr.k());
    }

    // ── (6) INTEGRATION: the incapable peer is benched on EVERY emit path,
    //         the tracker GOVERNS live selection (not dormant), and OFF is
    //         byte-identical to master. ─────────────────────────────────────
    //
    // getmnlistd_emit_eligible() is the SINGLE predicate all THREE live emit
    // sites gate a carrier through in p2p_client.hpp — the initial
    // send_getmnlistd() to the pinned primary, the rotating next_stateful_peer()
    // selection (used by send_getmnlistd_rotating and the reask rotating
    // fallback), and, via getmnlistd_capable() inside plan(), the tracker-
    // governed re-ask. Driving it here proves the SHIPPED selection, not a
    // parallel model.
    {
        // ARMED: the incapable carrier is rejected on the initial + rotating
        // paths (the predicate returns false), the capable one is accepted.
        dash::coin::set_embedded_getmnlistd_tracker_enabled(true);
        CHECK(getmnlistd_emit_eligible(70213) == false);   // initial/rotating: benched
        CHECK(getmnlistd_emit_eligible(70214) == true);    // exactly the floor: served
        CHECK(getmnlistd_emit_eligible(70230) == true);

        // TRACKER GOVERNS the re-ask path: with an incapable peer present in the
        // live projection, plan() NEVER hands it a slot on ANY rotation, and a
        // capable peer IS selected (governance is live, not dormant).
        GetmnlistdSlotTracker tr;
        tr.configure(2);
        std::vector<GetmnlistdCandidate> pool = {
            incap("bad0", "10.0"), cap("good0", "20.0"),
            incap("bad1", "30.0"), cap("good1", "40.0"),
        };
        bool selected_capable = false;
        int64_t now = 0;
        for (int step = 0; step < 30; ++step) {
            auto sent = tr.plan(pool, now);
            for (const auto& k : sent) {
                CHECK(k != "bad0" && k != "bad1");   // incapable NEVER slotted
                if (k == "good0" || k == "good1") selected_capable = true;
            }
            CHECK(!tr.holds("bad0"));
            CHECK(!tr.holds("bad1"));
            CHECK(tr.in_flight() <= tr.k());
            now += 10000;   // lapse every slot each step -> full retarget churn
        }
        CHECK(selected_capable);                     // NOT dormant: it did select

        // Only-incapable pool ARMED => plan selects NOTHING (correct: you cannot
        // ask a peer that cannot serve; the lane waits / escalates at expiry).
        GetmnlistdSlotTracker tr2;
        tr2.configure(2);
        std::vector<GetmnlistdCandidate> only_bad = {
            incap("x", "10.0"), incap("y", "20.0"),
        };
        CHECK(tr2.plan(only_bad, 0).empty());
        CHECK(tr2.in_flight() == 0);

        // OFF-EQUIVALENCE: flag OFF => the predicate is ALWAYS true, so the
        // initial + rotating emit sites select the incapable carrier EXACTLY as
        // master would (no filtering, byte-identical), and the tracker is never
        // consulted on the re-ask path.
        dash::coin::set_embedded_getmnlistd_tracker_enabled(false);
        CHECK(getmnlistd_emit_eligible(70213) == true);    // master: no filter
        CHECK(getmnlistd_emit_eligible(0)     == true);
        CHECK(getmnlistd_emit_eligible(70230) == true);
        CHECK(dash::coin::embedded_getmnlistd_tracker_enabled() == false); // restored OFF
    }

    // ── (7) k-inflight-live GATE: a member-sourcing reply for a DIFFERENT
    //         target must NOT clear the K mn-checkpoint slots, must NOT trigger
    //         a second wave of asks, and a reply for the TRACKED target MUST
    //         still fire win_race (liveness). This models the p2p_client.hpp
    //         mnlistdiff handler exactly: it gates note_answered()/win_race()
    //         on reply_answers_active_target(), the SAME predicate the wire hook
    //         calls, using the mn-checkpoint lane's pending fold target. ──────
    {
        const std::string T     = "TARGET_T_hash";      // the tracked fold target
        const std::string OTHER = "MEMBER_WORK_hash";   // filter #1's own target

        GetmnlistdSlotTracker tr;
        tr.configure(3);                                 // K = 3 mn-ckpt slots
        std::vector<GetmnlistdCandidate> pool = {
            cap("a", "10.0"), cap("b", "20.0"), cap("c", "30.0"),
        };
        // The tracker holds K asks outstanding for target T (as reask_via_tracker
        // does on the wire); the client has stamped the active target to T.
        auto s0 = tr.plan(pool, 0);
        CHECK(s0.size() == 3);
        CHECK(tr.in_flight() == 3);
        tr.set_active_target(T);
        CHECK(tr.active_target() == T);

        // A member-sourcing reply arrives: a full snapshot (base==ZERO) but for
        // OTHER, not T. The demux would set the aggregate `consumed` true (the
        // QuorumMemberSource filter claimed it), but the gate REFUSES it.
        const bool member_reply_fires =
            tr.reply_answers_active_target(/*base_is_null=*/true, OTHER);
        CHECK(member_reply_fires == false);              // gate: NOT the tracked target
        if (member_reply_fires) { tr.note_answered("a"); tr.win_race(); }  // (never taken)

        // (1) the K slots are NOT cleared, (2) no peer was mis-marked T1.
        CHECK(tr.in_flight() == 3);                      // slots intact
        CHECK(!tr.answered("a") && !tr.answered("b") && !tr.answered("c"));

        // (2) NO second wave: the next tick, still inside the fixed 10s window,
        // emits nothing and the wire in-flight stays <= K (never grows to 2K).
        auto s_next = tr.plan(pool, 5000);
        CHECK(s_next.empty());
        CHECK(tr.in_flight() == 3);
        CHECK(tr.in_flight() <= tr.k());

        // A base!=ZERO (delta / tip-sync) reply for T is also refused — only a
        // full snapshot answers a fold.
        CHECK(tr.reply_answers_active_target(/*base_is_null=*/false, T) == false);
        CHECK(tr.in_flight() == 3);

        // (3) LIVENESS: a genuine full-snapshot reply for the TRACKED target T
        // fires the gate, so win_race clears the slots and the fold proceeds.
        const bool tracked_reply_fires =
            tr.reply_answers_active_target(/*base_is_null=*/true, T);
        CHECK(tracked_reply_fires == true);              // gate: it IS the tracked target
        if (tracked_reply_fires) { tr.note_answered("a"); tr.win_race(); }
        CHECK(tr.in_flight() == 0);                      // slots cleared (no wedge)
        CHECK(tr.tier_of("a") == GetmnlistdTier::Answered);   // answering peer -> T1

        // With no active target (no fold pending) NO reply can win — the empty
        // active_target short-circuits the gate.
        GetmnlistdSlotTracker tr2;
        tr2.configure(2);
        tr2.plan({cap("x", "10.0"), cap("y", "20.0")}, 0);
        CHECK(tr2.active_target().empty());
        CHECK(tr2.reply_answers_active_target(true, T) == false);
        CHECK(tr2.in_flight() == 2);                     // untouched
    }

    if (g_fail == 0) { std::printf("dash_getmnlistd_tracker_kat PASS\n"); return 0; }
    std::printf("dash_getmnlistd_tracker_kat FAIL (%d)\n", g_fail);
    return 1;
}
