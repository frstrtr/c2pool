// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_prefer_own_race_kat.cpp
//
// c2pool#1551 -- THE SAME-HEIGHT DOUBLE-BLOCK REFUSAL, DECIDED PREFER-OWN
// WITHIN BOUNDS. The decision table, pinned.
//
// Two Monero blocks at one parent height, one of them carrying our K_fair
// settlement coinbase. The rule is that every lever WE control is biased toward
// our own block, and that the bias stops dead at the chain: credit follows
// burial and canonicality, never preference.
//
// THE TABLE THIS FILE PINS
//
//   own  other  buried  ours canonical | verdict            credit
//   ---  -----  ------  --------------- ------------------  ------
//    0     0      -           -         no-candidate        none
//    0    >=1     -           -         other-only          none   <- an aux
//                                                                     block
//                                                                     settles
//                                                                     us
//                                                                     nothing
//   >=1    *     no           -         defer-unburied      none   <- THE
//                                                                     REFUSAL
//   >=1    *     yes         yes        credit-own          ours
//   >=1    *     yes         no         refuse-orphaned     none   <- NO
//                                                                     orphan
//                                                                     credit
//    *     *      *           *         already-credited    frozen <- R-7
//
// AND THE PROPERTY THAT MAKES THE BOUNDS REAL. Suite B runs the SAME fixture
// under both tie-break policies and asserts the VERDICTS are identical while
// the NOMINATIONS differ. That is what "prefer-own never buys credit" means as
// something checkable rather than as a sentence in a header: the policy moves
// the lever and cannot reach the ledger.
//
// Suites:
//   A  credit_rule() -- the table as a pure function, exhaustively
//   B  SameHeightRaceLedger -- observation, nomination, policy-independence
//   C  R-7 -- one credit per height, frozen against a later reorg
//   D  the bounded prefer-own re-announce (lever (2)) and where it refuses
//   E  END TO END through XmrNode + FinalizeConnect on a pumped native chain:
//      ours-wins credits, ours-orphaned does NOT, other-only does NOT, and the
//      R-7 cross-check between the finalize driver and the gate stays at zero
//   F  MULTI-NODE convergence: two nodes, each holding its OWN candidate at the
//      same contested height, agree on which block the chain kept -- the winner
//      credits once, the loser fabricates nothing, and the fleet-wide credited
//      set has exactly one entry at that height
//
// No sockets, no RandomX, no live daemon: builds and runs on BOTH build.yml
// legs, which is also why it is listed in both --target lists -- a
// registered-but-unbuilt target reads as "***Not Run" and fails ctest with exit
// 8 (the #1539 lesson).
// ===========================================================================
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <map>
#include <string>
#include <unistd.h>
#include <vector>

#include "c2pool/v37/xmr/xmr_node.hpp"
#include "c2pool/v37/xmr/xmr_node_config.hpp"
#include "c2pool/v37/xmr/xmr_o2_finalize_connect.hpp"
#include "c2pool/v37/xmr/xmr_same_height_race.hpp"
#include "impl/xmr/node/monerod_transport.hpp"

using namespace c2pool::v37n::xmr;
namespace node = ::c2pool::xmr::node;

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------
static int g_pass = 0, g_fail = 0;

static void check(bool ok, const std::string& what, const std::string& detail = {}) {
    if (ok) {
        ++g_pass;
        std::printf("  [ok]   %s\n", what.c_str());
        return;
    }
    ++g_fail;
    std::printf("  [FAIL] %s%s%s\n", what.c_str(), detail.empty() ? "" : " -- ", detail.c_str());
}

static bool test_point_check(const std::uint8_t* pt) {
    for (int i = 0; i < 32; ++i)
        if (pt[i] != 0) return true;
    return false;
}

static node::Hash blk_id(std::uint8_t b) {
    node::Hash h{};
    for (int i = 0; i < 32; ++i) h[i] = static_cast<std::uint8_t>(b + i);
    return h;
}
static std::string bid_of(std::uint8_t b) { return hex_of(blk_id(b)); }

static ::v37::bytes32 key_of(std::uint8_t b) {
    ::v37::bytes32 k{};
    for (int i = 0; i < 32; ++i) k[i] = static_cast<std::uint8_t>(b + 3 * i + 1);
    return k;
}

// A canonical predicate over a plain height -> id map, the same shape
// native_chain_source() binds to the running index.
struct FakeChain {
    std::map<std::uint64_t, std::string> at;
    SameHeightRaceLedger::CanonicalFn fn() const {
        return [this](std::uint64_t h, const std::string& bid) {
            const auto it = at.find(h);
            return it != at.end() && it->second == bid;
        };
    }
};

// ===========================================================================
// A -- the table as a pure function
// ===========================================================================
static void suite_a() {
    std::printf("A: credit_rule() -- the decision table, exhaustively\n");

    // Row 1: nothing known.
    check(credit_rule(0, 0, false, false, false) == RaceVerdict::NoCandidate,
          "A1 no candidates at all -> no-candidate");
    check(credit_rule(0, 0, false, true, false) == RaceVerdict::NoCandidate,
          "A2 burial does not invent a candidate");

    // Row 2: only a stranger's block. An aux block settles our ledger nothing.
    check(credit_rule(0, 1, false, false, false) == RaceVerdict::OtherOnly,
          "A3 other-only, unburied -> other-only (no credit)");
    check(credit_rule(0, 3, false, true, false) == RaceVerdict::OtherOnly,
          "A4 other-only, BURIED -> still other-only: burying a stranger's block "
          "does not pay us");

    // Row 3: THE REFUSAL. We hold a candidate, the height is not yet buried.
    check(credit_rule(1, 0, false, false, true) == RaceVerdict::DeferUnburied,
          "A5 ours, unburied, and already canonical -> DEFER (canonical is not buried)");
    check(credit_rule(1, 1, false, false, false) == RaceVerdict::DeferUnburied,
          "A6 same-height double block, unburied -> DEFER: credit nobody yet");
    check(credit_rule(2, 2, false, false, true) == RaceVerdict::DeferUnburied,
          "A7 a four-way contest, unburied -> DEFER");

    // Row 4: buried and ours.
    check(credit_rule(1, 0, false, true, true) == RaceVerdict::CreditOwn,
          "A8 ours, buried, canonical -> CREDIT OURS");
    check(credit_rule(1, 5, false, true, true) == RaceVerdict::CreditOwn,
          "A9 ours wins a crowded height once buried -> CREDIT OURS");

    // Row 5: buried and NOT ours. Bound (a) and bound (b) in one row.
    check(credit_rule(1, 1, false, true, false) == RaceVerdict::RefuseOrphaned,
          "A10 ours ORPHANED by the network, buried -> NO CREDIT (bound a: we cannot "
          "override Monero consensus)");
    check(credit_rule(3, 0, false, true, false) == RaceVerdict::RefuseOrphaned,
          "A11 three of our own at one height, none canonical -> NO CREDIT");

    // Row 6: R-7 dominates every other row.
    for (int own = 0; own <= 2; ++own)
        for (int oth = 0; oth <= 2; ++oth)
            for (int b = 0; b <= 1; ++b)
                for (int c = 0; c <= 1; ++c)
                    if (credit_rule(static_cast<std::size_t>(own), static_cast<std::size_t>(oth),
                                    true, b != 0, c != 0) != RaceVerdict::AlreadyCredited) {
                        check(false, "A12 already-credited dominates every row");
                        return;
                    }
    check(true, "A12 already-credited dominates every row (24 combinations)");

    // Exactly one verdict authorises a credit.
    int crediting = 0;
    for (std::uint8_t v = 0; v <= 5; ++v)
        if (verdict_credits(static_cast<RaceVerdict>(v))) ++crediting;
    check(crediting == 1, "A13 exactly ONE of the six verdicts authorises a credit",
          "crediting=" + std::to_string(crediting));

    // The policy has no escape hatch.
    check(SameHeightPolicy::credit_requires_burial && !SameHeightPolicy::orphan_credit_allowed,
          "A14 the policy carries burial-required / no-orphan-credit as constants, not knobs");

    SameHeightTieBreak t = SameHeightTieBreak::FirstSeen;
    check(parse_tie_break("prefer-own", t) && t == SameHeightTieBreak::PreferOwn,
          "A15 --same-height-tiebreak prefer-own parses");
    check(parse_tie_break("first-seen", t) && t == SameHeightTieBreak::FirstSeen,
          "A16 --same-height-tiebreak first-seen parses");
    SameHeightTieBreak keep = SameHeightTieBreak::PreferOwn;
    check(!parse_tie_break("whatever", keep) && keep == SameHeightTieBreak::PreferOwn,
          "A17 an unknown spelling is REFUSED and leaves the setting alone");
}

// ===========================================================================
// B -- the ledger: observation, nomination, and policy-independence of credit
// ===========================================================================
static void suite_b() {
    std::printf("B: SameHeightRaceLedger -- the lever moves, the credit does not\n");

    const std::uint64_t H = 100, D = 3;
    const std::string OURS = bid_of(10), THEIRS = bid_of(20);

    FakeChain chain;

    // The rival is seen FIRST, so first-seen and prefer-own disagree about the
    // nomination. That disagreement is the whole point of the fixture.
    auto build = [&](SameHeightTieBreak tie) {
        SameHeightPolicy p;
        p.tie_break = tie;
        p.d_conf    = D;
        SameHeightRaceLedger L(p);
        L.observe_other(H, THEIRS);
        L.observe_own(H, OURS);
        return L;
    };

    SameHeightRaceLedger own_biased   = build(SameHeightTieBreak::PreferOwn);
    SameHeightRaceLedger first_seen   = build(SameHeightTieBreak::FirstSeen);

    check(own_biased.contested_heights().size() == 1 &&
          own_biased.contested_heights()[0] == H,
          "B1 one own + one stranger at the same height IS a contest");
    check(own_biased.stats().own_vs_other_opened == 1 &&
          own_biased.stats().contests_opened == 1,
          "B2 the contest is counted ONCE when it opens, not once per look");

    // Re-observing does not re-count and does not re-label.
    own_biased.observe_other(H, OURS);      // our own block, echoed back by the chain
    own_biased.observe_own(H, OURS);
    check(own_biased.holds_own(H, OURS) &&
          own_biased.stats().contests_opened == 1,
          "B3 our own block echoed back as a chain block stays OURS, and re-counts nothing");

    // --- the lever -----------------------------------------------------
    {
        chain.at[H] = OURS;
        const RaceDecision a = own_biased.decide(H, H - 1, chain.fn());
        const RaceDecision b = first_seen.decide(H, H - 1, chain.fn());
        check(a.nomination.bid == OURS && a.nomination.is_own,
              "B4 prefer-own NOMINATES our block even though the rival was seen first");
        check(b.nomination.bid == THEIRS && !b.nomination.is_own,
              "B5 first-seen nominates the rival (the bias, turned off)");
        check(a.verdict == b.verdict && a.verdict == RaceVerdict::DeferUnburied,
              "B6 ... and BOTH policies refuse to credit while the height is unburied");
    }

    // --- policy-independence, across the whole burial walk -------------
    {
        bool same = true;
        std::string nom_diff_at;
        for (std::uint64_t hw = H - 2; hw <= H + D + 2; ++hw) {
            const RaceDecision a = own_biased.decide(H, hw, chain.fn());
            const RaceDecision b = first_seen.decide(H, hw, chain.fn());
            if (a.verdict != b.verdict || a.credit_bid != b.credit_bid) same = false;
            if (a.nomination.bid != b.nomination.bid) nom_diff_at = std::to_string(hw);
        }
        check(same, "B7 the CREDIT is byte-identical under both policies at every high-water");
        check(!nom_diff_at.empty(),
              "B8 ... while the NOMINATION differs (the lever is real, not decorative)");
    }

    // --- the burial bar -------------------------------------------------
    check(own_biased.decide(H, H + D - 1, chain.fn()).verdict == RaceVerdict::DeferUnburied,
          "B9 one block short of D_conf is still a refusal");
    {
        const RaceDecision d = own_biased.decide(H, H + D, chain.fn());
        check(d.verdict == RaceVerdict::CreditOwn && d.credit_bid == OURS,
              "B10 exactly at h + D_conf, with the chain carrying ours -> CREDIT OURS");
        check(d.need_hw == H + D, "B11 the decision reports the burial bar it used");
    }

    // --- bound (a): the chain kept the rival ---------------------------
    {
        FakeChain lost;
        lost.at[H] = THEIRS;
        const RaceDecision d = own_biased.decide(H, H + D + 10, lost.fn());
        check(d.verdict == RaceVerdict::RefuseOrphaned && d.credit_bid.empty(),
              "B12 the network buried the RIVAL -> no credit, and no bid on the decision");
        const RaceDecision e = first_seen.decide(H, H + D + 10, lost.fn());
        check(e.verdict == d.verdict,
              "B13 ... and prefer-own vs first-seen makes no difference to that either");
    }

    // --- other-only: an aux block at a height we never mined -----------
    {
        SameHeightRaceLedger L{SameHeightPolicy{SameHeightTieBreak::PreferOwn, 3, 3}};
        L.observe_other(200, bid_of(30));
        FakeChain c;
        c.at[200] = bid_of(30);
        const RaceDecision d = L.decide(200, 500, c.fn());
        check(d.verdict == RaceVerdict::OtherOnly && d.credit_bid.empty(),
              "B14 a stranger's block, buried a mile deep, credits us NOTHING");
        check(!d.nomination.is_own && d.nomination.bid == bid_of(30),
              "B15 ... and prefer-own nominates it anyway, because we hold nothing to prefer");
    }

    // --- the book is bounded -------------------------------------------
    {
        SameHeightRaceLedger L;
        for (std::uint64_t h = 1; h <= 50; ++h) L.observe_other(h, bid_of(static_cast<std::uint8_t>(h)));
        check(L.book_size() == 50, "B16 the book holds what it was told");
        L.prune_below(40);
        check(L.book_size() == 11, "B17 prune_below drops the heights beneath the floor",
              "size=" + std::to_string(L.book_size()));
    }

    // --- heights_of_interest: a lone stranger is not a race ------------
    {
        SameHeightRaceLedger L;
        L.observe_other(1, bid_of(1));                 // a plain chain block
        L.observe_other(2, bid_of(2));
        L.observe_other(2, bid_of(3));                 // a fork we are not in
        L.observe_own(3, bid_of(4));                   // ours, unopposed
        const auto hoi = L.heights_of_interest();
        check(hoi.size() == 2 && hoi[0] == 2 && hoi[1] == 3,
              "B18 the gate walks contests and our own heights, not every block ever seen",
              "n=" + std::to_string(hoi.size()));
    }

    // --- a malformed id never becomes a ledger key ---------------------
    {
        SameHeightRaceLedger L;
        check(!L.observe_own(7, "not-a-block-id") && L.book_size() == 0,
              "B19 a malformed block id is refused, not stored");
    }
}

// ===========================================================================
// C -- R-7: one credit per height, frozen
// ===========================================================================
static void suite_c() {
    std::printf("C: R-7 -- a height credits one block, once, and never moves it\n");

    const std::uint64_t H = 300, D = 3;
    const std::string OURS = bid_of(40), ALSO_OURS = bid_of(41), THEIRS = bid_of(42);

    SameHeightPolicy p;
    p.d_conf = D;
    SameHeightRaceLedger L(p);
    L.observe_own(H, OURS);
    L.observe_own(H, ALSO_OURS);     // two of our own at one height (regtest reality)
    L.observe_other(H, THEIRS);

    FakeChain chain;
    chain.at[H] = OURS;

    const RaceDecision d = L.decide(H, H + D, chain.fn());
    check(d.verdict == RaceVerdict::CreditOwn && d.credit_bid == OURS,
          "C1 among three candidates the chain picks one, and that is the one credited");
    check(d.own_candidates == 2 && d.other_candidates == 1,
          "C2 the decision reports the whole field it decided over");

    check(L.note_credited(H, OURS), "C3 the first credit at a height is recorded");
    check(!L.note_credited(H, OURS), "C4 the SAME credit again is BLOCKED (replay)");
    check(!L.note_credited(H, ALSO_OURS),
          "C5 a DIFFERENT block at the same height is BLOCKED (a reorg may not move a credit)");
    check(L.stats().double_credit_blocked == 2 && L.stats().credited == 1,
          "C6 the blocked attempts are counted, not silently dropped",
          "blocked=" + std::to_string(L.stats().double_credit_blocked));

    const RaceDecision after = L.decide(H, H + D + 100, chain.fn());
    check(after.verdict == RaceVerdict::AlreadyCredited && after.credit_bid == OURS,
          "C7 the height now answers already-credited, with the bid it actually credited");

    // A reorg that hands the height to the rival, AFTER we credited: the gate
    // still says already-credited. Undoing a settled credit is the merged
    // ledger's post-SETTLED residual rule (O3.5), not a second credit decision.
    FakeChain reorged;
    reorged.at[H] = THEIRS;
    const RaceDecision post = L.decide(H, H + D + 200, reorged.fn());
    check(post.verdict == RaceVerdict::AlreadyCredited,
          "C8 a post-credit reorg does not reopen the decision (O3.5 owns what happens next)");
    check(L.credited_at(H) && *L.credited_at(H) == OURS,
          "C9 the credit record survives the reorg unchanged");
}

// ===========================================================================
// D -- lever (2): the bounded re-announce
// ===========================================================================
static void suite_d() {
    std::printf("D: the prefer-own re-announce is a lever, and it is bounded\n");

    const std::uint64_t H = 400, D = 3;
    const std::string OURS = bid_of(50), THEIRS = bid_of(51);

    SameHeightPolicy p;
    p.d_conf       = D;
    p.max_renotify = 2;
    SameHeightRaceLedger L(p);
    L.observe_own(H, OURS);
    L.observe_other(H, THEIRS);

    FakeChain theirs;                 // the chain currently carries the rival
    theirs.at[H] = THEIRS;

    const RaceDecision d = L.decide(H, H, theirs.fn());
    check(d.verdict == RaceVerdict::DeferUnburied && d.own_vs_other,
          "D1 contested and unburied is where the lever applies");
    check(L.take_renotify(H, d, theirs.fn()), "D2 first re-announce granted");
    check(L.take_renotify(H, d, theirs.fn()), "D3 second re-announce granted");
    check(!L.take_renotify(H, d, theirs.fn()),
          "D4 the THIRD is refused: max_renotify bounds it (we do not DoS our own peers)");
    check(L.stats().renotify_requested == 2, "D5 the spend is counted");

    // Refusals, each for its own reason.
    {
        FakeChain ours;
        ours.at[H] = OURS;
        SameHeightRaceLedger M(p);
        M.observe_own(H, OURS);
        M.observe_other(H, THEIRS);
        const RaceDecision e = M.decide(H, H, ours.fn());
        check(!M.take_renotify(H, e, ours.fn()),
              "D6 no re-announce when the chain ALREADY carries our block");
    }
    {
        SameHeightPolicy off = p;
        off.tie_break = SameHeightTieBreak::FirstSeen;
        SameHeightRaceLedger M(off);
        M.observe_own(H, OURS);
        M.observe_other(H, THEIRS);
        const RaceDecision e = M.decide(H, H, theirs.fn());
        check(!M.take_renotify(H, e, theirs.fn()),
              "D7 with the bias OFF there is no lever to pull");
    }
    {
        SameHeightRaceLedger M(p);
        M.observe_own(H, OURS);       // unopposed
        const RaceDecision e = M.decide(H, H, theirs.fn());
        check(!M.take_renotify(H, e, theirs.fn()),
              "D8 an UNCONTESTED height is not a relay race: nothing to re-announce");
    }
    {
        SameHeightRaceLedger M(p);
        M.observe_own(H, OURS);
        M.observe_other(H, THEIRS);
        const RaceDecision e = M.decide(H, H + D + 1, theirs.fn());
        check(e.verdict == RaceVerdict::RefuseOrphaned && !M.take_renotify(H, e, theirs.fn()),
              "D9 once the height is BURIED the race is over -- re-announcing a block "
              "the network already rejected is noise");
    }
    {
        SameHeightPolicy zero = p;
        zero.max_renotify = 0;
        SameHeightRaceLedger M(zero);
        M.observe_own(H, OURS);
        M.observe_other(H, THEIRS);
        const RaceDecision e = M.decide(H, H, theirs.fn());
        check(!M.take_renotify(H, e, theirs.fn()),
              "D10 --same-height-renotify 0 turns the lever off entirely");
    }
}

// ===========================================================================
// E / F -- end to end through the real node + the real accounting glue
// ===========================================================================
namespace {

// One c2pool node, wired the way the daemon wires it under --arm-order
// p2p-first: no monerod adapter, the tip and the canonical test supplied by a
// chain the node verified itself (here, a map the test drives).
struct Rig {
    FakeChain                      chain;
    node::MockMonerodTransport     mock;
    XmrNodeConfig                  cfg;
    std::unique_ptr<XmrNode>       node;
    o2::FoundBlockQueue            q;
    std::unique_ptr<o2::FinalizeConnect> fc;

    Rig(const std::filesystem::path& dir, ::v37::ChainId lane, std::uint64_t d_conf,
        SameHeightTieBreak tie = SameHeightTieBreak::PreferOwn) {
        cfg.network              = MoneroNetwork::Stagenet;
        cfg.lane_chain           = lane;
        cfg.d_conf               = d_conf;
        cfg.settle_db_path       = dir.string();
        cfg.arm_order            = ArmOrderMode::P2PFirst;
        cfg.coinbase             = CoinbaseMode::V37Settlement;
        cfg.template_source      = TemplateSourceMode::Native;
        cfg.same_height_tiebreak = tie;
        cfg.native_connect.push_back("127.0.0.1:18080");
        std::filesystem::create_directories(dir);

        node = std::make_unique<XmrNode>(cfg, mock, &test_point_check);
        node->set_native_chain_presence([this](std::uint64_t h, const std::string& bid) {
            return this->chain.fn()(h, bid);
        });
        node->bring_up();

        o2::FinalizeConnectOptions o;
        o.out = nullptr;               // silent; the KAT asserts, it does not narrate
        fc = std::make_unique<o2::FinalizeConnect>(*node, cfg, q, o);
    }

    // Extend the chain to `h` carrying `id`, then let the accounting react --
    // the same two calls the daemon's main loop makes, in the same order.
    void extend(std::uint64_t h, const std::string& id_hex, const std::string& prev_hex) {
        chain.at[h] = id_hex;
        node::MainchainEvent ev;
        ev.kind = node::MainchainEventKind::Extend;
        ev.block.height = h;
        (void)o2::hash_from_hex(id_hex, ev.block.id);
        (void)o2::hash_from_hex(prev_hex, ev.block.prev_id);
        node->pump_mainchain_event(ev);
        fc->tick();
    }

    void walk(std::uint64_t from, std::uint64_t to) {
        for (std::uint64_t h = from; h <= to; ++h)
            extend(h, bid_of(static_cast<std::uint8_t>(h)), bid_of(static_cast<std::uint8_t>(h - 1)));
    }

    // A block WE found at `h`, through the same queue the stratum sink pushes.
    void found(std::uint64_t h, const std::string& id_hex, std::uint64_t reward,
               const ::v37::bytes32& payee) {
        o2::FoundBlockEvent e;
        e.height          = h;
        e.block_id_hex    = id_hex;
        e.reward_piconero = reward;
        e.payee           = payee;
        q.push(e);
        fc->tick();
    }
};

} // namespace

static void suite_e(const std::filesystem::path& root) {
    std::printf("E: end to end -- the chain decides, the gate agrees, nothing is fabricated\n");

    const std::uint64_t D = 3;
    const std::uint64_t REWARD = 600000000000ull;
    const ::v37::bytes32 PAYEE = key_of(0xC5);

    // ── E1: ours wins ──────────────────────────────────────────────────
    {
        Rig r(root / "e1", 11, D);
        r.walk(1, 9);

        const std::uint64_t H = 10;
        const std::string OURS = bid_of(10), RIVAL = bid_of(90);

        r.found(H, OURS, REWARD, PAYEE);
        check(r.node->ledger().is_pending(OURS), "E1a our block is pending in the ledger");
        check(r.node->ledger().effective_owed(PAYEE) == -static_cast<long long>(REWARD),
              "E1b amount-honest while pending");

        // The rival exists -- held in the alt pool, never adopted. This is the
        // branch an event-stream-only accounting layer is blind in.
        r.fc->observe_alt_tips({o2::FinalizeConnect::AltObservation{H, RIVAL, false}});

        r.extend(H, OURS, bid_of(9));
        {
            const auto d = r.fc->race().decide(H, r.node->hw().hw_height, r.chain.fn());
            check(d.own_vs_other && d.contested,
                  "E1c the height is seen as CONTESTED even though the rival never became our tip");
            check(d.verdict == RaceVerdict::DeferUnburied,
                  "E1d unburied -> the double-block refusal holds, for both blocks");
            check(d.nomination.bid == OURS && d.nomination.is_own,
                  "E1e prefer-own nominates ours");
        }
        check(r.fc->race().credited().empty(), "E1f nothing credited before burial");

        r.walk(H + 1, H + D);
        check(r.node->ledger().is_settled(OURS), "E1g at h + D_conf the driver SETTLES our block");
        check(r.node->ledger().effective_owed(PAYEE) == 0, "E1h finalW nets to 0");
        check(r.fc->stats().race_credited == 1 && r.fc->stats().r7_violations == 0,
              "E1i the gate independently authorised that credit (R-7 violations = 0)",
              "credited=" + std::to_string(r.fc->stats().race_credited) +
              " r7=" + std::to_string(r.fc->stats().r7_violations));
        const auto* cr = r.fc->race().credited_at(H);
        check(cr && *cr == OURS, "E1j the credited block at that height is OURS, by id");
        check(r.fc->race().credited().size() == 1,
              "E1k exactly one height credited in the whole run");
    }

    // ── E2: ours is orphaned -- bound (a) and bound (b) ────────────────
    {
        Rig r(root / "e2", 12, D);
        r.walk(1, 9);

        const std::uint64_t H = 10;
        const std::string OURS = bid_of(10), THEIRS = bid_of(80);

        r.found(H, OURS, REWARD, PAYEE);
        check(r.node->ledger().is_pending(OURS), "E2a our block registers as a FOUND");

        // Monero keeps the OTHER block at this height. Nothing we can do.
        r.extend(H, THEIRS, bid_of(9));
        {
            const auto d = r.fc->race().decide(H, r.node->hw().hw_height, r.chain.fn());
            check(d.own_vs_other, "E2b the rival arrived on the chain: contested, own-vs-other");
            check(d.verdict == RaceVerdict::DeferUnburied,
                  "E2c still unburied -> still refusing, even though we are already losing");
            check(d.nomination.is_own,
                  "E2d prefer-own still nominates ours -- nominating is not crediting");
        }

        r.walk(H + 1, H + D + 2);
        check(!r.node->ledger().is_settled(OURS),
              "E2e our orphaned block is NEVER settled");
        check(!r.node->ledger().is_pending(OURS),
              "E2f ... and it left the pending set (O3.5 disposition)");
        check(r.node->ledger().effective_owed(PAYEE) == 0,
              "E2g the payee is back to zero: no phantom entitlement survives the orphan");
        {
            const auto d = r.fc->race().decide(H, r.node->hw().hw_height, r.chain.fn());
            check(d.verdict == RaceVerdict::RefuseOrphaned,
                  "E2h buried, and the chain kept theirs -> REFUSE ORPHANED");
            check(d.credit_bid.empty(), "E2i a refusal carries no bid to credit");
        }
        check(r.fc->race().credited().empty() && r.fc->stats().race_credited == 0,
              "E2j NO credit was fabricated for our orphaned block (no orphan-credit)");
        check(r.fc->stats().r7_violations == 0,
              "E2k and no R-7 violation: the driver and the gate agreed to refuse");
        check(r.fc->stats().race_refused_orphaned >= 1,
              "E2l the refusal is counted, so a run can be audited for it");
    }

    // ── E3: a height that was never ours ───────────────────────────────
    {
        Rig r(root / "e3", 13, D);
        r.walk(1, 5);
        const std::uint64_t H = 6;
        // Two strangers fork at H. We hold nothing. One of them gets buried.
        r.fc->observe_alt_tips({o2::FinalizeConnect::AltObservation{H, bid_of(70), false}});
        r.extend(H, bid_of(6), bid_of(5));
        r.walk(H + 1, H + D + 1);
        const auto d = r.fc->race().decide(H, r.node->hw().hw_height, r.chain.fn());
        check(d.verdict == RaceVerdict::OtherOnly && d.credit_bid.empty(),
              "E3a a fork we were not in credits us NOTHING, however deeply buried");
        check(r.fc->race().credited().empty() && r.fc->stats().r7_violations == 0,
              "E3b nothing credited, nothing violated");
    }
}

static void suite_f(const std::filesystem::path& root) {
    std::printf("F: MULTI-NODE -- two nodes, one contested height, one credit in the fleet\n");

    const std::uint64_t D = 3;
    const std::uint64_t REWARD = 600000000000ull;
    const ::v37::bytes32 PAYEE_A = key_of(0xA1);
    const ::v37::bytes32 PAYEE_B = key_of(0xB2);

    const std::uint64_t H = 10;
    const std::string A_BLOCK = bid_of(10);    // node A's own settlement block
    const std::string B_BLOCK = bid_of(60);    // node B's own settlement block, same height

    // Two independent nodes, independent settlement stores, independent race
    // books -- exactly as two hosts would be. They are handed the SAME chain
    // history, which is what "the network resolved the fork" looks like from
    // inside each of them.
    Rig A(root / "f_a", 21, D);
    Rig B(root / "f_b", 22, D);
    A.walk(1, 9);
    B.walk(1, 9);

    // Each node finds ITS OWN block at the same height: the real multi-node
    // race, not a simulated one.
    A.found(H, A_BLOCK, REWARD, PAYEE_A);
    B.found(H, B_BLOCK, REWARD, PAYEE_B);

    // Each node also learns of the other's block -- A holds B's in its alt pool
    // and vice versa. Until the fork resolves, both nodes are contested.
    A.fc->observe_alt_tips({o2::FinalizeConnect::AltObservation{H, B_BLOCK, false}});
    B.fc->observe_alt_tips({o2::FinalizeConnect::AltObservation{H, A_BLOCK, false}});

    check(A.fc->race().contested_heights().size() == 1 &&
          B.fc->race().contested_heights().size() == 1,
          "F1 both nodes see the same height as contested");

    // The network resolves it: A's block is the one that gets built on. B
    // reorgs onto it -- and B's own block becomes the orphan.
    A.extend(H, A_BLOCK, bid_of(9));
    B.extend(H, A_BLOCK, bid_of(9));
    {
        const auto da = A.fc->race().decide(H, A.node->hw().hw_height, A.chain.fn());
        const auto db = B.fc->race().decide(H, B.node->hw().hw_height, B.chain.fn());
        check(da.verdict == RaceVerdict::DeferUnburied && db.verdict == RaceVerdict::DeferUnburied,
              "F2 both nodes refuse to credit anybody while the height is unburied");
        check(da.nomination.bid == A_BLOCK && db.nomination.bid == B_BLOCK,
              "F3 each node nominates ITS OWN block -- prefer-own is a local preference, "
              "and local preferences are allowed to disagree");
    }

    A.walk(H + 1, H + D);
    B.walk(H + 1, H + D);

    // --- the convergence claim -----------------------------------------
    check(A.node->ledger().is_settled(A_BLOCK), "F4 the WINNER credits its own block");
    check(!B.node->ledger().is_settled(B_BLOCK), "F5 the LOSER never settles its own block");
    check(!B.node->ledger().is_pending(B_BLOCK), "F6 ... and disposes of it (O3.5)");
    check(B.node->ledger().effective_owed(PAYEE_B) == 0,
          "F7 the loser's payee keeps no phantom entitlement");
    check(A.node->ledger().effective_owed(PAYEE_A) == 0,
          "F8 the winner's finalW nets to 0");

    const auto ca = A.fc->race().credited();
    const auto cb = B.fc->race().credited();
    check(ca.size() == 1 && ca.count(H) && ca.at(H) == A_BLOCK,
          "F9 node A's credited map: exactly {h -> the block the chain kept}");
    check(cb.empty(), "F10 node B credited NOTHING -- it fabricated no credit for its orphan");

    // Both nodes agree about the chain, which is the thing they must agree on:
    // the same block is canonical at the contested height on both.
    check(A.chain.fn()(H, A_BLOCK) && B.chain.fn()(H, A_BLOCK),
          "F11 both nodes agree which block the chain carries at the contested height");

    // The fleet-wide credited set: one height, one block, one credit.
    std::map<std::uint64_t, std::string> fleet = ca;
    for (const auto& kv : cb) fleet[kv.first] = kv.second;
    check(fleet.size() == 1 && fleet.at(H) == A_BLOCK,
          "F12 across the fleet the height is credited ONCE, to the block Monero buried");

    check(A.fc->stats().r7_violations == 0 && B.fc->stats().r7_violations == 0,
          "F13 neither node's finalize driver outran its own same-height gate");
    check(B.fc->stats().race_refused_orphaned >= 1,
          "F14 the loser's refusal is on the record, not merely absent");

    // And the journal shape both nodes would have written can be compared directly.
    const auto da = A.fc->race().decide(H, A.node->hw().hw_height, A.chain.fn());
    const std::string line = race_journal_line(da, A.node->hw().hw_height);
    check(line.find("h=" + std::to_string(H)) != std::string::npos &&
          line.find("verdict=already-credited") != std::string::npos,
          "F15 the journal line names the height and the verdict", line);
}

// ===========================================================================
int main() {
    std::printf("== v37_xmr_prefer_own_race_kat: c2pool#1551 same-height prefer-own, bounded ==\n");

    const std::filesystem::path root =
        std::filesystem::temp_directory_path() /
        ("v37-xmr-race-" + std::to_string(static_cast<long>(::getpid())));
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    suite_a();
    suite_b();
    suite_c();
    suite_d();
    try {
        suite_e(root);
        suite_f(root);
    } catch (const std::exception& e) {
        check(false, "E/F bring-up", e.what());
    }

    std::filesystem::remove_all(root);

    std::printf("== %s: %d passed, %d failed ==\n", g_fail ? "FAIL" : "OK", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
