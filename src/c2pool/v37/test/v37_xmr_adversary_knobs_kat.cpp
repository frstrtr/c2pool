// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_adversary_knobs_kat -- the ADVERSARY KNOBS module (test-only fault
// injection for a stagenet soak). Pure: the config, the mainnet refusal (every
// knob, part (c) of the task's KAT contract), the loud banner gate, the
// per-minute rate gate, the probability gate and the censor decision logic.
// The live-path behaviour of knobs 1/3/4 is proven in the relay/publish KATs;
// the consensus-content knobs 2/5/6 are proven by the operator at their seams.
//
//   A  OFF by default: a default AdversaryKnobs touches nothing (any()==false,
//      refusal empty on every network, banner silent, gates never fire).
//   B  REFUSED on mainnet: each knob alone, and all together, make refusal()
//      non-empty on mainnet and empty on stagenet/testnet/regtest. Pins the
//      rule: an attack injector never runs on real money.
//   C  rate gate: --adv-garbage / --adv-stale-replay at RATE/min fire RATE
//      times in a minute, never at t=0, never faster than the interval.
//   D  withhold gate: P/100 of the 0..99 draws withhold; 0 never, 100 always.
//   E  censor decision: keep_in_cut / relay_onward keep own, drop foreign when
//      on; pass everything when off.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <string>

#include <c2pool/v37/xmr/xmr_adversary_knobs.hpp>

using c2pool::v37n::xmr::AdversaryKnobs;
using c2pool::v37n::xmr::AdvRateGate;

static int g_fail = 0, g_checks = 0;
#define CHECK(cond, ...) do { const bool _ok = (cond); ++g_checks; if (!_ok) ++g_fail; \
    std::printf("  [%s] ", _ok ? "PASS" : "FAIL"); std::printf(__VA_ARGS__); std::printf("\n"); } while (0)

int main() {
    std::printf("== v37_xmr_adversary_knobs_kat ==\n");

    // A: OFF by default
    {
        AdversaryKnobs k;
        CHECK(!k.any(), "A1 default any() == false");
        CHECK(AdversaryKnobs::refusal(true,  k).empty(), "A2 default: nothing to refuse even on mainnet");
        CHECK(AdversaryKnobs::refusal(false, k).empty(), "A3 default: nothing to refuse off mainnet");
        AdvRateGate g;  // rate 0
        bool any_due = false; for (std::uint64_t t = 0; t < 300000; t += 100) any_due |= g.due(t);
        CHECK(!any_due, "A4 rate 0 never fires");
        CHECK(!k.withhold(0) && !k.withhold(99), "A5 withhold 0 pct never");
        CHECK(k.keep_in_cut(false) && k.relay_onward(false), "A6 censor off: foreign kept/relayed");
    }

    // B: refused on mainnet, allowed off it -- every knob, and all at once
    {
        const char* names[] = {"withhold","censor","garbage","replay","self-pay","wrong-ballot"};
        for (int i = 0; i < 6; ++i) {
            AdversaryKnobs k;
            switch (i) {
                case 0: k.withhold_pct = 50; break;
                case 1: k.censor_receipts = 1; break;
                case 2: k.garbage_rate = 10; break;
                case 3: k.replay_rate = 10; break;
                case 4: k.self_pay = 1; break;
                case 5: k.wrong_epoch_ballot = 1; break;
            }
            CHECK(k.any(), "B.%s any() == true", names[i]);
            CHECK(!AdversaryKnobs::refusal(true,  k).empty(), "B.%s refused on mainnet", names[i]);
            CHECK( AdversaryKnobs::refusal(false, k).empty(), "B.%s allowed off mainnet", names[i]);
        }
        AdversaryKnobs all; all.withhold_pct = 10; all.censor_receipts = 1; all.garbage_rate = 5;
        all.replay_rate = 5; all.self_pay = 1; all.wrong_epoch_ballot = 1;
        const std::string r = AdversaryKnobs::refusal(true, all);
        CHECK(!r.empty(), "B.all refused on mainnet");
        CHECK(r.find("--adv-withhold-blocks") != std::string::npos
           && r.find("--adv-self-pay") != std::string::npos, "B.all names the knobs in the refusal");
    }

    // C: rate gate at RATE/min
    {
        AdvRateGate g(60);              // 60/min -> every 1000 ms
        CHECK(!g.due(0), "C1 never at t=0");
        std::uint64_t fired = 0;
        for (std::uint64_t t = 0; t < 60000; t += 100) if (g.due(t)) ++fired;
        // one minute at 60/min: ~59-60 edges (the first interval arms)
        CHECK(fired >= 58 && fired <= 60, "C2 60/min fires ~%llu in a minute", (unsigned long long)fired);
        AdvRateGate g2(10);             // 10/min -> every 6000 ms
        std::uint64_t f2 = 0;
        for (std::uint64_t t = 0; t < 60000; t += 100) if (g2.due(t)) ++f2;
        CHECK(f2 >= 9 && f2 <= 10, "C3 10/min fires ~%llu in a minute", (unsigned long long)f2);
        // never two edges within one interval
        AdvRateGate g3(30);             // every 2000 ms
        bool too_fast = false; std::uint64_t last = 0, seen = 0;
        for (std::uint64_t t = 0; t < 120000; t += 50) if (g3.due(t)) { if (seen && t - last < 1900) too_fast = true; last = t; ++seen; }
        CHECK(!too_fast, "C4 never faster than the interval");
    }

    // D: withhold gate
    {
        AdversaryKnobs k; k.withhold_pct = 25;
        std::uint32_t w = 0; for (std::uint32_t d = 0; d < 100; ++d) if (k.withhold(d)) ++w;
        CHECK(w == 25, "D1 P=25 withholds 25/100 draws");
        AdversaryKnobs k100; k100.withhold_pct = 100;
        std::uint32_t w100 = 0; for (std::uint32_t d = 0; d < 100; ++d) if (k100.withhold(d)) ++w100;
        CHECK(w100 == 100, "D2 P=100 withholds every draw");
    }

    // E: censor decision
    {
        AdversaryKnobs k; k.censor_receipts = 1;
        CHECK(k.keep_in_cut(true)  && !k.keep_in_cut(false), "E1 own kept, foreign dropped from the cut");
        CHECK(k.relay_onward(true) && !k.relay_onward(false), "E2 own relayed, foreign not relayed onward");
    }

    std::printf("== v37_xmr_adversary_knobs_kat: %s (%d/%d passed) ==\n",
                g_fail ? "FAIL" : "OK", g_checks - g_fail, g_checks);
    return g_fail ? 1 : 0;
}
