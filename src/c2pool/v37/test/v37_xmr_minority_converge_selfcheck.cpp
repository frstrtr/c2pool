// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_minority_converge_selfcheck.cpp
//   (D2, operator ruling D2 = A: minority converges to majority)
//
// The PURE pieces of xmr/xmr_minority_converge.hpp, no node, no network:
//   MC1  builder_key: one GAP-2 base -> one key; two bases -> two keys; no
//        relay (counter from 0) -> every node on key 0 (detection unavailable);
//   MC2  the detection rule: one unmatched foreign block, or M from ONE
//        builder, never detects; M from 2 builders with own blocks
//        interleaved does; a matched foreign block resets the run; undecided
//        never counts; the trailing-matched exit;
//   MC3  refold is EXACT: a node that credited its own isolated block X and a
//        control that refused it; refold(prefix, R = {X}) reproduces the
//        control's (digest, since) sequence at EVERY state -- driven through
//        the production XmrFinalizeDriver + OwedLedger + MemSettleStore;
//   MC4  refold credits the majority blocks the minority refused (their roots
//        commit states only the re-derived lineage holds), refuses the
//        minority's own later block (its root is minority-only), reproduces
//        the majority exactly; a cut-pending decode makes the attempt
//        UNDECIDABLE (no partial result);
//   MC5  the marker / observation codecs round-trip.
// ===========================================================================
#include <cstdio>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/xmr_minority_converge.hpp"
#include "c2pool/v37/xmr/xmr_finalize_driver.hpp"

namespace mc = c2pool::v37n::xmr::minority;
using c2pool::v37n::xmr::Amounts;
using c2pool::v37n::xmr::SettleEvent;
using c2pool::v37n::xmr::SettleEvKind;

static int g_n = 0, g_fail = 0;
static void check(const std::string& name, bool ok, const std::string& detail = {}) {
    ++g_n; if (!ok) ++g_fail;
    std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name.c_str(), detail.empty() ? "" : "  -- ", detail.c_str());
}
static ::v37::bytes32 key_of(std::uint8_t b) { ::v37::bytes32 k{}; k[0] = b; k[31] = b; return k; }
static std::string bid_of(std::uint64_t h) { char b[65]; std::snprintf(b, sizeof b, "%064llx", static_cast<unsigned long long>(0xb10c000000ull + h)); return b; }

// One simulated node: the production F1 driver over a MemSettleStore, fed in the
// SYNCED order (book h while the cursor stands at h - 1 - D, then advance to h).
struct SimNode {
    std::uint64_t D = 3;
    ::v37::ChainId chain = 7;
    c2pool::v37n::xmr::MemSettleStore store;
    c2pool::v37n::xmr::OwedLedger ledger{7};
    c2pool::v37n::xmr::SettleHW hw;
    c2pool::v37n::xmr::XmrFinalizeDriver drv{ledger, hw, store, 7, 3, 0, 0, [](std::uint64_t, const std::string&) { return true; }};
    std::vector<std::pair<::v37::bytes32, std::uint64_t>> ring;   // (digest, since) oldest first
    std::set<::v37::bytes32> known;
    SimNode() {
        ring.emplace_back(ledger.owed_digest(), 0); known.insert(ledger.owed_digest());
        drv.set_ledger_event_observer([this] {
            const auto d = ledger.owed_digest();
            if (!(ring.back().first == d)) { ring.emplace_back(d, drv.digest_since()); known.insert(d); }
        });
    }
    void book(std::uint64_t h, const Amounts& credit, const Amounts& payout) {
        c2pool::v37n::xmr::FoundBlock fb; fb.bid = bid_of(h); fb.height = h; fb.credit = credit; fb.payout = payout;
        drv.on_block_found(fb);
    }
    void advance(std::uint64_t h) { (void)drv.advance_to_tip(h, ::v37::bytes32{}); }
    std::vector<SettleEvent> events() {
        std::vector<SettleEvent> ev;
        store.for_each_prefix(c2pool::v37n::xmr::store_codec::k_evt_prefix(chain),
                              [&](const std::string&, const std::string& v) { ev.push_back(SettleEvent::deserialize(v)); return true; });
        return ev;
    }
};

int main() {
    std::printf("== v37_xmr_minority_converge_selfcheck ==\n");
    // ── MC1 builder keys ────────────────────────────────────────────────────
    {
        const std::uint32_t baseA = (1u << 24) + 123457u, baseB = baseA + 5u * (1u << 20);
        const bool one = mc::builder_key(baseA) == mc::builder_key(baseA + 999) && mc::builder_key(baseA) == mc::builder_key(baseA - 1 + 1);
        const bool two = mc::builder_key(baseA) != mc::builder_key(baseB);
        const bool none = mc::builder_key(0) == 0 && mc::builder_key(57) == 0;   // no relay: the counter starts at 0 on EVERY node
        // two different no-relay nodes, 3 unmatched blocks: one key -> never distinct
        std::vector<mc::Observation> obs;
        for (std::uint64_t h = 10; h < 13; ++h) { mc::Observation o; o.h = h; o.bid = bid_of(h); o.verdict = mc::Verdict::Unmatched;
                                                   o.has_builder = true; o.builder = mc::builder_key(static_cast<std::uint32_t>(h % 2)); obs.push_back(o); }
        const auto st = mc::evaluate_run(obs, 3, 2, 0);
        check("MC1 builder_key: one GAP-2 base (stratum sessions + the miner slot) -> ONE key; bases 5*2^20 apart -> two keys; no relay (counter from 0) -> key 0 on every node, so M unmatched blocks from two no-relay nodes are ONE builder: detection unavailable",
              one && two && none && !st.detected && st.run.size() == 3 && st.builders == 1,
              "keyA=" + std::to_string(mc::builder_key(baseA)) + " keyB=" + std::to_string(mc::builder_key(baseB)) +
              " norelay_builders=" + std::to_string(st.builders));
    }
    // ── MC2 the detection rule ──────────────────────────────────────────────
    {
        auto mk = [](std::uint64_t h, mc::Verdict v, std::uint32_t b, bool own = false) {
            mc::Observation o; o.h = h; o.bid = bid_of(h); o.verdict = v; o.has_builder = true; o.builder = b; o.own = own; return o; };
        using V = mc::Verdict;
        const auto one = mc::evaluate_run({mk(10, V::Matched, 1), mk(11, V::Unmatched, 2)}, 3, 2, 0);
        const auto onebuilder = mc::evaluate_run({mk(10, V::Unmatched, 2), mk(11, V::Unmatched, 2), mk(12, V::Unmatched, 2), mk(13, V::Unmatched, 2)}, 3, 2, 0);
        const auto interleaved = mc::evaluate_run({mk(9, V::Matched, 1, false), mk(10, V::Unmatched, 2), mk(11, V::Matched, 7, true),
                                                   mk(12, V::Unmatched, 3), mk(13, V::Matched, 7, true), mk(14, V::Unmatched, 2)}, 3, 2, 0);
        const auto reset = mc::evaluate_run({mk(10, V::Unmatched, 2), mk(11, V::Unmatched, 3), mk(12, V::Matched, 2), mk(13, V::Unmatched, 3)}, 3, 2, 0);
        const auto undecided = mc::evaluate_run({mk(10, V::Unmatched, 2), mk(11, V::Undecided, 9), mk(12, V::Undecided, 9), mk(13, V::Unmatched, 3)}, 3, 2, 0);
        const auto floor = mc::evaluate_run({mk(10, V::Unmatched, 2), mk(11, V::Unmatched, 3), mk(12, V::Unmatched, 2)}, 3, 2, 11);
        const auto clear = mc::evaluate_run({mk(10, V::Unmatched, 2), mk(11, V::Unmatched, 3), mk(12, V::Unmatched, 2),
                                             mk(13, V::Matched, 2), mk(14, V::Matched, 3), mk(15, V::Matched, 2)}, 3, 2, 0);
        check("MC2a a single unmatched foreign block is refuse + alarm only: no detection", !one.detected && one.run.size() == 1);
        check("MC2b M (=4) unmatched from ONE builder: no detection (a lone stuck/forked node never looks like a majority)",
              !onebuilder.detected && onebuilder.run.size() == 4 && onebuilder.builders == 1);
        check("MC2c 3 unmatched from 2 builders with this node's OWN blocks interleaved (own skipped, never 'matched'): DETECTED; the last matched foreign obs before the run is h=9",
              interleaved.detected && interleaved.run.size() == 3 && interleaved.builders == 2 &&
              interleaved.last_matched_before && interleaved.last_matched_before->h == 9,
              "run=" + std::to_string(interleaved.run.size()) + " builders=" + std::to_string(interleaved.builders));
        check("MC2d a matched foreign block inside the run resets it; undecided never counts and never resets; observations at/below the adoption floor are consumed",
              !reset.detected && reset.run.size() == 1 && !undecided.detected && undecided.run.size() == 2 && !floor.detected && floor.run.size() == 1);
        check("MC2e exit (DIVERGED cleared): M matched foreign blocks from >= B_min builders after the run",
              clear.trailing_clear && clear.trailing_matched == 3 && clear.trailing_matched_builders == 2 && !clear.detected);
    }
    // ── MC3 / MC4 refold exactness through the production driver ────────────
    // D = 3. Lane blocks at 5..20; X = the minority's own isolated block at 8
    // (credited by the minority, refused by the majority: its credit cut never
    // reached them); Y = the minority's own block at 13, built on the minority
    // lineage (commits a digest containing X). Every other block is the
    // majority's, committing the MAJORITY digest at its builder cut.
    for (int variant = 0; variant < 3; ++variant) {   // 0 = MC3 (to 12), 1 = MC4 (to 20), 2 = MC4 undecidable
        const std::uint64_t D = 3, TOP = variant == 0 ? 12 : 20, X = 8, Y = 13;
        SimNode maj, mino;
        std::map<std::uint64_t, ::v37::bytes32> commit;
        std::map<std::uint64_t, std::pair<Amounts, Amounts>> maps;
        std::set<std::uint64_t> maj_refused_on_mino;
        for (std::uint64_t h = 1; h <= TOP; ++h) {
            if (h >= 5) {
                Amounts cr, po; cr[key_of(static_cast<std::uint8_t>(0x10 + h % 3))] = static_cast<long long>(1000 + 17 * h);
                po[key_of(static_cast<std::uint8_t>(0x10 + (h + 1) % 3))] = static_cast<long long>(300 + h);
                maps[h] = {cr, po};
                const bool own = (h == X) || (h == Y && TOP >= Y);
                commit[h] = own ? mino.ledger.owed_digest() : maj.ledger.owed_digest();
                if (!own) maj.book(h, cr, po);                                 // the majority never credits X / Y
                if (own || mino.known.count(commit[h])) mino.book(h, cr, po);  // the minority credits its own + what it can match
                else maj_refused_on_mino.insert(h);
            }
            maj.advance(h); mino.advance(h);
        }
        const std::uint64_t c = mino.drv.cursor_height();
        mc::RefoldInput in; in.chain = 7; in.d_conf = D; in.fork_h = 7; in.cursor = c; in.events = mino.events();
        for (std::uint64_t h = in.fork_h + 1; h <= c + 1 + D && h <= TOP; ++h) in.chain_blocks[h] = bid_of(h);
        in.refuse = {bid_of(X)};
        std::size_t calls = 0;
        auto decode = [&](std::uint64_t h, const std::string&, const std::vector<::v37::bytes32>& cands, const std::vector<std::uint64_t>&, bool root_only) {
            ++calls;
            mc::DecodeResult r;
            if (variant == 2 && h == 15) { r.outcome = mc::DecodeOutcome::Undecidable; r.why = "cut-pending: relay repair of P=9 in flight (test)"; return r; }
            bool m = false; for (const auto& d : cands) if (d == commit[h]) { m = true; break; }
            if (!m) { r.outcome = mc::DecodeOutcome::Refused; r.why = "lane-root-refused:test"; r.total_pico = 5000; r.unattributed_pico = 5000; return r; }
            r.outcome = mc::DecodeOutcome::Booked;
            if (!root_only) { r.credit = maps[h].first; r.payout = maps[h].second; }
            return r;
        };
        const mc::RefoldResult res = mc::refold(in, decode);
        if (variant == 0) {
            check("MC3 refold is EXACT: the minority credited its own isolated block X; refold(prefix <= F, R = {X}) reproduces the majority control's (digest, since) sequence at EVERY state and its final digest (production XmrFinalizeDriver + OwedLedger)",
                  res.ok && res.ring == maj.ring && res.digest == maj.ledger.owed_digest() && !(res.digest == mino.ledger.owed_digest()) &&
                  res.refused.size() == 1 && res.refused[0].forced && res.refused[0].had_old && res.pending.size() == maj.ledger.pending_count(),
                  "states refold/control=" + std::to_string(res.ring.size()) + "/" + std::to_string(maj.ring.size()) + " prefix_events=" +
                  std::to_string(res.prefix_events) + " reused=" + std::to_string(res.reused_maps));
        } else if (variant == 1) {
            std::size_t released = 0; for (const auto h : maj_refused_on_mino) if (res.booked.count(bid_of(h))) ++released;
            bool y_refused = false; for (const auto& rb : res.refused) if (rb.bid == bid_of(Y) && !rb.forced && rb.had_old) y_refused = true;
            std::vector<mc::Observation> run;
            for (const auto h : maj_refused_on_mino) { mc::Observation o; o.h = h; o.bid = bid_of(h); run.push_back(o); }
            check("MC4 refold CREDITS the " + std::to_string(maj_refused_on_mino.size()) + " majority blocks the minority refused (their roots commit states only the re-derived lineage holds), REFUSES the minority's own block Y built on the minority lineage (root unmatched in the scratch ring), and reproduces the majority's (digest, since) sequence and final digest exactly",
                  res.ok && !maj_refused_on_mino.empty() && released == maj_refused_on_mino.size() && y_refused &&
                  mc::reproduced(res, run) == run.size() && res.ring == maj.ring && res.digest == maj.ledger.owed_digest(),
                  "released=" + std::to_string(released) + "/" + std::to_string(maj_refused_on_mino.size()) + " states=" +
                  std::to_string(res.ring.size()) + "/" + std::to_string(maj.ring.size()) + " decodes=" + std::to_string(calls));
        } else {
            check("MC4b a cut-pending decode inside the re-derivation makes the WHOLE attempt UNDECIDABLE (no partial result to adopt)",
                  !res.ok && res.undecidable && res.why.find("cut-pending") != std::string::npos, res.why);
        }
    }
    // ── MC5 codecs ──────────────────────────────────────────────────────────
    {
        mc::Marker m; m.phase = "applied"; m.fork_h = 7; m.cursor = 12; m.new_seq = 44; m.new_events = 40; m.old_events = 43;
        m.floor_h = 16; m.new_digest_hex = std::string(64, 'a'); m.utc = "20260924T010203Z"; m.candidate = "R1";
        m.forced = {bid_of(8)}; m.refused = {bid_of(8), bid_of(13)}; m.released = {};
        mc::Marker b; const bool okm = mc::marker_parse(mc::marker_str(m), b);
        mc::Observation o; o.h = 15; o.bid = bid_of(15); o.root = std::string(64, 'c'); o.own = false; o.has_builder = true; o.builder = 34;
        o.verdict = mc::Verdict::Unmatched; o.has_matched_since = false; o.t = 99;
        mc::Observation p; const bool oko = mc::obs_parse(mc::obs_line(o), p);
        check("MC5 the adoption marker and the observation line round-trip",
              okm && b.phase == "applied" && b.fork_h == 7 && b.cursor == 12 && b.new_seq == 44 && b.new_events == 40 && b.floor_h == 16 &&
              b.new_digest_hex == m.new_digest_hex && b.forced == m.forced && b.refused == m.refused && b.released.empty() &&
              oko && p.h == 15 && p.bid == o.bid && p.root == o.root && p.verdict == o.verdict && p.builder == 34 && p.has_builder && !p.own);
    }
    std::printf("== %s (%d/%d passed) ==\n", g_fail ? "FAIL" : "OK", g_n - g_fail, g_n);
    return g_fail ? 1 : 0;
}
