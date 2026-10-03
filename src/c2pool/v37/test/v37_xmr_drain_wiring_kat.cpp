// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_drain_wiring_kat.cpp
//   THE DRAIN RULE (docs/xmr-lane/settlement-drain.md): the daemon-side
//   activation chain and the receiver's booking pieces, each through the
//   function the daemon itself calls, plus operator ruling O-2.
//
//   W1  the network triple: apply_network_drain() gives 16/64/1 on the test
//       networks and 0/0/0 on mainnet; XmrNode(cfg)'s ledger rules carry
//       lane_height and decay_from_gross == (drain_rule_version >= 1); the
//       settlement config's rule (drain_rule_of) is the triple.
//   W2  make_xmr_coinbase_context(cfg).drain == cfg.drain for 16/64/1 and 0/0/0.
//   W3  the builder's reward fixpoint (drain_reward_fixpoint, the provider's
//       loop): a weight-dependent reward stub converges within 4 rebuilds;
//       one that does not fails closed; a refused rebuild fails closed; the
//       rule off never rebuilds.
//   W4  the receiver's D7 pieces main calls: the refold at P = split_at
//       (drain_refold_credit), the gross set G_b (drain_gross_set) and the
//       empty-cut finder credited P (drain_finder_credit).
//   W5  O-2: a lane block refused on the lane-root path between two canonical
//       lane blocks is FOUND as an EMPTY booking carrying its height: dh of
//       the next lane block counts from it, V37Z commits it at FINALIZE, its
//       payout stays node-local liability; a restart (store replay + sidecar
//       re-drive) reproduces the same owed_digest; the rule off books nothing.
//
// Network-free, RandomX-free (monerod stub + the injected test point-check,
// the v37_xmr_relay_repair_hold_kat shape). Nonzero exit on failure.
// ===========================================================================
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include "impl/xmr/settle/xmr_drain_rule.hpp"
#include "c2pool/v37/xmr/xmr_o2_finalize_connect.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_paynow.hpp"

namespace o2  = c2pool::v37n::xmr::o2;
namespace xs  = c2pool::v37n::xmr;
namespace x6  = ::v37::xmr::settle;
namespace pn  = c2pool::v37n::xmr::paynow;
using Amounts = std::map<::v37::bytes32, long long>;
using T3 = std::tuple<std::uint32_t, std::uint32_t, std::uint32_t>;

namespace {

int g_fail = 0, g_n = 0;
void check(const char* name, bool ok, const std::string& detail = {}) {
    ++g_n; if (!ok) ++g_fail;
    std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name, detail.empty() ? "" : "  -- ", detail.c_str());
}
std::string triple(std::uint32_t v, std::uint32_t q, std::uint32_t h) {
    return std::to_string(v) + "/" + std::to_string(q) + "/" + std::to_string(h);
}

// ── W1: the network triple -> the node's ledger rules -> the settlement rule ──
void w1_network_triple() {
    std::printf("-- W1: the network triple, the node's ledger rules, the settlement rule --\n");
    struct Net { xs::MoneroNetwork n; const char* name; bool on; };
    for (const Net& t : {Net{xs::MoneroNetwork::Stagenet, "stagenet", true}, Net{xs::MoneroNetwork::Testnet, "testnet", true},
                         Net{xs::MoneroNetwork::Mainnet, "mainnet", false}}) {
        xs::XmrNodeConfig c; c.network = t.n; c.lane_chain = 7;
        xs::apply_network_drain(c);
        const bool trip = t.on ? (c.drain_rule_version == 1 && c.drain_q == 16 && c.drain_h_cap == 64)
                               : (c.drain_rule_version == 0 && c.drain_q == 0 && c.drain_h_cap == 0);
        c2pool::xmr::node::MockMonerodTransport mock;
        xs::XmrNode node(c, mock, &xs::smoke::test_point_check);
        const auto& r = node.ledger().rules();
        const o2::DrainRule dr = o2::drain_rule_of(c);
        const std::string d = std::string(t.name) + " triple " + triple(c.drain_rule_version, c.drain_q, c.drain_h_cap) +
                              " lane_height=" + std::to_string(r.lane_height) + " decay_from_gross=" + std::to_string(r.decay_from_gross) +
                              " rule.on=" + std::to_string(dr.on());
        check(t.on ? "W1 test network: 16/64/1; XmrNode ledger rules lane_height + decay_from_gross ON; settlement rule ON"
                   : "W1 mainnet: 0/0/0; XmrNode ledger rules lane_height + decay_from_gross OFF; settlement rule OFF (master)",
              trip && r.lane_height == t.on && r.decay_from_gross == t.on && dr.on() == t.on &&
              dr.version == c.drain_rule_version && dr.q == c.drain_q && dr.h_cap == c.drain_h_cap, d);
    }
    // the review's two triples set by hand (a rig's config, not main's)
    for (const auto& [v, q, h] : std::vector<T3>{{1, 16, 64}, {0, 0, 0}}) {
        xs::XmrNodeConfig c; c.network = xs::MoneroNetwork::Stagenet; c.lane_chain = 7;
        c.drain_rule_version = v; c.drain_q = q; c.drain_h_cap = h;
        c2pool::xmr::node::MockMonerodTransport mock;
        xs::XmrNode node(c, mock, &xs::smoke::test_point_check);
        const bool on = v >= 1;
        check(on ? "W1 XmrNode(cfg 16/64/1).ledger().rules(): lane_height and decay_from_gross ON"
                 : "W1 XmrNode(cfg 0/0/0).ledger().rules(): lane_height and decay_from_gross OFF",
              node.ledger().rules().lane_height == on && node.ledger().rules().decay_from_gross == on &&
              node.ledger_rules().lane_height == on, triple(v, q, h));
    }
}

// ── W2: the template context carries the settlement config's rule ──
void w2_context_drain() {
    std::printf("-- W2: make_xmr_coinbase_context(cfg).drain == cfg.drain --\n");
    for (const auto& [v, q, h] : std::vector<T3>{{1, 16, 64}, {0, 0, 0}}) {
        xs::XmrNodeConfig nc; nc.drain_rule_version = v; nc.drain_q = q; nc.drain_h_cap = h;
        o2::XmrSettlementConfig cfg;
        cfg.chain_id = 7;
        cfg.residual_sink = o2::selftest::sample_wellformed_ref();
        cfg.residual_sink_identity = ::v37::xmr::xmr_identity_key(cfg.residual_sink);
        cfg.spend_floor = true;
        cfg.drain = o2::drain_rule_of(nc);
        o2::XmrOwedFixture fx(7);
        o2::XmrParentContext parent; parent.height = 100; parent.base_reward = 600000000000ULL; parent.fees = 0;
        std::string w;
        const auto ctx = o2::make_xmr_coinbase_context(cfg, parent, fx.ledger(), &w);
        check(v ? "W2 rule 16/64/1: the template context's drain == the settlement config's (rule ON in the template)"
                : "W2 rule 0/0/0: the template context's drain == the settlement config's (rule OFF: master)",
              ctx && ctx->drain == cfg.drain && ctx->drain.on() == (v >= 1) && ctx->drain.q == q && ctx->drain.h_cap == h,
              ctx ? triple(ctx->drain.version, ctx->drain.q, ctx->drain.h_cap) : ("refused: " + w));
    }
}

// ── W3: the builder's reward fixpoint ──
// A weight-dependent stub: the template's reward is the block reward plus fees
// minus a coinbase-weight penalty that depends on the payee set, i.e. on the
// reward the settlement source was cut at. `seq` maps a cut to the reward the
// assembler would settle on.
void w3_fixpoint() {
    std::printf("-- W3: the builder's reward fixpoint (snapshot at the template's final reward) --\n");
    const std::uint64_t R0 = 600000000000ull;
    auto run = [&](bool on, std::uint64_t first_reward, const std::function<std::optional<std::uint64_t>(std::uint64_t)>& seq,
                   std::uint64_t& hint, std::uint64_t& reward, int& passes, int& calls, std::string& why) {
        hint = R0; reward = first_reward; passes = -1; calls = 0; why.clear();
        return x6::drain_reward_fixpoint(on, hint, reward,
            [&](std::uint64_t at, std::string& w) -> std::optional<std::uint64_t> {
                ++calls;
                const auto r = seq(at);
                if (!r) w = "assembler refused (drain fixpoint): test";
                return r;
            }, why, &passes);
    };
    std::uint64_t hint = 0, reward = 0; int passes = 0, calls = 0; std::string why;
    // (a) converges in 2 rebuilds: the penalty grows by 1 pico per 1000 pico the cut drops
    {
        auto seq = [&](std::uint64_t at) -> std::optional<std::uint64_t> { return R0 - 1000 - (R0 - at) / 1000; };
        const bool ok = run(true, R0 - 1000, seq, hint, reward, passes, calls, why);
        check("W3a a reward that moves with the payee set: rebuilt at the template's reward until the two agree (2 rebuilds), "
              "the snapshot is cut at the FINAL reward",
              ok && hint == reward && reward == R0 - 1001 && calls == 2 && passes == 2,
              "hint=" + std::to_string(hint) + " reward=" + std::to_string(reward) + " rebuilds=" + std::to_string(calls));
    }
    // (b) needs exactly 4 rebuilds (the bound): accepted
    {
        auto seq = [&](std::uint64_t at) -> std::optional<std::uint64_t> {
            const std::uint64_t d = R0 - at;          // 10, 20, 30, 40 -> 40 is a fixpoint
            return d >= 40 ? at : at - 10; };
        const bool ok = run(true, R0 - 10, seq, hint, reward, passes, calls, why);
        check("W3b a fixpoint reached on the 4th rebuild is accepted (the bound is 4 rebuilds)",
              ok && hint == reward && reward == R0 - 40 && calls == 4,
              "reward=" + std::to_string(reward) + " rebuilds=" + std::to_string(calls) + " why=" + why);
    }
    // (c) oscillates (penalty zone: the output count flips R by 7 pico each cut): fails closed after 4 rebuilds
    {
        auto seq = [&](std::uint64_t at) -> std::optional<std::uint64_t> { return at == R0 - 7 ? R0 : R0 - 7; };
        const bool ok = run(true, R0 - 7, seq, hint, reward, passes, calls, why);
        check("W3c no fixpoint within 4 rebuilds: FAILS CLOSED (no template served), the reason names the bound",
              !ok && calls == 4 && why.find("no reward fixpoint within 4 passes") != std::string::npos,
              "rebuilds=" + std::to_string(calls) + " why=" + why);
    }
    // (d) a refused rebuild fails closed with its reason
    {
        auto seq = [&](std::uint64_t) -> std::optional<std::uint64_t> { return std::nullopt; };
        const bool ok = run(true, R0 - 5, seq, hint, reward, passes, calls, why);
        check("W3d a refused rebuild fails closed with the assembler's reason", !ok && calls == 1 && why.find("assembler refused") != std::string::npos, why);
    }
    // (e) rule off: never rebuilt (master), whatever the reward
    {
        auto seq = [&](std::uint64_t at) -> std::optional<std::uint64_t> { return at; };
        const bool ok = run(false, R0 - 5, seq, hint, reward, passes, calls, why);
        check("W3e rule off: no rebuild (master's single build)", ok && calls == 0 && hint == R0 && reward == R0 - 5);
    }
    // (f) already at the fixpoint: no rebuild
    {
        auto seq = [&](std::uint64_t at) -> std::optional<std::uint64_t> { return at; };
        const bool ok = run(true, R0, seq, hint, reward, passes, calls, why);
        check("W3f rule on, the first build's reward equals the snapshot's: no rebuild", ok && calls == 0 && reward == R0);
    }
}

// ── W4: the receiver's D7 pieces (main's drain_refold, the G_b capture, the finder) ──
void w4_receiver_pieces() {
    std::printf("-- W4: the receiver's D7 booking pieces --\n");
    const ::v37::bytes32 a = xs::smoke::key_of(0xA1), b = xs::smoke::key_of(0xB2), c = xs::smoke::key_of(0xC3), f = xs::smoke::key_of(0xF4);
    const std::uint64_t R = 600000000000ull, P = 450000000000ull;
    // a stub fold: the window's E_b at the reward it is asked for, 1:2 between a and b
    std::vector<std::uint64_t> asked;
    auto fold = [&](std::uint64_t at, Amounts& cr) { asked.push_back(at); cr.clear(); cr[a] = static_cast<long long>(at / 3); cr[b] = static_cast<long long>(at - at / 3); return true; };
    auto base = [&] { Amounts m; m[a] = static_cast<long long>(R / 3); m[b] = static_cast<long long>(R - R / 3); return m; };
    {
        Amounts cr = base(); bool refolded = false; asked.clear();
        const bool ok = pn::drain_refold_credit(true, true, P, R, cr, fold, &refolded);
        long long sum = 0; for (const auto& [k, v] : cr) { (void)k; sum += v; }
        check("W4a canonical, rule on, debt paid (P < R): the window's credit is REFOLDED at P (credit sums to P, not R)",
              ok && refolded && asked.size() == 1 && asked[0] == P && sum == static_cast<long long>(P),
              "sum=" + std::to_string(sum) + " P=" + std::to_string(P));
    }
    {
        int ran = 0;
        for (const auto& [canon, on, at] : std::vector<std::tuple<bool, bool, std::uint64_t>>{{true, false, P}, {false, true, P}, {true, true, R}}) {
            Amounts cr = base(); bool refolded = true; asked.clear();
            const bool ok = pn::drain_refold_credit(canon, on, at, R, cr, fold, &refolded);
            if (ok && !refolded && asked.empty() && cr == base()) ++ran;
        }
        check("W4b no refold when the rule is off, the block is not canonical, or no debt was paid (P == R): credit as folded at R", ran == 3);
    }
    {
        Amounts cr = base();
        auto bad = [&](std::uint64_t, Amounts&) { return false; };
        check("W4c a refold that cannot complete (cut-pending) leaves the booking undecidable (false)", !pn::drain_refold_credit(true, true, P, R, cr, bad));
    }
    {
        Amounts cr; cr[a] = 5; cr[b] = 0; cr[c] = -3; cr[f] = 1;
        const auto on = pn::drain_gross_set(cr, true), off = pn::drain_gross_set(cr, false);
        check("W4d G_b = {k : E'_b(k) > 0} under the gross clock; empty with the clock off (master)",
              on == std::set<::v37::bytes32>{a, f} && off.empty(), "on=" + std::to_string(on.size()) + " off=" + std::to_string(off.size()));
    }
    {
        Amounts cr; cr[f] = static_cast<long long>(R);
        pn::drain_finder_credit(cr, f, P, R);
        Amounts same; same[f] = static_cast<long long>(R);
        Amounts c0 = same, cR = same;
        pn::drain_finder_credit(c0, f, 0, R); pn::drain_finder_credit(cR, f, R, R);
        check("W4e the empty-cut finder is credited P (what the canonical coinbase paid it), unchanged with no split",
              cr.size() == 1 && cr.at(f) == static_cast<long long>(P) && c0 == same && cR == same);
    }
}

// ── W5: O-2, the lane-root-refused block FOUND as an empty booking ──
constexpr long long kReward = 600000000000ll;
const std::string kRootRefused = "lane-root-refused:" + std::string(64, 'e') + ":no candidate digest (test)";

// Lane blocks at 5 and 9 book (credit the payee, pay no owed balance); the lane
// block at 7 is refused on the lane-root path (its decoded payout -> liability).
struct Rig {
    xs::XmrNodeConfig c;
    o2::FinalizeConnectOptions o;
    c2pool::xmr::node::MockMonerodTransport mock;
    std::unique_ptr<xs::XmrNode> node;
    o2::FoundBlockQueue q;
    std::unique_ptr<o2::FinalizeConnect> fc;
    ::v37::bytes32 payee = xs::smoke::key_of(0xC3), victim = xs::smoke::key_of(0xD4);
    std::string bid7;
    bool ok = false;
    Rig(const std::filesystem::path& dir, bool rule_on) {
        c.network = xs::MoneroNetwork::Stagenet;
        c.lane_chain = 7;
        c.d_conf = 3;
        if (rule_on) { c.drain_rule_version = 1; c.drain_q = 16; c.drain_h_cap = 64; }
        c.settle_db_path = dir.string();
        std::filesystem::create_directories(dir);
        o.out = nullptr;
        o.sidecar_path = (dir / "pfound.tsv").string();
        o.retry_bound = 30; o.held_retry_every = 5;
        node = std::make_unique<xs::XmrNode>(c, mock, &xs::smoke::test_point_check);
        try { node->bring_up(); } catch (const std::exception& e) { check("W5 bring_up", false, e.what()); return; }
        bid7 = xs::hex_of(xs::smoke::blk_id(7));
        o.book_from_chain_ex = [this](std::uint64_t h, const std::string&, o2::FinalizeConnectOptions::ChainBooking& bk) {
            if (h != 5 && h != 7 && h != 9) { bk.why = "not-lane: test"; return false; }
            bk.payout.clear(); bk.credit.clear();
            if (h == 7) { bk.payout[victim] = 1000000000ll; bk.payout_decoded = true; bk.total_pico = kReward; bk.why = kRootRefused; return false; }
            bk.credit[payee] = kReward; bk.total_pico = kReward;
            return true;
        };
        fc = std::make_unique<o2::FinalizeConnect>(*node, c, q, o);
        (void)fc->reseed_after_bring_up();
        ok = true;
    }
    void chain(std::uint64_t from, std::uint64_t to) {
        for (std::uint64_t h = from; h <= to; ++h)
            xs::smoke::apply_row(*node, h, xs::smoke::blk_id(static_cast<std::uint8_t>(h)), xs::smoke::blk_id(static_cast<std::uint8_t>(h - 1)));
    }
    void ticks(int n) { for (int i = 0; i < n; ++i) (void)fc->tick(); }
    const xs::OwedLedger& L() const { return node->ledger(); }
    std::string brief() const {
        return "cursor=" + std::to_string(node->finalize_driver().cursor_height()) + " pending7=" + std::to_string(L().is_pending(bid7)) +
               " prev_lane=" + std::to_string(L().prev_lane_height()) + " settled_lane=" + std::to_string(L().last_settled_lane_height()) +
               " dh(9)=" + std::to_string(L().heights_since_last_lane(9)) + " rnc=" + std::to_string(fc->stats().refused_not_credited) +
               " empty=" + std::to_string(fc->stats().refused_found_empty) + " liability=" + std::to_string(fc->stats().liability_blocks);
    }
    void stop() { (void)fc->drain_before_stop(); fc.reset(); node.reset(); }
};

void w5_refused_found_empty(const std::filesystem::path& tmp) {
    std::printf("-- W5: O-2, a lane-root-refused block is FOUND as an empty booking (dh counts it) --\n");
    std::string d_live, d_restart, d_ref;
    {
        auto r = std::make_unique<Rig>(tmp / "w5-live", true);
        if (!r->ok) return;
        r->chain(1, 4); r->ticks(1); r->chain(5, 8); r->ticks(20);
        const bool empty_found = r->L().is_pending(r->bid7) && r->fc->stats().refused_found_empty == 1 &&
                                 r->fc->pending().count(r->bid7) && r->fc->pending().at(r->bid7).kind == 'e';
        check("W5a the refused block at 7 is FOUND as an EMPTY booking ('e'): pending in the ledger, refused-not-credited, "
              "its payout recorded as node-local liability", empty_found && r->fc->stats().refused_not_credited == 1 &&
              r->fc->stats().liability_blocks == 1 && r->L().effective_owed(r->victim) == 0, r->brief());
        check("W5b dh counts it: prev_lane_height 7, so a lane block at 9 has dh 2 (4 without O-2)",
              r->L().prev_lane_height() == 7 && r->L().heights_since_last_lane(9) == 2 && r->L().last_settled_lane_height() == 5, r->brief());
        d_live = xs::hex_of(r->L().owed_digest());
        r->stop();
    }
    {   // restart: the store replay + the sidecar's 'e' record re-drive the same empty FOUND
        auto r = std::make_unique<Rig>(tmp / "w5-live", true);
        if (!r->ok) return;
        r->chain(1, 8); r->ticks(5);
        d_restart = xs::hex_of(r->L().owed_digest());
        check("W5c restart (store replay + sidecar re-drive): the empty FOUND is pending again, same owed_digest, same dh",
              d_restart == d_live && r->L().is_pending(r->bid7) && r->fc->pending().count(r->bid7) &&
              r->fc->pending().at(r->bid7).kind == 'e' && r->L().heights_since_last_lane(9) == 2,
              r->brief() + " digest " + d_restart.substr(0, 12) + " vs " + d_live.substr(0, 12));
        r->chain(9, 14); r->ticks(30);
        d_restart = xs::hex_of(r->L().owed_digest());
        r->stop();
    }
    {   // the uninterrupted reference
        auto r = std::make_unique<Rig>(tmp / "w5-ref", true);
        if (!r->ok) return;
        r->chain(1, 4); r->ticks(1); r->chain(5, 10); r->ticks(20);
        check("W5d V37Z commits the empty FOUND at its FINALIZE: last_settled_lane_height 7 (5 without O-2)",
              r->L().is_settled(r->bid7) && r->L().last_settled_lane_height() == 7, r->brief());
        r->chain(11, 14); r->ticks(30);
        d_ref = xs::hex_of(r->L().owed_digest());
        check("W5e restarted and uninterrupted nodes end at the same owed_digest; the money is as without the block "
              "(payee credited 2 blocks, the refused payout never booked)",
              d_ref == d_restart && r->L().is_settled(r->bid7) && r->L().last_settled_lane_height() == 9 &&
              r->L().effective_owed(r->payee) == 2 * kReward && r->L().effective_owed(r->victim) == 0,
              r->brief() + " ref " + d_ref.substr(0, 12) + " restart " + d_restart.substr(0, 12));
        r->stop();
    }
    {   // rule off: master -- nothing FOUND for the refused block
        auto r = std::make_unique<Rig>(tmp / "w5-off", false);
        if (!r->ok) return;
        r->chain(1, 4); r->ticks(1); r->chain(5, 14); r->ticks(30);
        check("W5f rule off (0/0/0): the refused block is NOT FOUND (master), liability recorded, no lane heights",
              !r->L().is_pending(r->bid7) && !r->L().is_settled(r->bid7) && r->fc->stats().refused_found_empty == 0 &&
              r->fc->stats().liability_blocks == 1 && r->L().prev_lane_height() == 0, r->brief());
        r->stop();
    }
}

} // namespace

int main() {
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / ("v37-xmr-drain-wiring-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);
    std::printf("== v37_xmr_drain_wiring_kat ==\n");
    w1_network_triple();
    w2_context_drain();
    w3_fixpoint();
    w4_receiver_pieces();
    w5_refused_found_empty(tmp);
    std::filesystem::remove_all(tmp);
    std::printf("== %s (%d/%d checks, %d failure(s)) ==\n", g_fail ? "FAIL" : "PASS", g_n - g_fail, g_n, g_fail);
    return g_fail ? 1 : 0;
}
