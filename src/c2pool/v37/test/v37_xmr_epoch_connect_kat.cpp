// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_epoch_connect_kat -- LANE-EPOCH (E1) through XmrNode + FinalizeConnect
// (D_conf 3, N 12). The FALSE START in miniature: three Own lane blocks of
// epoch 0 at h 5..7 whose roots this node cannot resolve, silence, an opener
// of epoch 1 at h 20, new-epoch lane blocks at 23 and 26.
//
//   BASE   (no epoch rule, today's callback): 5..7 stay lane-root-unknown ->
//          HELD, the finalize cursor frozen below 5, the opener never booked.
//   FRESH  (the rule, empty store): 5..7 decided "epoch-dead"/"epoch-closed"
//          (not held, not a vote observation), the cursor walks, the opener
//          and the epoch-1 blocks are booked and SETTLED.
//   HOLDER (the rule, a store holding the epoch-0 history: a seeded row and
//          5..7 booked): the opener CLOSES its ledger through the event log;
//          from the opener's finalize on, its owed_digest equals FRESH's at
//          every shared cursor (M3: holder and newcomer converge), and a
//          restart of the holder store replays the same digest.
// The booking callback is main's wrapper in behaviour, through the SAME
// shared functions (EpochView::decide, decided_why, undecided_to_decided,
// close_ledger).
// ---------------------------------------------------------------------------
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <set>
#include <map>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/xmr_o2_finalize_connect.hpp"
#include "c2pool/v37/xmr/xmr_node_smoke.hpp"
#include "c2pool/v37/xmr/xmr_lane_epoch_chain.hpp"

namespace o2 = c2pool::v37n::xmr::o2;
namespace ep = c2pool::v37n::xmr::epoch;
namespace credit = c2pool::v37n::xmr::credit;
namespace smoke = c2pool::v37n::xmr::smoke;
using bytes32 = ::v37::bytes32;

namespace {
int g_fail = 0, g_pass = 0;
void check(bool ok, const std::string& what) {
    if (ok) { ++g_pass; std::printf("  ok   %s\n", what.c_str()); }
    else    { ++g_fail; std::printf("  FAIL %s\n", what.c_str()); }
}
constexpr std::uint64_t kD = 3, kN = 12, kTop = 40;
bytes32 bid_b(std::uint64_t h) { bytes32 b{}; const auto id = smoke::blk_id(static_cast<std::uint8_t>(h)); std::memcpy(b.data(), id.data(), 32); return b; }
std::string bid_s(std::uint64_t h) { return c2pool::v37n::xmr::hex_of(smoke::blk_id(static_cast<std::uint8_t>(h))); }
std::string hx(const bytes32& b) { static const char* d = "0123456789abcdef"; std::string s; for (auto c : b) { s += d[c >> 4]; s += d[c & 15]; } return s; }
bytes32 key(std::uint8_t k) { bytes32 b{}; b[0] = k; b[31] = 0x5A; return b; }
bytes32 root_old(std::uint64_t h) { bytes32 b{}; b[0] = 0x77; b[1] = static_cast<std::uint8_t>(h); return b; }

enum class Mode { Base, Fresh, Holder };
const char* name(Mode m) { return m == Mode::Base ? "BASE" : m == Mode::Fresh ? "FRESH" : "HOLDER"; }

struct Run {
    std::uint64_t cursor = 0, held_now = 0, held_entered = 0, epoch_decided = 0, obs_refused = 0, closed_rows = 0;
    bool opener_settled = false, b26_settled = false;
    std::map<std::uint64_t, bytes32> digest_at;   // cursor -> owed_digest after that tick
    bytes32 final_digest{}, replay_digest{};
};

Run run(Mode m, const std::filesystem::path& tmp) {
    using c2pool::xmr::node::MockMonerodTransport;
    using namespace c2pool::v37n::xmr;
    Run r;
    XmrNodeConfig cfg;
    cfg.network = MoneroNetwork::Regtest; cfg.lane_chain = 7; cfg.d_conf = kD;
    cfg.settle_db_path = (tmp / name(m)).string();
    std::filesystem::create_directories(cfg.settle_db_path);
    o2::FinalizeConnectOptions o;
    o.out = nullptr;
    o.sidecar_path = (std::filesystem::path(cfg.settle_db_path) / "pfound.tsv").string();
    o.retry_bound = 30; o.held_retry_every = 5;
    MockMonerodTransport mock;
    XmrNode node(cfg, mock, &smoke::test_point_check);
    try { node.bring_up(); } catch (const std::exception& ex) { check(false, std::string("bring_up ") + ex.what()); return r; }
    if (m == Mode::Holder) (void)node.seed_settled_owed("5eed", {{key(9), 500}}, 2);   // epoch-0 history this node holds

    const bytes32 E = ep::empty_root(7);
    ep::EpochView view(kN, E);
    view.set_origin(1);
    const bytes32 parent1 = ep::parent_digest(0, bid_b(7), root_old(7));
    auto fact = [&](std::uint64_t h) {
        ep::ChainFact c; c.h = h; c.bid = bid_b(h);
        auto lane = [&](std::uint32_t seq, const bytes32& par, const bytes32& root) {
            c.own = true; c.has_root = true; c.root = root; c.has_cut = true;
            c.ep = credit::EpochParse::Present; c.f = credit::EpochField{seq, ep::kEpochRuleVersion, par};
        };
        if (h >= 5 && h <= 7) lane(0, bytes32{}, root_old(h));
        else if (h == 20) lane(1, parent1, E);
        else if (h == 23 || h == 26) lane(1, parent1, E);
        return c;
    };
    std::set<std::string> closed;
    // the lane block's credit (the same on every node: E_b at the on-chain cut)
    auto credit_of = [&](std::uint64_t h) -> std::map<bytes32, long long> {
        return {{key(static_cast<std::uint8_t>(h)), static_cast<long long>(100 + h)}};
    };
    o.book_from_chain_ex = [&](std::uint64_t h, const std::string& bid, o2::FinalizeConnectOptions::ChainBooking& bk) -> bool {
        const ep::ChainFact* c = view.at(h);
        if (!c || !c->own) { bk.why = "not-lane: test"; return false; }
        bk.total_pico = 1000;
        // today's booking: the epoch-0 roots are unknown to a fresh node, known to the holder
        auto core = [&]() -> bool {
            if (h <= 7 && m != Mode::Holder) { bk.why = "lane-root-unknown: 03 root matches none of 1 candidate digests (test)"; return false; }
            bk.credit = credit_of(h); bk.payout.clear(); bk.payout_decoded = true;
            return true;
        };
        if (m == Mode::Base) return core();
        const ep::Decision d = view.decide(h);
        if (const auto w = ep::decided_why(d)) { bk.why = *w; return false; }
        if (d.v == ep::Verdict::Opener && closed.insert(bid).second)
            r.closed_rows += ep::close_ledger(node, d.f.seq, c->bid, h, kD).size();
        if (core()) return true;
        if (const auto w = ep::undecided_to_decided(view, d, bk.why)) bk.why = *w;
        return false;
    };
    o2::FoundBlockQueue q;
    o2::FinalizeConnect fc(node, cfg, q, o);
    auto chain = [&](std::uint64_t from, std::uint64_t to) {
        for (std::uint64_t h = from; h <= to; ++h) {
            (void)view.put(fact(h));   // the scan runs before the tick's bookings
            smoke::apply_row(node, h, smoke::blk_id(static_cast<std::uint8_t>(h)), smoke::blk_id(static_cast<std::uint8_t>(h - 1)));
        }
    };
    auto ticks = [&](int n) {
        for (int i = 0; i < n; ++i) {
            (void)fc.tick();
            r.digest_at[node.finalize_driver().cursor_height()] = node.ledger().owed_digest();
        }
    };
    chain(1, 4); ticks(1);
    chain(5, 19); ticks(45);    // the dead lineage: 7 + N = 19 <= frontier 19 + 1
    for (std::uint64_t h = 20; h <= kTop; ++h) { chain(h, h); ticks(3); }   // one height at a time: a digest sample per cursor
    ticks(45);
    const auto& s = fc.stats();
    r.cursor = node.finalize_driver().cursor_height(); r.held_now = s.held_now; r.held_entered = s.held_entered;
    r.epoch_decided = s.epoch_decided; r.obs_refused = s.obs_refused;
    r.opener_settled = node.ledger().is_settled(bid_s(20)); r.b26_settled = node.ledger().is_settled(bid_s(26));
    r.final_digest = node.ledger().owed_digest();
    (void)fc.drain_before_stop();
    std::printf("  %-6s cursor=%llu held_now=%llu held_entered=%llu epoch_decided=%llu vote_obs_refused=%llu closed_rows=%llu "
                "opener_settled=%d h26_settled=%d owed_digest=%s\n",
                name(m), (unsigned long long)r.cursor, (unsigned long long)r.held_now, (unsigned long long)r.held_entered,
                (unsigned long long)r.epoch_decided, (unsigned long long)r.obs_refused, (unsigned long long)r.closed_rows,
                r.opener_settled, r.b26_settled, hx(r.final_digest).substr(0, 16).c_str());
    if (m == Mode::Holder) {   // restart: the close replays from the event log
        XmrNode node2(cfg, mock, &smoke::test_point_check);
        try { node2.bring_up(); r.replay_digest = node2.ledger().owed_digest(); } catch (...) {}
    }
    return r;
}
} // namespace

int main() {
    std::printf("v37_xmr_epoch_connect_kat: LANE-EPOCH E1 through FinalizeConnect (D_conf %llu, N %llu)\n",
                (unsigned long long)kD, (unsigned long long)kN);
    const auto tmp = std::filesystem::temp_directory_path() / ("v37_epoch_connect_" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    const Run b = run(Mode::Base, tmp), f = run(Mode::Fresh, tmp), h = run(Mode::Holder, tmp);
    check(b.held_now >= 1 && b.cursor < 5 && !b.opener_settled,
          "BASE: the unresolvable epoch-0 block is HELD, cursor frozen at " + std::to_string(b.cursor) + ", the opener never booked");
    check(f.held_now == 0 && f.held_entered == 0 && f.epoch_decided == 3 && f.obs_refused == 0,
          "FRESH: 3 epoch-0 blocks decided by the epoch rule, 0 held, 0 vote observations");
    check(f.cursor >= kTop - kD - 1 && f.opener_settled && f.b26_settled,
          "FRESH: cursor walks to " + std::to_string(f.cursor) + ", the opener and the epoch-1 blocks SETTLE");
    check(h.held_now == 0 && h.epoch_decided == 0 && h.closed_rows >= 1 && h.opener_settled && h.b26_settled,
          "HOLDER: books its own history, closes " + std::to_string(h.closed_rows) + " row(s) at the opener, settles epoch 1");
    int shared = 0, diff = 0;
    for (const auto& [cur, d] : f.digest_at) {
        if (cur < 20 + kD) continue;   // from the opener's FINALIZE on
        auto it = h.digest_at.find(cur);
        if (it == h.digest_at.end()) continue;
        ++shared; if (!(it->second == d)) ++diff;
    }
    check(shared >= 10 && diff == 0, "M3: owed_digest HOLDER == FRESH at every shared cursor from the opener's finalize (" +
                                          std::to_string(shared) + " cursors, " + std::to_string(diff) + " mismatches)");
    check(f.final_digest == h.final_digest && h.replay_digest == h.final_digest,
          "final digests equal; the holder's restart replays the closed ledger to the same digest");
    std::filesystem::remove_all(tmp);
    std::printf("v37_xmr_epoch_connect_kat: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
