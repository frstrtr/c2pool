// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The DGB stratum work gate (rides dgb_work_source_test): no work and no
// authorize without sharechain peers (mainnet) or with digibyted lost for
// more than 60 s, as python work.py preprocess_request; the live sessions are
// closed once a hold has lasted 15 s.
// ---------------------------------------------------------------------------

#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/config_coin.hpp>
#include <impl/dgb/stratum/work_source.hpp>
#include <impl/dgb/stratum_work_gate.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <boost/asio/io_context.hpp>
#include <chrono>
#include <fstream>
#include <functional>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#ifndef DGB_MAIN_SRC
#error "DGB_MAIN_SRC must name src/c2pool/main_dgb.cpp"
#endif

namespace {
const std::string kNoPeers = "p2pool is not connected to any peers";
const std::string kLost = "lost contact with digibyted";
} // namespace

TEST(DgbWorkGate, ReasonsAsThePythonNetwork)
{
    dgb::WorkGateInputs in;
    in.require_peers = true;
    in.sharechain_peers = 0;
    EXPECT_EQ(dgb::work_gate_reason(in), kNoPeers);
    in.sharechain_peers = 2;
    EXPECT_EQ(dgb::work_gate_reason(in), "");
    // testnet / regtest are not PERSIST: no peers is fine there.
    in.require_peers = false;
    in.sharechain_peers = 0;
    EXPECT_EQ(dgb::work_gate_reason(in), "");
    // digibyted: lost after more than 60 s (python: now > last_update + 60).
    in.coin_daemon = true;
    in.coin_contact_age_sec = 60;
    EXPECT_EQ(dgb::work_gate_reason(in), "");
    in.coin_contact_age_sec = 61;
    EXPECT_EQ(dgb::work_gate_reason(in), kLost);
    // No coin peer dialled: nothing to lose.
    in.coin_daemon = false;
    in.coin_contact_age_sec = 100000;
    EXPECT_EQ(dgb::work_gate_reason(in), "");
    // Python's order: peers first.
    in.require_peers = true;
    in.coin_daemon = true;
    EXPECT_EQ(dgb::work_gate_reason(in), kNoPeers);
}

TEST(DgbWorkGate, LiveSessionsAreClosedOncePerHoldAfter15s)
{
    using A = dgb::WorkGateWatch::Action;
    dgb::WorkGateWatch w;
    EXPECT_EQ(w.tick("", 0), A::none);
    EXPECT_EQ(w.tick(kNoPeers, 100), A::none);
    EXPECT_EQ(w.tick(kNoPeers, 114), A::none);
    EXPECT_EQ(w.tick(kNoPeers, 115), A::drop_sessions);
    EXPECT_EQ(w.tick(kNoPeers, 116), A::none);
    EXPECT_EQ(w.tick(kLost, 500), A::none) << "the same hold, another reason: closed already";
    // A short blip never closes sessions.
    EXPECT_EQ(w.tick("", 501), A::none);
    EXPECT_EQ(w.tick(kNoPeers, 600), A::none);
    EXPECT_EQ(w.tick("", 610), A::none);
    // A new hold closes them again.
    EXPECT_EQ(w.tick(kLost, 700), A::none);
    EXPECT_EQ(w.tick(kLost, 715), A::drop_sessions);
}

TEST(DgbWorkGate, HeldWorkSourceServesNoTemplateAndRefusesAuthorize)
{
    c2pool::dgb::HeaderChain hc;
    dgb::coin::Mempool mempool;
    hc.set_base_height(20000000);
    dgb::stratum::DGBWorkSource ws(hc, mempool, false, [](const std::vector<unsigned char>&, uint32_t) { return false; },
                                   [](uint32_t h) -> uint64_t { return dgb::CoinParams::subsidy(h); });
    ws.set_gbt_tip_fn([]() -> std::optional<dgb::stratum::DGBWorkSource::GbtTip> {
        return dgb::stratum::DGBWorkSource::GbtTip{std::string(64, '1'), "1a00ffff", 20000000};
    });
    const std::string login = "DQ8AwqR2XJE9G5dSEfspJYH7Spre85dj6L";
    ASSERT_FALSE(ws.get_current_work_template().empty());
    ASSERT_EQ(ws.authorize_refusal(login), "");

    ws.set_work_hold(kNoPeers);
    EXPECT_EQ(ws.work_hold(), kNoPeers);
    EXPECT_TRUE(ws.get_current_work_template().empty()) << "held: no template, so no job";
    EXPECT_EQ(ws.authorize_refusal(login), kNoPeers);
    EXPECT_EQ(ws.authorize_refusal(""), kNoPeers) << "the gate first, as preprocess_request";

    ws.set_work_hold("");
    EXPECT_FALSE(ws.get_current_work_template().empty());
    EXPECT_EQ(ws.authorize_refusal(login), "");
}

// Review 7793bfb6c #6: the tick itself, through fakes.
namespace {
struct FakeWs {
    std::string hold;
    void set_work_hold(const std::string& r) { hold = r; }
};
struct FakeSrv {
    size_t sessions = 3;
    int drops = 0;
    size_t get_session_count() const { return sessions; }
    size_t drop_sessions(size_t n)
    {
        ++drops;
        const size_t k = std::min(n, sessions);
        sessions -= k;
        return k;
    }
};
dgb::WorkGateObservation healthy()
{
    dgb::WorkGateObservation ob;
    ob.require_peers = true;
    ob.sharechain_peers = 3;
    ob.coin_dialled = true;
    ob.coin_handshaken = true;
    ob.embedded_serves = true;
    ob.best_share_null = false;
    return ob;
}
} // namespace

TEST(DgbWorkGate, TheTickHoldsReleasesAndClosesSessionsOnce)
{
    dgb::WorkGateState st;
    st.last_contact = 1000;
    FakeWs ws;
    FakeSrv srv;
    auto ob = healthy();
    EXPECT_EQ(dgb::work_gate_tick(st, ob, 1000, ws, srv), "");
    EXPECT_EQ(ws.hold, "");

    // No peers on mainnet: held at once, sessions closed once after 15 s.
    ob.sharechain_peers = 0;
    EXPECT_EQ(dgb::work_gate_tick(st, ob, 1001, ws, srv), kNoPeers);
    EXPECT_EQ(ws.hold, kNoPeers);
    EXPECT_EQ(dgb::work_gate_tick(st, ob, 1015, ws, srv), kNoPeers);
    EXPECT_EQ(srv.drops, 0);
    dgb::work_gate_tick(st, ob, 1016, ws, srv);
    EXPECT_EQ(srv.drops, 1);
    EXPECT_EQ(srv.sessions, 0u) << "not every session was closed";
    srv.sessions = 2;
    dgb::work_gate_tick(st, ob, 1100, ws, srv);
    EXPECT_EQ(srv.drops, 1) << "closed twice in one hold";
    ob.sharechain_peers = 2;
    EXPECT_EQ(dgb::work_gate_tick(st, ob, 1101, ws, srv), "");
    EXPECT_EQ(ws.hold, "") << "the hold was not released";

    // Testnet / regtest (not PERSIST): no peers and no best share are fine.
    auto t = ob;
    t.require_peers = false;
    t.sharechain_peers = 0;
    t.best_share_null = true;
    EXPECT_EQ(dgb::work_gate_tick(st, t, 1102, ws, srv), "");

    // No best share on mainnet (the revive): downloading shares.
    ob.best_share_null = true;
    EXPECT_EQ(dgb::work_gate_tick(st, ob, 1103, ws, srv), "p2pool is downloading shares");
    ob.best_share_null = false;
    EXPECT_EQ(dgb::work_gate_tick(st, ob, 1104, ws, srv), "");
}

TEST(DgbWorkGate, ContactCountsOnlyWhileWorkComesFromTheEmbeddedChain)
{
    dgb::WorkGateState st;
    st.last_contact = 1000;
    FakeWs ws;
    FakeSrv srv;
    auto ob = healthy();
    dgb::work_gate_tick(st, ob, 1000, ws, srv);
    ob.coin_handshaken = false;
    EXPECT_EQ(dgb::work_gate_tick(st, ob, 1060, ws, srv), "") << "60 s is still contact";
    EXPECT_EQ(dgb::work_gate_tick(st, ob, 1061, ws, srv), kLost);
    // A handshake seen again restores contact.
    ob.coin_handshaken = true;
    EXPECT_EQ(dgb::work_gate_tick(st, ob, 1062, ws, srv), "");
    // Work from digibyted's GBT (embedded chain behind or unfed): the coin
    // P2P is not its contact; a failed GBT gives no work by itself.
    ob.coin_handshaken = false;
    ob.embedded_serves = false;
    EXPECT_EQ(dgb::work_gate_tick(st, ob, 5000, ws, srv), "");
    // No coin peer dialled at all (--coin-p2p-discover): no contact check.
    ob.embedded_serves = true;
    ob.coin_dialled = false;
    EXPECT_EQ(dgb::work_gate_tick(st, ob, 9000, ws, srv), "");
}

TEST(DgbWorkGate, StartPeriodicRepeatsAndStops)
{
    boost::asio::io_context ioc;
    int ticks = 0;
    std::function<void()> stop;
    stop = dgb::start_periodic(ioc, std::chrono::milliseconds(5), [&] {
        if (++ticks == 3)
            stop();
    });
    ioc.run_for(std::chrono::milliseconds(500));
    EXPECT_EQ(ticks, 3) << "the periodic tick did not repeat, or did not stop";
}

TEST(DgbWorkGate, MainDgbRunsTheGate)
{
    std::ifstream f(DGB_MAIN_SRC);
    ASSERT_TRUE(f.good()) << DGB_MAIN_SRC;
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string s = ss.str();
    const auto at = s.find("stop_work_gate = dgb::start_periodic(ioc, dgb::kWorkGateTick,");
    ASSERT_NE(at, std::string::npos);
    const std::string body = s.substr(at, s.find("});", at) - at);
    for (const char* line : {"ob.require_peers = require_peers;",
                             "ob.sharechain_peers = p2p_node.get_peer_info_json().size();",
                             "ob.coin_dialled = static_cast<bool>(coin_p2p);",
                             "ob.coin_handshaken = coin_p2p && coin_p2p->is_handshake_complete();",
                             "ob.embedded_serves = ws->embedded_chain_serves();",
                             "ob.best_share_null = cell->get().IsNull();",
                             "dgb::work_gate_tick(*gate, ob, steady_sec(), *ws, *srv);"})
        EXPECT_NE(body.find(line), std::string::npos) << line;
    EXPECT_NE(s.find("const bool require_peers = !testnet && !regtest;"), std::string::npos);
    EXPECT_NE(s.find("gate->last_contact = steady_sec();"), std::string::npos);
    // Stopped before the server it closes sessions on goes.
    const auto stop = s.find("if (stop_work_gate) stop_work_gate();");
    const auto reset = s.rfind("stratum_server.reset();");
    ASSERT_NE(stop, std::string::npos);
    EXPECT_LT(stop, reset);
}
