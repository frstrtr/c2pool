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

#include <fstream>
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

TEST(DgbWorkGate, MainDgbRunsTheGate)
{
    std::ifstream f(DGB_MAIN_SRC);
    ASSERT_TRUE(f.good()) << DGB_MAIN_SRC;
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string s = ss.str();
    EXPECT_NE(s.find("const bool require_peers = !testnet && !regtest;"), std::string::npos);
    EXPECT_NE(s.find("in.sharechain_peers = p2p_node.get_peer_info_json().size();"), std::string::npos);
    EXPECT_NE(s.find("if (coin_p2p && coin_p2p->is_handshake_complete())"), std::string::npos);
    EXPECT_NE(s.find("ws->set_work_hold(reason);"), std::string::npos);
    EXPECT_NE(s.find("srv->drop_sessions(srv->get_session_count())"), std::string::npos);
    // Stopped before the server it closes sessions on goes.
    const auto stop = s.find("if (stop_work_gate) stop_work_gate();");
    const auto reset = s.rfind("stratum_server.reset();");
    ASSERT_NE(stop, std::string::npos);
    EXPECT_LT(stop, reset);
}
