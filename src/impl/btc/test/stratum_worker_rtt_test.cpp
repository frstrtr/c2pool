// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// Stratum latency refresh -- the dashboard's per-connection Latency column
// reads WorkerInfo::rtt_ms from BTCWorkSource's worker registry.
//
// The stratum session samples the kernel TCP RTT at authorize (into the
// registered WorkerInfo) and again on every accepted submit through
// IWorkSource::update_stratum_worker_rtt (core/stratum_server.cpp). Before this
// fix BTCWorkSource did not override it, so the base no-op dropped every
// submit-time sample and stratum.html showed the connect-time reading forever.
// Same defect and same fix as the DASH work source (PR #2033).
//
// Folded into the existing btc_share_test target (never a standalone
// add_executable -- those silently report "Not Run"; see PR #868).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/btc/stratum/work_source.hpp>
#include <impl/btc/coin/header_chain.hpp>
#include <impl/btc/coin/mempool.hpp>
#include <core/stratum_types.hpp>

#include <memory>
#include <string>
#include <vector>

namespace {

// A BTCWorkSource over default coin deps; the submit callback is never hit.
struct Fixture {
    btc::coin::BTCChainParams params = btc::coin::BTCChainParams::mainnet();
    btc::coin::HeaderChain    chain{params};
    btc::coin::Mempool        mempool;

    std::unique_ptr<btc::stratum::BTCWorkSource> make()
    {
        auto fn = [](const std::vector<unsigned char>&, uint32_t) -> bool { return true; };
        return std::make_unique<btc::stratum::BTCWorkSource>(
            chain, mempool, /*is_testnet=*/false, fn);
    }
};

} // namespace

TEST(BtcStratumWorkerRtt, RefreshesAfterRegistration)
{
    Fixture fx;
    auto ws = fx.make();
    core::stratum::WorkerInfo info;
    info.username    = "1BitcoinEaterAddressDontSendf59kuE.r14";
    info.worker_name = "r14";
    info.rtt_ms      = 90.4;   // sampled at authorize
    ws->register_stratum_worker("sess-1", info);
    ASSERT_DOUBLE_EQ(ws->snapshot_stratum_workers().at("sess-1").rtt_ms, 90.4);

    ws->update_stratum_worker_rtt("sess-1", 23.1);
    EXPECT_DOUBLE_EQ(ws->snapshot_stratum_workers().at("sess-1").rtt_ms, 23.1)
        << "a submit-time RTT sample replaces the connect-time one";

    // The share-stats update leaves the fresh RTT alone.
    ws->update_stratum_worker("sess-1", 1.0e12, 0.0, 16.0, 4, 0, 0);
    EXPECT_DOUBLE_EQ(ws->snapshot_stratum_workers().at("sess-1").rtt_ms, 23.1);

    // An unknown session is dropped, never inserted.
    ws->update_stratum_worker_rtt("sess-unknown", 5.0);
    EXPECT_EQ(ws->snapshot_stratum_workers().count("sess-unknown"), 0u);

    ws->unregister_stratum_worker("sess-1");
    EXPECT_TRUE(ws->snapshot_stratum_workers().empty());
}
