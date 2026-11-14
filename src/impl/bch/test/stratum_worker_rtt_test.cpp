// SPDX-License-Identifier: AGPL-3.0-or-later
//
// BCH stratum latency refresh KAT (BCH half of the DASH fix in PR #2033).
//
// The stratum session samples the kernel TCP RTT at authorize (into the
// WorkerInfo it registers) and again on every accepted submit, through
// IWorkSource::update_stratum_worker_rtt (src/core/stratum_server.cpp). The
// base is a no-op. BCHWorkSource did not override it, so the registry kept the
// connect-time reading and the dashboard's Latency column froze there.
//
//   SubmitTimeRttReplacesConnectTimeRtt      FAILS without the override
//   ShareStatsUpdateLeavesFreshRttAlone      FAILS without the override
//   UnknownSessionRttUpdateIsDropped         passes both: never inserted
//   UnregisterEmptiesTheRegistry             passes both
//
// Every update goes through an IWorkSource& so the cases take the same virtual
// dispatch the stratum session does.
//
// HARNESS: the bch test tree is plain int main()/CHECK (no GTest), so this TU
// exposes run_stratum_worker_rtt_checks() and rides the already-allowlisted
// bch_embedded_block_broadcast_test executable, which already compiles
// stratum/work_source.cpp. A standalone add_executable is not in build.yml's
// --target list, so CI would never build it (the #769 "Not Run" trap).

#include "../coin/header_chain.hpp"
#include "../coin/mempool.hpp"
#include "../stratum/work_source.hpp"

#include <core/stratum_types.hpp>
#include <core/stratum_work_source.hpp>

#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

int g_failures = 0;
int g_case_failures = 0;

#define CHECK(cond, what) do { if (!(cond)) { \
    std::cerr << "  FAIL: " #cond " @ line " << __LINE__ << ": " << what << "\n"; \
    ++g_case_failures; } } while (0)
#define REQUIRE(cond, what) do { if (!(cond)) { \
    std::cerr << "  FAIL: " #cond " @ line " << __LINE__ << ": " << what << "\n"; \
    ++g_case_failures; return; } } while (0)

struct Rig {
    bch::coin::BCHChainParams params = bch::coin::BCHChainParams::mainnet();
    bch::coin::HeaderChain    chain{params};
    bch::coin::Mempool        mempool;
    std::unique_ptr<bch::stratum::BCHWorkSource> ws;

    Rig()
    {
        ws = std::make_unique<bch::stratum::BCHWorkSource>(
            chain, mempool, /*is_testnet=*/false,
            [](const std::vector<unsigned char>&, uint32_t) { return true; });
        core::stratum::WorkerInfo info;
        info.username    = "bitcoincash:qrig.B14";
        info.worker_name = "B14";
        info.rtt_ms      = 90.4;   // sampled at authorize
        ws->register_stratum_worker("sess-1", info);
    }

    core::stratum::IWorkSource& base() { return *ws; }

    double rtt(const std::string& session_id) const
    {
        return ws->get_stratum_workers().at(session_id).rtt_ms;
    }
};

void SubmitTimeRttReplacesConnectTimeRtt()
{
    Rig rig;
    REQUIRE(rig.rtt("sess-1") == 90.4, "authorize-time sample is registered");

    rig.base().update_stratum_worker_rtt("sess-1", 23.1);
    CHECK(rig.rtt("sess-1") == 23.1,
          "a submit-time RTT sample replaces the connect-time one, got " << rig.rtt("sess-1"));

    rig.base().update_stratum_worker_rtt("sess-1", 31.7);
    CHECK(rig.rtt("sess-1") == 31.7,
          "every later sample replaces the previous one, got " << rig.rtt("sess-1"));
}

void ShareStatsUpdateLeavesFreshRttAlone()
{
    Rig rig;
    rig.base().update_stratum_worker_rtt("sess-1", 23.1);
    rig.base().update_stratum_worker("sess-1", 1.0e9, 0.0, 16.0, 4, 0, 0);

    const auto w = rig.ws->get_stratum_workers().at("sess-1");
    CHECK(w.rtt_ms == 23.1, "share-stats update must not touch rtt_ms, got " << w.rtt_ms);
    CHECK(w.accepted == 4u, "share-stats update still lands, got " << w.accepted);
}

void UnknownSessionRttUpdateIsDropped()
{
    Rig rig;
    rig.base().update_stratum_worker_rtt("sess-unknown", 5.0);

    const auto workers = rig.ws->get_stratum_workers();
    CHECK(workers.count("sess-unknown") == 0u, "an unknown session is dropped, never inserted");
    CHECK(workers.size() == 1u, "registry size unchanged, got " << workers.size());
    CHECK(workers.at("sess-1").rtt_ms == 90.4, "the registered session is untouched");
}

void UnregisterEmptiesTheRegistry()
{
    Rig rig;
    rig.base().update_stratum_worker_rtt("sess-1", 23.1);
    rig.base().unregister_stratum_worker("sess-1");
    CHECK(rig.ws->get_stratum_workers().empty(), "unregister removes the session");

    rig.base().update_stratum_worker_rtt("sess-1", 12.0);
    CHECK(rig.ws->get_stratum_workers().empty(),
          "an RTT sample racing the disconnect does not resurrect the session");
}

void run_case(const char* name, void (*fn)())
{
    g_case_failures = 0;
    try {
        fn();
    } catch (const std::exception& e) {
        std::cerr << "  FAIL: threw: " << e.what() << "\n";
        ++g_case_failures;
    }
    std::cout << "[" << (g_case_failures == 0 ? "PASS" : "FAIL") << "] BchStratumWorkerRtt."
              << name << "\n";
    g_failures += g_case_failures;
}

} // namespace

int run_stratum_worker_rtt_checks()
{
    g_failures = 0;
    run_case("SubmitTimeRttReplacesConnectTimeRtt", SubmitTimeRttReplacesConnectTimeRtt);
    run_case("ShareStatsUpdateLeavesFreshRttAlone", ShareStatsUpdateLeavesFreshRttAlone);
    run_case("UnknownSessionRttUpdateIsDropped", UnknownSessionRttUpdateIsDropped);
    run_case("UnregisterEmptiesTheRegistry", UnregisterEmptiesTheRegistry);
    return g_failures;
}
