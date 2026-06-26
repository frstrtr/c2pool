// Regression lock for the #506 follow-up: a persisted addrs.json must never
// re-feed the dialer of an isolated net (--regtest) after the regtest gate runs.
//
// Root cause (proven on the live regtest standup): the AddrStore constructor
// reloads config_path()/<net>/addrs.json at startup. A prior regtest run
// accumulates PUBLIC peers in that file via addr-exchange, so on restart they
// are reloaded into the outbound dial set even though the store path is already
// net-namespaced ("bitcoin_regtest"). The fix btc::Node applies under --regtest
// is AddrStore::clear() before seeding bootstrap -> dial set starts empty.
//
// This KAT exercises the REAL persistence path (add()->save()->reconstruct->
// from_json) and the REAL gate primitive (clear()) that the btc node ctor calls.
#include <gtest/gtest.h>

#include <filesystem>
#include <core/addr_store.hpp>
#include <core/filesystem.hpp>
#include <core/netaddress.hpp>

using namespace core;

namespace {
// Unique coin/net name so the KAT never collides with a real config dir.
const std::string kTestNet = "btc_regtest_addrstore_isolation_kat";

std::filesystem::path test_dir()
{
    return core::filesystem::config_path() / kTestNet;
}

void wipe()
{
    std::error_code ec;
    std::filesystem::remove_all(test_dir(), ec);
}
} // namespace

// A persisted store reloads its public peers on reconstruct (the leak vector),
// the regtest gate (clear()) empties the dial set, and the on-disk file SURVIVES
// the clear (no user-data loss; the mainnet/testnet path is never gated).
TEST(AddrStoreRegtestIsolation, PollutedFileNeverFeedsDialerAfterGate)
{
    std::filesystem::create_directories(test_dir());
    wipe();
    std::filesystem::create_directories(test_dir());

    // Populate + persist three PUBLIC peers (simulates addr-exchange pollution).
    {
        AddrStore seeded(kTestNet);
        seeded.add(NetService("8.8.8.8", uint16_t(9333)), {0, 1, 1});
        seeded.add(NetService("1.1.1.1", uint16_t(9333)), {0, 1, 1});
        seeded.add(NetService("9.9.9.9", uint16_t(9333)), {0, 1, 1});
        ASSERT_EQ(seeded.len(), 3u);
    }

    // Fresh construct reloads the persisted public peers -> THIS is the leak the
    // dialer would consume at startup if left ungated.
    AddrStore reloaded(kTestNet);
    EXPECT_EQ(reloaded.len(), 3u) << "persisted addrs.json must round-trip (leak vector)";

    // The regtest gate (exactly what btc::Node calls under --regtest) empties the
    // in-memory dial set -> bootstrap-only -> zero outbound dials.
    reloaded.clear();
    EXPECT_EQ(reloaded.len(), 0u) << "regtest gate must yield an empty dial set";

    // The gate must NOT destroy the persisted file: a non-gated (mainnet/testnet)
    // construct still reloads it intact. Proves clear() is dial-set-only.
    AddrStore mainnet_view(kTestNet);
    EXPECT_EQ(mainnet_view.len(), 3u) << "clear() must not touch the on-disk file";

    wipe();
}
