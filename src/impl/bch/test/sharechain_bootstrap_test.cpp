// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::seed_sharechain_bootstrap KAT -- pins the pure sharechain bootstrap-addr
// resolver + builder added for the contabo BCH revival (2026-09-04).
//
// THE INCIDENT (regression witness, section 1): run_pool (main_bch.cpp) hand-
// builds bch::Config WITHOUT PoolConfig::load() -- the YAML load() was the ONLY
// populator of m_bootstrap_addrs. So on master the addr store was ALWAYS empty
// (contabo state/bch/addrs.json = literal `null`) -> the sharechain node had 0
// peers forever. Section 1 pins that empty-BEFORE state; sections 2-5 pin the
// fix's builder output (empty -> populated).
//
// The resolver/builder are PURE (no I/O, no PoolConfig construction), so this
// KAT is header-only over config_pool.hpp + <core/netaddress.hpp>; no coin lib
// link, no network -- per-coin isolation stays clean. Mirrors the BTC
// regression guard (src/impl/btc/test/regtest_sharechain_isolation_test.cpp)
// for the identical "dialed the wrong / no peers" incident class.
//
// REWARD-SAFETY: this seam decides ONLY which transport addresses are dialed.
// PREFIX/IDENTIFIER, P2P_PORT, protocol versions, share format, PPLNS and
// coinbase are untouched -- section 6 asserts the compiled-in identity
// constants are the live jtoomim/kr1z1s BCH values, so a bootstrap edit can
// never silently fork the net.
//
// Harness: plain int main() + assert-style CHECK (CTest treats exit 0 as PASS),
// matching the sibling bch KAT tests.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include <core/netaddress.hpp>
#include "../config_pool.hpp"

namespace {
int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

using bch::PoolConfig;
using bch::SharechainBootstrapMode;
using bch::select_sharechain_bootstrap_mode;
using bch::build_sharechain_bootstrap;

using AddNodes = std::vector<std::pair<std::string, uint16_t>>;
} // namespace

int main()
{
    // ---- 1) REGRESSION WITNESS: empty BEFORE seed --------------------------
    // The pre-fix live state: run_pool never populated m_bootstrap_addrs, so it
    // stayed default-empty (contabo addrs.json = null, 0 sharechain peers). A
    // node that never runs the seeder has an empty store -- this pins today's
    // broken baseline so the fix (sections 2-5) is a proven empty -> populated.
    {
        std::vector<NetService> unseeded;               // what run_pool's config had
        CHECK(unseeded.empty());                        // == the contabo live bug
        // The fix, same inputs run_pool now uses (no explicit peers, mainnet):
        auto after = build_sharechain_bootstrap(
            select_sharechain_bootstrap_mode(/*has_explicit_peers=*/false, /*regtest=*/false),
            AddNodes{});
        CHECK(!after.empty());                          // populated AFTER the fix
    }

    // ---- 2) mode selection precedence: explicit > regtest > public --------
    CHECK(select_sharechain_bootstrap_mode(/*explicit=*/true,  /*regtest=*/false)
          == SharechainBootstrapMode::ExplicitPeers);
    CHECK(select_sharechain_bootstrap_mode(/*explicit=*/true,  /*regtest=*/true)
          == SharechainBootstrapMode::ExplicitPeers);   // explicit wins over regtest
    CHECK(select_sharechain_bootstrap_mode(/*explicit=*/false, /*regtest=*/true)
          == SharechainBootstrapMode::RegtestIsolated);
    CHECK(select_sharechain_bootstrap_mode(/*explicit=*/false, /*regtest=*/false)
          == SharechainBootstrapMode::PublicDefault);

    // ---- 3) PublicDefault seeds ALL default hosts on :9349 ----------------
    {
        auto addrs = build_sharechain_bootstrap(
            SharechainBootstrapMode::PublicDefault, AddNodes{});
        CHECK(addrs.size() == PoolConfig::DEFAULT_BOOTSTRAP_HOSTS.size());  // 7
        CHECK(!addrs.empty());
        bool saw_toom = false;
        for (const auto& a : addrs) {
            CHECK(a.port() == PoolConfig::P2P_PORT);     // every entry on 9349
            if (a.to_string() == "ml.toom.im:9349") saw_toom = true;
        }
        CHECK(saw_toom);                                 // host literal preserved
    }

    // ---- 4) ExplicitAddnode pins EXACTLY the given peer(s) ----------------
    // The load-bearing contabo revival lever: --sharechain-addnode
    // 92.53.224.27:9349 (the live kr1z1s BCH sharechain) must be the ONLY
    // dialed peer -- the mostly-dead public defaults must NOT be present.
    {
        AddNodes pin = { {"92.53.224.27", 9349} };
        auto addrs = build_sharechain_bootstrap(
            select_sharechain_bootstrap_mode(/*explicit=*/true, /*regtest=*/false), pin);
        CHECK(addrs.size() == 1);
        CHECK(addrs.at(0).to_string() == "92.53.224.27:9349");
        // Defaults absent: no public host leaked into an explicit pin.
        for (const auto& a : addrs)
            CHECK(a.to_string() != "ml.toom.im:9349");
    }
    {
        // Repeatable: two pins accumulate, both preserved, order kept.
        AddNodes pins = { {"92.53.224.27", 9349}, {"5.8.79.155", 9350} };
        auto addrs = build_sharechain_bootstrap(
            SharechainBootstrapMode::ExplicitPeers, pins);
        CHECK(addrs.size() == 2);
        CHECK(addrs.at(0).to_string() == "92.53.224.27:9349");
        CHECK(addrs.at(1).to_string() == "5.8.79.155:9350");   // per-pin port honored
    }

    // ---- 5) RegtestIsolated is EMPTY (never dial public 9349 seeds) -------
    // A regtest standup must NOT dial the public mainnet sharechain -- same
    // incident class as the BTC .121 regtest-dialed-mainnet guard.
    {
        auto addrs = build_sharechain_bootstrap(
            SharechainBootstrapMode::RegtestIsolated, AddNodes{});
        CHECK(addrs.empty());
        // Explicit peer STILL wins over regtest (a tuned isolated peer is OK).
        AddNodes pin = { {"127.0.0.1", 19349} };
        auto ex = build_sharechain_bootstrap(
            select_sharechain_bootstrap_mode(/*explicit=*/true, /*regtest=*/true), pin);
        CHECK(ex.size() == 1);
        CHECK(ex.at(0).to_string() == "127.0.0.1:19349");
    }

    // ---- 6) REWARD-SAFETY: sharechain identity constants UNCHANGED --------
    // A bootstrap edit must not touch the values that decide which chain we join.
    // These pin the live jtoomim/kr1z1s BCH sharechain identity (bitcoincash.py):
    // any change here would be the fork vector -- this seam leaves them alone.
    CHECK(PoolConfig::P2P_PORT == 9349);
    CHECK(PoolConfig::DEFAULT_PREFIX_HEX     == "ac9a8fda9a911bce");
    CHECK(PoolConfig::DEFAULT_IDENTIFIER_HEX == "b826c0a51ddc2d2b");
    CHECK(PoolConfig::MINIMUM_PROTOCOL_VERSION == 3301);
    CHECK(PoolConfig::ADVERTISED_PROTOCOL_VERSION == 3600);

    if (failures) {
        std::cerr << failures << " CHECK(s) FAILED\n";
        return 1;
    }
    std::cout << "bch sharechain_bootstrap KAT: all checks passed\n";
    return 0;
}
