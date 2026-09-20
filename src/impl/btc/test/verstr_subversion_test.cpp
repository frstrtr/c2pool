// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc VERSTR (P2P sub_version) KATs -- locks the lane-labeled version string
// btc advertises in the version handshake (send_version reads m_software_version,
// node.cpp:278). Before this change every lane shipped the generic default
// "/c2pool:0.1/", so a third-party operator on the live public sharechain had no
// way to tell the btc lane from ltc/dgb by sub_version.
//
// Drives the REAL btc::make_subversion helper (node.hpp) with real string types
// -- NOT a mock. main_btc composes the live advertised string as
// make_subversion("btc", C2POOL_VERSION) and feeds it to set_software_version();
// that call site (main_btc.cpp, after the p2p_node lifetime assert) is verified
// by reading the source, not by this unit test (main() is not unit-testable).
//
// Canonical p2pool-dash caps sub_version at 512 bytes (p2p.py:154); the cap is
// asserted here so an over-long build-version string can never corrupt the wire
// handshake.
//
// Rides the already-allowlisted btc_share_test executable (no new add_executable,
// no build.yml target-allowlist change -- #769 NOT_RUN trap avoided).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <string>

#include "../node.hpp"

namespace
{

TEST(BtcVerstrSubversion, LaneLabeledExactFormat)
{
    // The composed advertisement is "c2pool-<lane>/<version>".
    EXPECT_EQ(btc::make_subversion("btc", "0.2.5"), "c2pool-btc/0.2.5");
}

TEST(BtcVerstrSubversion, DistinguishesLaneFromGenericDefault)
{
    const std::string v = btc::make_subversion("btc", "1.2.3");
    // No longer the generic pre-VERSTR default that hid the lane identity.
    EXPECT_NE(v, "/c2pool:0.1/");
    EXPECT_EQ(v.rfind("c2pool-btc/", 0), 0u);   // starts with the lane tag
}

TEST(BtcVerstrSubversion, CapsAt512BytesCanonicalLimit)
{
    // p2p.py:154 truncates sub_version[:512]; an over-long version must not
    // overflow the handshake field.
    const std::string huge(600, 'x');
    const std::string v = btc::make_subversion("btc", huge);
    EXPECT_EQ(v.size(), 512u);
    EXPECT_EQ(v.rfind("c2pool-btc/", 0), 0u);   // prefix survives the cap
}

TEST(BtcVerstrSubversion, ShortVersionNotPadded)
{
    const std::string v = btc::make_subversion("btc", "dev");
    EXPECT_EQ(v, "c2pool-btc/dev");
    EXPECT_LE(v.size(), 512u);
}

} // namespace
