// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <string>

#include <nlohmann/json.hpp>

#include <core/web_server.hpp>
#include <core/uint256.hpp>

// ---------------------------------------------------------------------------
// KATs for core::MiningInterface::rest_recent_blocks -> node-role honesty (#942).
//
// A relay-only node learns some blocks over P2P from peers rather than finding
// them itself. Those relay-learned records carry NO local share_hash and NO
// miner address, and no local timing was ever computed for them. Before this
// fix the endpoint labelled every timing-less block luck_method="first_block"
// -- fabricating a computed-luck claim for blocks this node never found -- and
// surfaced the timing fields as a real-looking 0.0, so the dashboard rendered
// ten empty-but-numeric fields as if they were measured.
//
// The honesty rule these lock, in both directions:
//   * RELAY-LEARNED (no share_hash, no miner): found_locally is false,
//     luck_method is "relayed", and the timing-derived fields (luck,
//     time_to_find, expected_time) are honest-absent null, never 0.
//   * LOCALLY-FOUND (share_hash + miner present): found_locally is true,
//     luck_method is a real timing label, and luck is a genuine number.
//
// Both FAIL WITHOUT THE FIX: before it there is no found_locally key at all,
// the relay block reports luck_method=="first_block" not "relayed", and its
// luck is 0.0 rather than null.
// ---------------------------------------------------------------------------

namespace {

// Locate a recorded block by hash in the /recent_blocks array.
nlohmann::json find_block(const nlohmann::json& arr, const std::string& hash) {
    for (const auto& b : arr)
        if (b.contains("hash") && b["hash"].get<std::string>() == hash)
            return b;
    return nlohmann::json(nullptr);
}

} // namespace

// RELAY-LEARNED: no local share/miner -> found_locally false, luck_method
// "relayed", timing fields honest-absent null (never a fabricated 0).
TEST(RelayBlockHonesty, RelayLearnedBlockIsHonestlyLabelled) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);

    const std::string h =
        "1111111111111111111111111111111111111111111111111111111111111111";
    // Relay path: empty miner + empty share_hash (this node did not find it).
    mi.record_found_block(/*height=*/900000, uint256S(h), /*ts=*/1750000000,
                          /*chain=*/"LTC", /*miner=*/"", /*share_hash=*/"");

    auto blk = find_block(mi.rest_recent_blocks(), h);
    ASSERT_TRUE(blk.is_object()) << "relay-learned block must be recorded";

    ASSERT_TRUE(blk.contains("found_locally"))
        << "found_locally is the node-role signal the dashboard reads";
    EXPECT_FALSE(blk["found_locally"].get<bool>())
        << "a block with no local share/miner was not found by this node";

    EXPECT_EQ(blk["luck_method"].get<std::string>(), "relayed")
        << "must not fabricate a computed-luck label for a relay-learned block";

    EXPECT_TRUE(blk["luck"].is_null())
        << "relay-learned luck is unknown -- honest-absent null, not 0";
    EXPECT_TRUE(blk["time_to_find"].is_null())
        << "relay-learned time_to_find is unknown -- honest-absent null, not 0";
    EXPECT_TRUE(blk["expected_time"].is_null())
        << "relay-learned expected_time is unknown -- honest-absent null, not 0";
}

// LOCALLY-FOUND: real share + miner -> found_locally true, real timing label,
// luck surfaced as a genuine number.
TEST(RelayBlockHonesty, LocallyFoundBlockKeepsRealTiming) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);

    const std::string h =
        "2222222222222222222222222222222222222222222222222222222222222222";
    // Found locally: real payout address + real share hash.
    mi.record_found_block(/*height=*/900001, uint256S(h), /*ts=*/1750000100,
                          /*chain=*/"LTC",
                          /*miner=*/"LhK2b7hQ8example",
                          /*share_hash=*/"deadbeef");

    auto blk = find_block(mi.rest_recent_blocks(), h);
    ASSERT_TRUE(blk.is_object()) << "locally-found block must be recorded";

    ASSERT_TRUE(blk.contains("found_locally"));
    EXPECT_TRUE(blk["found_locally"].get<bool>())
        << "a block with a real local share/miner was found by this node";

    EXPECT_NE(blk["luck_method"].get<std::string>(), "relayed")
        << "a locally-found block must carry a real timing label, not 'relayed'";

    // 2026-08-05 revision: this block is the FIRST in its ledger, so no
    // time_to_find exists and no luck was ever computed. The original
    // assertion pinned that fabricated 0.0 as "a genuine measured number" —
    // and the hotel's luck-trend chart faithfully drew those zeros as a
    // catastrophe. An uncomputed luck is honest-absent null on found blocks
    // too; luck_method=first_block is the label that says why.
    EXPECT_TRUE(blk["luck"].is_null())
        << "a first block has no luck measurement; 0 would be a fabricated one";
    EXPECT_EQ(blk["luck_method"].get<std::string>(), "first_block");
}
