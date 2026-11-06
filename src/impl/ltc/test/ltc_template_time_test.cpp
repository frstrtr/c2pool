// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The embedded LTC template's time never falls at or below the median time
// past of its parent (rides share_test): litecoind refuses such a block
// (time-too-old, validation.cpp:3653) and dates its own templates
// max(MTP + 1, now) (miner.cpp:31). With the last 11 headers ahead of the
// local clock the template's curtime and mintime are above the MTP; with a
// clock ahead of it, curtime is the clock.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/template_builder.hpp>

#include <impl/ltc/test/ltc_mined_headers.hpp>

namespace {

using namespace ltc::coin;

BlockHeaderType testnet_genesis() { return ltc_test::easy_testnet_genesis(); }

/// Genesis, then one mined header per timestamp.
void grow(HeaderChain& chain, const std::vector<uint32_t>& timestamps)
{
    ASSERT_TRUE(chain.init());
    ASSERT_TRUE(chain.add_header(testnet_genesis()));
    uint256 prev = Hash(pack(testnet_genesis()).get_span());
    for (size_t i = 0; i < timestamps.size(); ++i) {
        BlockHeaderType h;
        h.m_version = 0x20000000;
        h.m_previous_block = prev;
        h.m_merkle_root.SetHex(std::to_string(500 + i));
        h.m_timestamp = timestamps[i];
        h.m_bits = ltc_test::kEasyBits;
        h.m_nonce = static_cast<uint32_t>(i) << 16;
        ltc_test::mine(h);
        ASSERT_TRUE(chain.add_header(h)) << "header " << i;
        prev = Hash(pack(h).get_span());
    }
}

} // namespace

TEST(LtcTemplateTime, CurtimeNeverAtOrBelowMtp)
{
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    std::vector<uint32_t> ts;
    for (uint32_t i = 0; i < 11; ++i)
        ts.push_back(now + 7200 + i * 150);
    HeaderChain chain(ltc_test::easy_testnet_params());
    grow(chain, ts);
    const int64_t mtp = now + 7200 + 5 * 150;   // the 6th of the last 11

    Mempool pool;
    auto wd = TemplateBuilder::build_template(chain, pool, /*is_testnet=*/true);
    ASSERT_TRUE(wd.has_value());
    const int64_t curtime = wd->m_data["curtime"].get<int64_t>();
    EXPECT_GT(curtime, mtp) << "time-too-old: curtime " << curtime << " <= MTP " << mtp;
    EXPECT_EQ(wd->m_data["mintime"].get<int64_t>(), mtp + 1);

    // A clock ahead of the MTP is used as is.
    HeaderChain past(ltc_test::easy_testnet_params());
    grow(past, {now - 3000, now - 2000, now - 1000});
    auto wd2 = TemplateBuilder::build_template(past, pool, /*is_testnet=*/true);
    ASSERT_TRUE(wd2.has_value());
    EXPECT_GE(wd2->m_data["curtime"].get<int64_t>(), static_cast<int64_t>(now));
    EXPECT_LE(wd2->m_data["curtime"].get<int64_t>(), static_cast<int64_t>(now) + 5);
}
