// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// dgb::coin::CoinNode seam-contract test (#82 broadcaster-gate, RPC-fallback
// half).
//
// Locks the embedded-primary / external-RPC-fallback contract of the DGB
// CoinNode seam (core::coin::ICoinNode) that the won-block dispatch depends on.
// web_server.cpp submits a solved block through exactly this seam:
//     m_coin_node->submit_block_hex(hex, false)   (core/web_server.cpp)
// which forwards to NodeRPC::submitblock (the external-digibyted fallback that
// MUST persist alongside the embedded path). This test pins the three
// invariants that path relies on, so a regression here is caught before it can
// silently break block submission:
//   1. no work source at all            -> empty WorkView, no throw
//   2. embedded present, no RPC          -> WorkView sourced from embedded;
//                                          is_embedded()=true, has_rpc()=false
//   3. submit_block_hex w/ no RPC sink   -> false (the !m_rpc guard, NOT a throw
//                                          and NOT a crash dereferencing null)
//
// SCOPE: the no-RPC guard + embedded WorkView slice only. The LIVE submitblock
// RPC call and the m_on_block_found tracker callback are wired by the DGB
// run-loop standup (NodeBridge + web_server; main_dgb.cpp is selftest-only
// today) -- that is the remaining #82 slice and is NOT exercised here (rpc=
// nullptr in every case). p2pool-merged-v36 surface: NONE (pure local seam).
//
// Mirrors src/impl/bch/test/coin_node_seam_test.cpp; written gtest-style to
// match the sibling dgb tests (gtest_add_tests AUTO). MUST appear in BOTH the
// test/CMakeLists.txt registration AND the build.yml --target allowlist or it
// becomes a #143-style NOT_BUILT sentinel that reds master.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <string>

#include "../coin/coin_node.hpp"

namespace {

// Minimal embedded work source: returns a recognisable WorkData so the test can
// prove the seam moved THIS object's agnostic slice into the WorkView.
class FakeEmbedded : public dgb::coin::CoinNodeInterface {
public:
    int calls = 0;

    dgb::coin::rpc::WorkData getwork() override {
        ++calls;
        dgb::coin::rpc::WorkData wd;
        wd.m_data = nlohmann::json{{"marker", "embedded-dgb"}};
        wd.m_hashes.push_back(uint256(static_cast<uint64_t>(0xab)));
        wd.m_latency = 42;
        return wd;
    }

    nlohmann::json getblockchaininfo() override { return nlohmann::json::object(); }
    bool is_synced() const override { return true; }
};

} // namespace

// 1) No work source configured -> empty view, no throw (1:1 btc/bch/ltc ref).
TEST(DgbCoinNodeSeam, NoSourceEmptyView) {
    dgb::coin::CoinNode n(nullptr, nullptr);
    EXPECT_FALSE(n.is_embedded());
    EXPECT_FALSE(n.has_rpc());
    core::coin::WorkView v = n.get_work_view();
    EXPECT_TRUE(v.m_data.is_null() || v.m_data.empty());
    EXPECT_TRUE(v.m_hashes.empty());
    EXPECT_EQ(v.m_latency, 0);
}

// 2) Embedded preferred, no RPC fallback wired -> view comes from embedded.
TEST(DgbCoinNodeSeam, EmbeddedSourcedView) {
    FakeEmbedded emb;
    dgb::coin::CoinNode n(&emb, /*rpc=*/nullptr);
    EXPECT_TRUE(n.is_embedded());
    EXPECT_FALSE(n.has_rpc());
    core::coin::WorkView v = n.get_work_view();
    EXPECT_EQ(emb.calls, 1);                       // embedded WAS the source
    ASSERT_TRUE(v.m_data.contains("marker"));
    EXPECT_EQ(v.m_data["marker"], "embedded-dgb");
    EXPECT_EQ(v.m_hashes.size(), 1u);
    EXPECT_EQ(v.m_latency, 42);
}

// 3) No RPC sink -> submit_block_hex returns false (the !m_rpc guard), not a
//    throw and not a null-deref crash. This is the won-block fallback contract.
TEST(DgbCoinNodeSeam, SubmitNoRpcReturnsFalse) {
    FakeEmbedded emb;
    dgb::coin::CoinNode n(&emb, /*rpc=*/nullptr);
    EXPECT_FALSE(n.submit_block_hex("00", /*ignore_failure=*/true));

    dgb::coin::CoinNode bare(nullptr, nullptr);
    EXPECT_FALSE(bare.submit_block_hex("00", /*ignore_failure=*/false));
}