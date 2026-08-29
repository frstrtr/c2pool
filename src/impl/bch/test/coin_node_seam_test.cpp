// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin::CoinNode seam-contract test (M5 seam-wire validation).
//
// Validates the embedded-primary / external-RPC-fallback contract of the
// CoinNode seam (core::coin::ICoinNode) that EmbeddedDaemon::run() builds and
// hands to web_server. Asserts the three invariants web_server depends on:
//   1. no work source at all            -> empty WorkView (no throw)
//   2. embedded present                 -> WorkView sourced from embedded;
//                                          is_embedded()=true, has_rpc()=false
//   3. submit_block_hex w/ no RPC sink  -> false (the no-RPC guard), NOT a throw
//
// The full per-coin WorkData (incl. m_txs) is retained coin-side via work.set()
// and only the agnostic slice (m_data/m_hashes/m_latency) crosses the seam --
// this test confirms exactly those three fields survive and nothing else is
// required to satisfy ICoinNode.
//
// Build-INERT / source-only: impl_bch stays unregistered in CMake (bch =
// skip-green; don`t race ci-steward), so this is verified with -fsyntax-only
// and runs under the embedded test target once impl_bch is registered. Out of
// tree it links against coin_node.cpp + btclibs uint256; the external NodeRPC
// fallback leg is never invoked here (rpc=nullptr in both cases), so it needs
// no live RPC/boost graph. p2pool-merged-v36 surface: NONE (pure local seam).
// ---------------------------------------------------------------------------

#include <cassert>
#include <iostream>
#include <string>

#include "../coin/coin_node.hpp"

namespace {

// Minimal embedded work source: returns a recognisable WorkData so the test can
// prove the seam moved THIS object`s agnostic slice into the WorkView.
class FakeEmbedded : public bch::coin::CoinNodeInterface {
public:
    int calls = 0;

    bch::coin::rpc::WorkData getwork() override {
        ++calls;
        bch::coin::rpc::WorkData wd;
        wd.m_data = nlohmann::json{{"marker", "embedded-bch"}};
        wd.m_hashes.push_back(uint256(static_cast<uint64_t>(0xab)));
        wd.m_latency = 42;
        // m_txs intentionally left empty -- it must NOT cross the seam anyway.
        wd.m_txs.clear();
        return wd;
    }

    void submit_block(bch::coin::BlockType& /*block*/) override {}
    nlohmann::json getblockchaininfo() override { return nlohmann::json::object(); }
    bool is_synced() const override { return true; }
};

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

} // namespace

int main() {
    using bch::coin::CoinNode;

    // 1) No work source configured -> empty view, no throw (1:1 btc/ltc ref).
    {
        CoinNode n(nullptr, nullptr);
        CHECK(!n.is_embedded());
        CHECK(!n.has_rpc());
        core::coin::WorkView v = n.get_work_view();
        CHECK(v.m_data.is_null() || v.m_data.empty());
        CHECK(v.m_hashes.empty());
        CHECK(v.m_latency == 0);
    }

    // 2) Embedded preferred, no RPC fallback wired -> view comes from embedded.
    {
        FakeEmbedded emb;
        CoinNode n(&emb, /*rpc=*/nullptr);
        CHECK(n.is_embedded());
        CHECK(!n.has_rpc());
        core::coin::WorkView v = n.get_work_view();
        CHECK(emb.calls == 1);                       // embedded WAS the source
        CHECK(v.m_data.contains("marker"));
        CHECK(v.m_data["marker"] == "embedded-bch");
        CHECK(v.m_hashes.size() == 1);
        CHECK(v.m_latency == 42);

        // 3) No RPC sink -> submit_block_hex returns false (guard, not throw).
        bool ok = n.submit_block_hex("00", /*ignore_failure=*/true);
        CHECK(ok == false);
    }

    if (failures == 0) {
        std::cout << "coin_node_seam_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "coin_node_seam_test: " << failures << " FAILURE(S)\n";
    return 1;
}