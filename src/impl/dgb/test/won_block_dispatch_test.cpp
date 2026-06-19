// ---------------------------------------------------------------------------
// dgb::coin::make_on_block_found won-block dispatch wiring test (#82
// broadcaster-gate, dispatch half).
//
// Drives the handler the run-loop installs as ShareTracker::m_on_block_found
// END-TO-END: invoke the closure with a winning share hash and assert it (a)
// calls the injected reconstructor for that hash, (b) on a reconstructed block
// fires broadcast_won_block down BOTH paths (P2P primary + RPC fallback), and
// (c) on an unknown/unassemblable share broadcasts NOTHING. This is the seam
// that, once the live NodeP2P relay + faithful as_block reconstructor are
// bound, makes a won block reach the network -- so it locks the dispatch
// contract now while those pieces are still being ported.
//
// Uses a fake ICoinNode (the external-digibyted submitblock fallback is the
// live leg today) + a stub reconstructor, so no embedded daemon / network is
// needed. p2pool-merged-v36 surface: NONE.
//
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist
// or it becomes a #143-style NOT_BUILT sentinel that reds master.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "../coin/won_block_dispatch.hpp"

namespace {

// Same controllable seam shape as block_broadcast_test: records the submitblock
// call so the "always-fire fallback" rule is observable through the handler.
class FakeSeam : public core::coin::ICoinNode {
public:
    bool        rpc_present  = true;
    bool        submit_ack   = true;
    int         submit_calls = 0;
    std::string last_hex;

    core::coin::WorkView get_work_view() override { return {}; }
    bool submit_block_hex(const std::string& hex, bool) override {
        ++submit_calls; last_hex = hex; return submit_ack;
    }
    bool is_embedded() const override { return false; }
    bool has_rpc()     const override { return rpc_present; }
};

const std::vector<unsigned char> kBytes(160, 0x37);
const std::string                kHex = "deadbeef";

// Reconstructor that returns a canned block for a single "known" share and
// nullopt for anything else -- and records every hash it was asked about.
struct StubReconstructor {
    uint256                   known;
    std::vector<uint256>      seen;
    std::optional<std::pair<std::vector<unsigned char>, std::string>>
    operator()(const uint256& h) {
        seen.push_back(h);
        if (h == known)
            return std::make_pair(kBytes, kHex);
        return std::nullopt;
    }
};

uint256 hash_a() { return uint256S("00000000000000000000000000000000000000000000000000000000000000aa"); }
uint256 hash_b() { return uint256S("00000000000000000000000000000000000000000000000000000000000000bb"); }

} // namespace

// 1) Known won share: reconstructor consulted for THAT hash, then both paths
//    fire (P2P primary relays the bytes, RPC fallback always fires the hex).
TEST(DgbWonBlockDispatch, KnownShareFiresBothPaths) {
    std::vector<unsigned char> relayed;
    bool did_relay = false;
    auto relay = [&](const std::vector<unsigned char>& b) { did_relay = true; relayed = b; };

    auto recon = std::make_shared<StubReconstructor>();
    recon->known = hash_a();
    FakeSeam seam; seam.rpc_present = true; seam.submit_ack = true;

    auto handler = dgb::coin::make_on_block_found(
        [recon](const uint256& h) { return (*recon)(h); }, relay, &seam);

    handler(hash_a());

    ASSERT_EQ(recon->seen.size(), 1u);
    EXPECT_EQ(recon->seen[0], hash_a());
    EXPECT_TRUE(did_relay);
    EXPECT_EQ(relayed, kBytes);          // P2P primary carried the reconstructed bytes
    EXPECT_EQ(seam.submit_calls, 1);     // RPC fallback ALWAYS fired
    EXPECT_EQ(seam.last_hex, kHex);      // ...with the reconstructed block hex
}

// 2) Unknown share: reconstructor returns nullopt -> NOTHING is broadcast on
//    either path (no fabricated / partial block ever reaches the network).
TEST(DgbWonBlockDispatch, UnknownShareBroadcastsNothing) {
    bool did_relay = false;
    auto relay = [&](const std::vector<unsigned char>&) { did_relay = true; };

    auto recon = std::make_shared<StubReconstructor>();
    recon->known = hash_a();
    FakeSeam seam; seam.rpc_present = true; seam.submit_ack = true;

    auto handler = dgb::coin::make_on_block_found(
        [recon](const uint256& h) { return (*recon)(h); }, relay, &seam);

    handler(hash_b());                   // not the known share

    ASSERT_EQ(recon->seen.size(), 1u);
    EXPECT_EQ(recon->seen[0], hash_b());
    EXPECT_FALSE(did_relay);             // P2P primary not touched
    EXPECT_EQ(seam.submit_calls, 0);     // RPC fallback not touched
}

// 3) RPC-only deployment (no embedded P2P sink yet): the handler still carries
//    a known won block to the network via the submitblock fallback alone.
TEST(DgbWonBlockDispatch, RpcOnlyStillReachesNetwork) {
    auto recon = std::make_shared<StubReconstructor>();
    recon->known = hash_a();
    FakeSeam seam; seam.rpc_present = true; seam.submit_ack = true;

    auto handler = dgb::coin::make_on_block_found(
        [recon](const uint256& h) { return (*recon)(h); },
        /*p2p_relay=*/{}, &seam);

    handler(hash_a());

    EXPECT_EQ(seam.submit_calls, 1);     // block reached the network via RPC fallback
    EXPECT_EQ(seam.last_hex, kHex);
}

// 4) No reconstructor wired at all: handler is a safe no-op, never throws,
//    never dereferences the (here null) seam.
TEST(DgbWonBlockDispatch, MissingReconstructorIsSafeNoOp) {
    auto handler = dgb::coin::make_on_block_found(
        /*reconstruct=*/{}, /*p2p_relay=*/{}, /*seam=*/nullptr);
    EXPECT_NO_THROW(handler(hash_a()));
}
