// ---------------------------------------------------------------------------
// dgb_forced_won_share_dualpath_test -- the #82 broadcaster-gate BINDING KAT.
//
// This is the deterministic gate-closer for DGB's won-block broadcaster
// dual-path (integrator 2026-06-21): it drives a FORCED won share through the
// REAL run-loop reconstructor (coin::make_reconstruct_closure_from_template,
// the #271/#279/#280 closure main_dgb.cpp installs) wired into the REAL
// dispatch handler (coin::make_on_block_found, tracker.m_on_block_found), and
// asserts the one won block fans out down BOTH broadcast sinks --
//   ARM A : embedded P2P relay (primary)          -> receives block_bytes
//   ARM B : external digibyted submitblock (fallback, always-fire) -> block_hex
// -- carrying the BYTE-IDENTICAL faithfully-reconstructed block (HexStr(bytes)
// of arm A == hex of arm B == the oracle reconstruct_won_block_from_template
// output). The existing dgb_won_block_dispatch_test pins the same fan-out with
// a CANNED stub reconstructor; this KAT closes the gap integrator named: prove
// the dual-path with the REAL reconstructor so the bytes both arms carry are
// the genuine won block, not synthesized constants.
//
// The live A/B soak (block lands on peer node B + submitblock accepts on a
// self-provisioned regtest digibyted) is the CORROBORATING evidence; THIS KAT
// is the binding proof on the record. SYNTHETIC seams only -- no live
// ShareTracker / mempool / network. Fail-closed end-to-end is also pinned: a
// forced won share the chain does not know fires NEITHER arm.
//
// DGB-Scrypt is a STANDALONE parent in the V36 default build (no merged-
// coinbase leg). p2pool-merged-v36 surface: NONE -- block dispatch + framing
// only; no PoW hash, share format, coinbase commitment, or PPLNS math touched.
// Per-coin isolation: src/impl/dgb/ only. MUST appear in BOTH test/CMakeLists
// AND the build.yml --target allowlist (#143 NOT_BUILT sentinel trap).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <core/coin/node_iface.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include "../coin/reconstruct_closure.hpp"   // make_reconstruct_closure_from_template, reconstruct_won_block_from_template, unpack_gentx_coinbase, WonShareInputs, types
#include "../coin/won_block_dispatch.hpp"    // make_on_block_found

using dgb::coin::make_reconstruct_closure_from_template;
using dgb::coin::reconstruct_won_block_from_template;
using dgb::coin::unpack_gentx_coinbase;
using dgb::coin::make_on_block_found;
using dgb::coin::SmallBlockHeaderType;
using dgb::coin::MutableTransaction;
using dgb::coin::WonShareInputs;

namespace {

// ---- synthetic share inputs (mirror reconstruct_closure_test.cpp) -----------

uint256 H(const char* two) // 0x"two" repeated to 64 hex chars
{
    std::string s;
    for (int i = 0; i < 32; ++i) s += two;
    uint256 h; h.SetHex(s);
    return h;
}

MutableTransaction make_tx(int64_t value)
{
    MutableTransaction tx;
    tx.version = 1; tx.locktime = 0;
    dgb::coin::TxIn in;
    in.prevout.hash.SetNull(); in.prevout.index = 0; in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    dgb::coin::TxOut out; out.value = value;
    tx.vout.push_back(out);
    return tx;
}

MutableTransaction make_gentx()
{
    MutableTransaction tx;
    tx.version = 1; tx.locktime = 0;
    dgb::coin::TxIn in;
    in.prevout.hash.SetNull(); in.prevout.index = 0xffffffff;  // coinbase
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    dgb::coin::TxOut out; out.value = 5000000000LL;
    tx.vout.push_back(out);
    return tx;
}

SmallBlockHeaderType make_small_header()
{
    SmallBlockHeaderType h;
    h.m_version = 0x20000000;
    h.m_previous_block.SetHex("00000000000000000000000000000000000000000000000000000000deadbeef");
    h.m_timestamp = 1718700000;
    h.m_bits = 0x1a0fffff;
    h.m_nonce = 0x12345678;
    return h;
}

// Canonical non-witness gentx serialization (the run-loop gentx_bytes_fn bytes).
std::vector<unsigned char> noseg_bytes(const MutableTransaction& tx)
{
    auto packed = pack(dgb::coin::TX_NO_WITNESS(tx));
    auto sp = packed.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

// won_share_fields_fn that knows ONLY the won share; throws for any other hash
// (the run-loop's chain.get_share miss => fail-closed).
std::function<WonShareInputs(const uint256&)>
won_fields(const uint256& won, SmallBlockHeaderType sh, ::dgb::MerkleLink link)
{
    return [won, sh, link](const uint256& h) -> WonShareInputs {
        if (h != won) throw std::out_of_range("won_share_fields: unknown share");
        return WonShareInputs{sh, link};
    };
}

// Independent hex encoder so the cross-arm identity (arm A bytes hex-encode to
// the exact hex arm B submitted) is asserted self-containedly, not assumed.
std::string to_hex(const std::vector<unsigned char>& b)
{
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(b.size() * 2);
    for (unsigned char c : b) { s += d[c >> 4]; s += d[c & 0x0f]; }
    return s;
}

// ---- controllable submitblock seam (mirror won_block_dispatch_test.cpp) ------

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

// Build the REAL from-template reconstruct closure over a won share with the
// given non-coinbase template set, and the oracle block it must produce.
struct Rig {
    uint256                             won = H("a0");
    SmallBlockHeaderType                sh  = make_small_header();
    ::dgb::MerkleLink                   link;
    std::vector<unsigned char>          gentx_bytes = noseg_bytes(make_gentx());
    dgb::coin::WonBlockReconstructor    reconstruct;
    std::vector<unsigned char>          oracle_bytes;
    std::string                         oracle_hex;

    explicit Rig(std::vector<MutableTransaction> other)
    {
        auto ug = unpack_gentx_coinbase(gentx_bytes);
        auto oracle = reconstruct_won_block_from_template(sh, link, ug.tx, ug.txid, other);
        oracle_bytes = oracle.bytes;
        oracle_hex   = oracle.hex;
        auto gb = gentx_bytes;
        reconstruct = make_reconstruct_closure_from_template(
            won_fields(won, sh, link),
            [gb](const uint256&) { return gb; },
            [other](const uint256&) { return other; });
    }
};

} // namespace

// 1) THE GATE: one forced won share -> REAL reconstruct -> BOTH arms carry the
//    byte-identical faithful block (P2P primary bytes, submitblock fallback hex).
TEST(DgbForcedWonShareDualPath, BothArmsCarryIdenticalFaithfulBlock)
{
    Rig rig({ make_tx(11), make_tx(22) });   // a non-trivial template tx set

    std::vector<unsigned char> relayed;
    bool did_relay = false;
    auto p2p = [&](const std::vector<unsigned char>& b) { did_relay = true; relayed = b; };
    FakeSeam seam;

    auto handler = make_on_block_found(rig.reconstruct, p2p, &seam);
    handler(rig.won);                        // FORCE the won share

    // ARM A -- embedded P2P relay fired with the faithful block bytes.
    ASSERT_TRUE(did_relay);
    EXPECT_FALSE(relayed.empty());
    EXPECT_EQ(relayed, rig.oracle_bytes);

    // ARM B -- submitblock fallback ALWAYS fired, with the faithful block hex.
    ASSERT_EQ(seam.submit_calls, 1);
    EXPECT_EQ(seam.last_hex, rig.oracle_hex);

    // CROSS-ARM IDENTITY: both arms carry the SAME block bytes (arm-A bytes
    // hex-encode to exactly arm-B's submitted hex). This is the dual-path proof.
    EXPECT_EQ(to_hex(relayed), seam.last_hex);
}

// 2) Today's realistic shape: empty template (mempool tx-selection pending) ->
//    a valid coinbase-only block still dual-paths byte-identically (NOT a stub,
//    NOT fail-closed -- correct-and-empty).
TEST(DgbForcedWonShareDualPath, CoinbaseOnlyTemplateStillDualPaths)
{
    Rig rig(std::vector<MutableTransaction>{});

    std::vector<unsigned char> relayed;
    auto p2p = [&](const std::vector<unsigned char>& b) { relayed = b; };
    FakeSeam seam;

    auto handler = make_on_block_found(rig.reconstruct, p2p, &seam);
    handler(rig.won);

    EXPECT_EQ(relayed, rig.oracle_bytes);
    EXPECT_EQ(seam.submit_calls, 1);
    EXPECT_EQ(seam.last_hex, rig.oracle_hex);
    EXPECT_EQ(to_hex(relayed), seam.last_hex);
}

// 3) RPC-only deployment (no embedded P2P sink wired yet): the same forced won
//    block still reaches the network via the submitblock fallback alone,
//    carrying the identical faithful hex.
TEST(DgbForcedWonShareDualPath, RpcOnlyDeploymentStillReachesNetwork)
{
    Rig rig({ make_tx(7) });
    FakeSeam seam;

    auto handler = make_on_block_found(rig.reconstruct, /*p2p_relay=*/{}, &seam);
    handler(rig.won);

    EXPECT_EQ(seam.submit_calls, 1);
    EXPECT_EQ(seam.last_hex, rig.oracle_hex);
}

// 4) FAIL-CLOSED end-to-end: a forced won share the chain cannot reconstruct
//    (won_share_fields miss) fires NEITHER arm -- no fabricated/partial block
//    ever reaches either broadcast path.
TEST(DgbForcedWonShareDualPath, UnreconstructableForcedShareFiresNeitherArm)
{
    Rig rig({ make_tx(11) });

    bool did_relay = false;
    auto p2p = [&](const std::vector<unsigned char>&) { did_relay = true; };
    FakeSeam seam;

    auto handler = make_on_block_found(rig.reconstruct, p2p, &seam);
    handler(H("ff"));                        // NOT the won share the rig knows

    EXPECT_FALSE(did_relay);                 // P2P arm silent
    EXPECT_EQ(seam.submit_calls, 0);         // submitblock fallback silent
}
