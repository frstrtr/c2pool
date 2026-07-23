// SPDX-License-Identifier: AGPL-3.0-or-later
// DGB Phase B — per-connection PPLNS-inputs producer-assembly KAT.
//
// Locks dgb::make_conn_pplns_inputs() (conn_pplns_producer.hpp): the seam that
// binds the verifier ref-hash primitive (compute_ref_hash_for_work, the #336
// parity-fixed path) onto the per-connection coinbase PPLNS inputs. A PASS
// proves the producer-assembly path:
//
//   1. derives ref_hash / last_txout_nonce from the SAME primitive the share
//      verifier uses — for BOTH the no-segwit-v36 case (the latent gap #336
//      fixed: the producer is that primitive's FIRST live caller) and the
//      with-segwit case — so a Stratum-emitted OP_RETURN matches the share it
//      commits to by construction, not by a second ref-hash implementation;
//   2. forwards the caller-resolved PPLNS weights + the two oracle-pinned
//      design points (subsidy == template value, use_v36_pplns == minted
//      formula) verbatim into ConnCoinbasePplnsInputs; and
//   3. round-trips through build_connection_coinbase_from_pplns so the emitted
//      coinbase embeds exactly that ref_hash + nonce in its OP_RETURN.
//
// Pure / tracker-free: weights + RefHashParams are fixed inputs, so the
// assembled output is checked against the verifier primitive directly — not
// self-generated.
//
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist
// or it becomes a #143-style NOT_BUILT sentinel that reds master.

#include <gtest/gtest.h>

#include <impl/dgb/conn_pplns_producer.hpp>
#include <impl/dgb/share_check.hpp>
#include <impl/dgb/coin/connection_coinbase.hpp>
#include <impl/dgb/params.hpp>

#include <core/uint256.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace {

using Script = std::vector<unsigned char>;

std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> v; v.reserve(h.size() / 2);
    auto nyb = [](char c) -> int { return (c <= '9') ? c - '0' : (c | 0x20) - 'a' + 10; };
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        v.push_back(static_cast<unsigned char>((nyb(h[i]) << 4) | nyb(h[i + 1])));
    return v;
}

// Donation script: byte-identical to the oracle wire vector (4104ffd0...ac).
const Script DON = unhex("4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac");
const Script SA{0x01};
const Script SB{0x02};
const Script CB = unhex("03a1b2c3041122334455667788");

// A v36 RefHashParams with non-trivial fields (mirrors gentx_share_path_test's
// make_v36_share). has_segwit defaults false => exercises the #336 placeholder.
dgb::RefHashParams make_v36_ref_params() {
    dgb::RefHashParams p;
    p.share_version    = 36;
    p.prev_share.SetNull();
    p.coinbase_scriptSig = CB;
    p.share_nonce      = 0x12345678;
    p.pubkey_hash.SetNull();
    p.pubkey_type      = 0;
    p.subsidy          = 10000;
    p.donation         = 0;
    p.stale_info       = 0;
    p.desired_version  = 36;
    p.has_segwit       = false;
    p.far_share_hash.SetNull();
    p.max_bits         = 0x1e0fffff;
    p.bits             = 0x1e0fffff;
    p.timestamp        = 1718700000;
    p.absheight        = 1000;
    p.merged_payout_hash.SetNull();
    return p;
}

dgb::ConnPplnsAssemblyInputs make_assembly_inputs(const dgb::RefHashParams& rp) {
    dgb::ConnPplnsAssemblyInputs in;
    in.weights = std::map<Script, uint288>{{SA, uint288(3)}, {SB, uint288(1)}};
    in.total_weight             = uint288(4);
    in.subsidy                  = 10000;           // == coinbase_value(...) [design #1]
    in.use_v36_pplns            = true;            // == is_v36_active(mint ver) [design #2]
    in.coinbase_script          = CB;
    in.segwit_commitment_script = std::nullopt;    // no-segwit v36
    in.finder_script            = {};
    in.donation_script          = DON;
    in.ref_params               = rp;
    return in;
}

// (1a) No-segwit v36: ref_hash/nonce come from the verifier primitive verbatim.
TEST(ConnPplnsProducer, RefHashDelegatesToVerifierPrimitiveNoSegwit) {
    const auto params = dgb::make_coin_params(/*testnet=*/false);
    auto rp = make_v36_ref_params();
    ASSERT_FALSE(rp.has_segwit);   // the #336 placeholder branch

    auto out = dgb::make_conn_pplns_inputs(make_assembly_inputs(rp), params);

    // Delegation invariant: the producers ref_hash IS the verifier primitives
    // output verbatim. The ref preimage is a pure function of the ref params and
    // does NOT commit to last_txout_nonce, so this equality is deterministic.
    // last_txout_nonce is an independent uniform 64-bit draw per call (the #338
    // SSOT, mirroring oracle random.randrange(2**64)); two draws never match, so
    // it is NOT asserted here -- its real contract (carried verbatim into the
    // coinbase OP_RETURN) is pinned by RoundTripEmbedsRefInOpReturn below.
    const auto ref_hash = dgb::compute_ref_hash_for_work(rp, params).first;
    EXPECT_EQ(out.ref_hash, ref_hash);
    EXPECT_FALSE(out.ref_hash.IsNull());
}

// (1b) With-segwit v36: same delegation (the producer never re-implements the
//      ref preimage — it always tracks the verifier primitive).
TEST(ConnPplnsProducer, RefHashDelegatesToVerifierPrimitiveWithSegwit) {
    const auto params = dgb::make_coin_params(/*testnet=*/false);
    auto rp = make_v36_ref_params();
    rp.has_segwit = true;          // SegwitData default-constructed

    auto out = dgb::make_conn_pplns_inputs(make_assembly_inputs(rp), params);

    // Same delegation invariant as the no-segwit case: ref_hash is deterministic;
    // last_txout_nonce is an independent per-call draw (see note above).
    const auto ref_hash = dgb::compute_ref_hash_for_work(rp, params).first;
    EXPECT_EQ(out.ref_hash, ref_hash);
}

// (2) Caller-resolved PPLNS weights + design points forward verbatim.
TEST(ConnPplnsProducer, ForwardsWeightsAndDesignPoints) {
    const auto params = dgb::make_coin_params(/*testnet=*/false);
    auto in  = make_assembly_inputs(make_v36_ref_params());
    auto out = dgb::make_conn_pplns_inputs(in, params);

    EXPECT_EQ(out.weights, in.weights);
    EXPECT_EQ(out.total_weight, in.total_weight);
    EXPECT_EQ(out.subsidy, in.subsidy);
    EXPECT_EQ(out.use_v36_pplns, in.use_v36_pplns);
    EXPECT_EQ(out.coinbase_script, in.coinbase_script);
    EXPECT_EQ(out.donation_script, in.donation_script);
    EXPECT_FALSE(out.segwit_commitment_script.has_value());
}

// (3) The assembled inputs round-trip through the coinbase SSOT and the emitted
//     OP_RETURN embeds exactly the producer's ref_hash + nonce.
TEST(ConnPplnsProducer, RoundTripEmbedsRefInOpReturn) {
    const auto params = dgb::make_coin_params(/*testnet=*/false);
    auto out = dgb::make_conn_pplns_inputs(make_assembly_inputs(make_v36_ref_params()), params);

    auto parts = dgb::coin::build_connection_coinbase_from_pplns(out);
    const auto want = dgb::coin::build_ref_op_return(out.ref_hash, out.last_txout_nonce);

    const auto& bytes = parts.gentx.bytes;
    auto it = std::search(bytes.begin(), bytes.end(), want.begin(), want.end());
    EXPECT_NE(it, bytes.end());   // the OP_RETURN commitment is present verbatim
    EXPECT_FALSE(parts.coinb1.empty());
}

}  // namespace