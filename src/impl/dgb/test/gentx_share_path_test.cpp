// DGB #82 / #172 — share-path gentx KAT.
//
// The helper-level KAT (gentx_coinbase_test) pins dgb::coin::assemble_gentx_coinbase
// directly against oracle vectors. This test proves the *consumption* side of
// the #172 collapse: that generate_share_transaction() — the verification SSOT
// call site that #172 rewired onto assemble_gentx_coinbase — actually EMITS the
// SSOT framing for a real share, not merely that the pure helper does.
//
// The OP_RETURN ref commitment is share-derived:
//   ref_hash = check_merkle_link(Hash(ref_serialization), m_ref_merkle_link)
// so the share-path gentx cannot be pinned to a fixed 0xab..×32 oracle byte
// vector (criterion 1: no oracle vector regeneration). Instead we assert a
// round-trip equivalence: generate_share_transaction(share) == a verbatim
// re-derivation of the same per-share inputs handed to the SAME SSOT assembler.
// If the share path ever stops routing through the SSOT, or builds the coinbase
// inputs differently, the two txids diverge and this fails — which is exactly
// "the collapse is what's tested."
//
// A v36 MergedMiningShare with a NULL parent is used so the PPLNS walk is
// skipped entirely (no tracker chain entries are touched): payout_outputs is
// empty and donation_amount == subsidy. That isolates the coinbase framing +
// op_return derivation, which is the SSOT contract under test.
//
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist
// or it becomes a #143-style NOT_BUILT sentinel that reds master.

#include <gtest/gtest.h>

#include <impl/dgb/share.hpp>
#include <impl/dgb/share_tracker.hpp>
#include <impl/dgb/share_check.hpp>
#include <impl/dgb/params.hpp>
#include <impl/dgb/coin/gentx_coinbase.hpp>
#include <impl/dgb/coin/transaction.hpp>

#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace {

// A v36 share with a null parent => PPLNS skipped (empty payouts, donation ==
// subsidy). Coinbase script / nonce / timestamp / last_txout_nonce are set to
// non-trivial values so the op_return ref derivation is exercised.
dgb::MergedMiningShare make_v36_share()
{
    dgb::MergedMiningShare s;
    s.m_prev_hash.SetNull();                 // null parent => PPLNS walk skipped
    s.m_coinbase.m_data = { 0x03, 0xa1, 0xb2, 0xc3, 0x04, 0x11, 0x22, 0x33, 0x44 };
    s.m_nonce = 0x12345678;
    s.m_pubkey_hash.SetNull();
    s.m_pubkey_type = 0;
    s.m_subsidy = 500000000ull;
    s.m_donation = 0;
    s.m_stale_info = dgb::none;
    s.m_desired_version = 36;
    s.m_segwit_data = std::nullopt;
    s.m_far_share_hash.SetNull();
    s.m_max_bits = 0x1e0fffff;
    s.m_bits = 0x1e0fffff;
    s.m_timestamp = 1718700000;
    s.m_absheight = 1000;
    // m_abswork default-constructs to zero (uint128)
    s.m_merged_payout_hash.SetNull();
    s.m_last_txout_nonce = 0x0001020304050607ull;
    // m_ref_merkle_link left empty => check_merkle_link returns Hash(ref) directly
    return s;
}

// Verbatim re-derivation of generate_share_transaction's per-share coinbase
// inputs (v36 path), ending in the SAME SSOT assembler. Mirrors share_check.hpp
// section 4/5 byte-for-byte via the identical pack primitives.
template <typename ShareT>
dgb::coin::GentxCoinbase rederive_via_ssot(
    const ShareT& share, const core::CoinParams& params)
{
    constexpr int64_t ver = ShareT::version;

    // null parent => empty payouts, donation_amount == subsidy
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payout_outputs;
    uint64_t donation_amount = share.m_subsidy;

    // no segwit_data => no witness-commitment vout
    std::optional<std::vector<unsigned char>> segwit_commitment_script;

    auto donation_script = params.donation_script_func(ver);

    std::vector<unsigned char> op_return_script;
    {
        PackStream ref_stream;
        {
            auto hex = params.active_identifier_hex();
            for (size_t i = 0; i + 1 < hex.size(); i += 2)
            {
                unsigned char byte = static_cast<unsigned char>(
                    std::stoul(hex.substr(i, 2), nullptr, 16));
                ref_stream.write(std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(&byte), 1));
            }
        }
        {
            ref_stream << share.m_prev_hash;
            ref_stream << share.m_coinbase;
            ref_stream << share.m_nonce;

            if constexpr (requires { share.m_address; })
                ref_stream << share.m_address;
            else if constexpr (requires { share.m_pubkey_type; })
            {
                ref_stream << share.m_pubkey_hash;
                ref_stream << share.m_pubkey_type;
            }
            else
                ref_stream << share.m_pubkey_hash;

            if constexpr (core::version_gate::is_v36_active(ver))
                ::Serialize(ref_stream, VarInt(share.m_subsidy));
            else
                ref_stream << share.m_subsidy;

            ref_stream << share.m_donation;
            {
                uint8_t si = static_cast<uint8_t>(share.m_stale_info);
                ref_stream << si;
            }
            ::Serialize(ref_stream, VarInt(share.m_desired_version));

            if constexpr (requires { share.m_segwit_data; })
            {
                if constexpr (ver >= dgb::SEGWIT_ACTIVATION_VERSION)
                {
                    if (share.m_segwit_data.has_value()) {
                        ref_stream << share.m_segwit_data.value();
                    } else {
                        std::vector<uint256> empty_branch;
                        ref_stream << empty_branch;
                        uint256 zero_root;
                        ref_stream << zero_root;
                    }
                }
            }

            if constexpr (core::version_gate::is_v36_active(ver))
            {
                if constexpr (requires { share.m_merged_addresses; })
                    ref_stream << share.m_merged_addresses;
            }

            if constexpr (ver < 34)
            {
                if constexpr (requires { share.m_tx_info; })
                    ref_stream << share.m_tx_info;
            }

            ref_stream << share.m_far_share_hash;
            ref_stream << share.m_max_bits;
            ref_stream << share.m_bits;
            ref_stream << share.m_timestamp;
            ref_stream << share.m_absheight;

            if constexpr (core::version_gate::is_v36_active(ver))
            {
                if constexpr (requires { share.m_abswork; })
                    ::Serialize(ref_stream, Using<dgb::AbsworkV36Format>(share.m_abswork));
            }
            else
            {
                ref_stream << share.m_abswork;
            }

            if constexpr (core::version_gate::is_v36_active(ver))
            {
                if constexpr (requires { share.m_merged_coinbase_info; })
                    ref_stream << share.m_merged_coinbase_info;
                if constexpr (requires { share.m_merged_payout_hash; })
                    ref_stream << share.m_merged_payout_hash;
            }
        }

        if constexpr (core::version_gate::is_v36_active(ver))
        {
            if constexpr (requires { share.m_message_data; })
                ref_stream << share.m_message_data;
        }

        auto ref_span = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
        uint256 hash_ref = Hash(ref_span);
        uint256 ref_hash = dgb::check_merkle_link(hash_ref, share.m_ref_merkle_link);

        op_return_script.push_back(0x6a); // OP_RETURN
        op_return_script.push_back(0x28); // PUSH 40
        op_return_script.insert(op_return_script.end(), ref_hash.data(), ref_hash.data() + 32);
        {
            uint64_t nonce = share.m_last_txout_nonce;
            auto* p = reinterpret_cast<const unsigned char*>(&nonce);
            op_return_script.insert(op_return_script.end(), p, p + 8);
        }
    }

    return dgb::coin::assemble_gentx_coinbase(
        share.m_coinbase.m_data, segwit_commitment_script, payout_outputs,
        donation_amount, donation_script, op_return_script);
}

// --- Test 1: share path emits SSOT framing (round-trip equivalence) -----------
TEST(DgbGentxSharePath, GenerateShareTransactionEmitsSsotFraming)
{
    auto params = dgb::make_coin_params(/*testnet=*/false);
    dgb::ShareTracker tracker;                 // empty chain
    auto share = make_v36_share();

    // Route A: the verification SSOT call site under test.
    uint256 actual = dgb::generate_share_transaction(
        share, tracker, params, /*dump_diag=*/false, /*v36_active=*/true);

    // Route B: verbatim re-derivation through the SAME assembler.
    auto expected = rederive_via_ssot(share, params);

    EXPECT_EQ(actual, expected.txid)
        << "generate_share_transaction no longer emits assemble_gentx_coinbase framing";
}

// --- Test 2: determinism (the SSOT path is a pure function of the share) -------
TEST(DgbGentxSharePath, Deterministic)
{
    auto params = dgb::make_coin_params(false);
    dgb::ShareTracker tracker;
    auto share = make_v36_share();

    uint256 a = dgb::generate_share_transaction(share, tracker, params, false, true);
    uint256 b = dgb::generate_share_transaction(share, tracker, params, false, true);
    EXPECT_EQ(a, b);
}

// --- Test 3: coinbase-affecting fields flow into the SSOT gentx ----------------
// last_txout_nonce feeds the op_return; coinbase script feeds vin[0]. Changing
// either must change the gentx txid (proves the share data reaches the SSOT,
// not a cached/stubbed value).
TEST(DgbGentxSharePath, CoinbaseInputsAreLoadBearing)
{
    auto params = dgb::make_coin_params(false);
    dgb::ShareTracker tracker;

    auto base = make_v36_share();
    uint256 h0 = dgb::generate_share_transaction(base, tracker, params, false, true);

    auto bumped_nonce = base;
    bumped_nonce.m_last_txout_nonce ^= 0xffull;
    uint256 h1 = dgb::generate_share_transaction(bumped_nonce, tracker, params, false, true);
    EXPECT_NE(h0, h1) << "last_txout_nonce did not reach the op_return commitment";

    auto bumped_cb = base;
    bumped_cb.m_coinbase.m_data.push_back(0x99);
    uint256 h2 = dgb::generate_share_transaction(bumped_cb, tracker, params, false, true);
    EXPECT_NE(h0, h2) << "coinbase script did not reach the gentx vin";
}

// --- Test 4: SSOT gentx bytes are exposed for won-block reconstruction (#82) ---
// reconstruct_won_block needs the EXACT coinbase bytes whose txid is the merkle
// leaf -- not just the hash. The out_gentx param surfaces them straight from the
// SSOT assembler; they must (a) hash to the returned gentx_hash and (b)
// deserialize into the coinbase MutableTransaction that assemble_won_block frames
// as block tx[0], round-tripping byte-identically.
TEST(DgbGentxSharePath, SsotGentxBytesExposedForReconstruct)
{
    auto params = dgb::make_coin_params(false);
    dgb::ShareTracker tracker;
    auto share = make_v36_share();

    dgb::coin::GentxCoinbase gc;
    uint256 gentx_hash = dgb::generate_share_transaction(
        share, tracker, params, /*dump_diag=*/false, /*v36_active=*/true, &gc);

    ASSERT_FALSE(gc.bytes.empty()) << "out_gentx not populated";
    EXPECT_EQ(gc.txid, gentx_hash)
        << "exposed gentx bytes do not match the returned gentx_hash";
    auto sp = std::span<const unsigned char>(gc.bytes.data(), gc.bytes.size());
    EXPECT_EQ(Hash(sp), gentx_hash)
        << "double-SHA(exposed bytes) != gentx_hash (merkle leaf would mismatch)";

    // Deserialize into the coinbase tx that assemble_won_block consumes.
    dgb::coin::MutableTransaction gentx;
    {
        PackStream ps(gc.bytes);
        dgb::coin::UnserializeTransaction(gentx, ps, dgb::coin::TX_NO_WITNESS);
    }
    // Coinbase shape: single input spending the null outpoint at 0xffffffff.
    ASSERT_EQ(gentx.vin.size(), 1u);
    EXPECT_TRUE(gentx.vin[0].prevout.hash.IsNull());
    EXPECT_EQ(gentx.vin[0].prevout.index, 0xffffffffu);

    // Re-serialize non-witness => byte-identical to the SSOT bytes, so the
    // reconstructed block tx[0] is faithful and the daemon-side block hashes.
    auto repacked = pack(dgb::coin::TX_NO_WITNESS(gentx));
    std::vector<unsigned char> rebytes(
        reinterpret_cast<const unsigned char*>(repacked.data()),
        reinterpret_cast<const unsigned char*>(repacked.data()) + repacked.size());
    EXPECT_EQ(rebytes, gc.bytes) << "coinbase tx does not round-trip the SSOT bytes";
}


// ============================================================================
// Emission==verification ref_hash parity KAT.
//
// dgb::compute_ref_hash_for_work() is the Stratum WORK-GENERATION ref_hash SSOT
// the per-connection coinbase producer seam (set_pplns_inputs_fn) will call to
// build each connection's OP_RETURN commitment. generate_share_transaction() is
// the VERIFICATION SSOT. The OP_RETURN a miner hashes MUST commit to the exact
// ref_hash the verifier recomputes for the share that mines it, or the won
// block / share is rejected.
//
// This pins them production-vs-production: the ref_hash compute_ref_hash_for_work
// returns must equal the 32 bytes generate_share_transaction actually embeds in
// the gentx OP_RETURN (6a 28 <ref32> <nonce8>) for the SAME share. No test-side
// re-serialization -- both sides are production code.
//
// REGRESSION CAUGHT: for ver >= SEGWIT_ACTIVATION_VERSION (=35) the verifier
// ALWAYS serializes a segwit field -- the SegwitData, or an (empty branch, zero
// root) placeholder when None. The prior compute_ref_hash_for_work wrote the
// field ONLY when has_segwit, so a no-segwit v36 share got a 33-byte-shorter
// preimage and a non-matching ref_hash. There is no live DGB caller yet (work
// path is the 4a skeleton), so this was latent until the producer seam binds.
namespace {
dgb::RefHashParams ref_params_from_share(const dgb::MergedMiningShare& s)
{
    dgb::RefHashParams p;
    p.share_version      = dgb::MergedMiningShare::version;   // 36
    p.prev_share         = s.m_prev_hash;
    p.coinbase_scriptSig = s.m_coinbase.m_data;
    p.share_nonce        = s.m_nonce;
    p.pubkey_hash        = s.m_pubkey_hash;
    p.pubkey_type        = s.m_pubkey_type;
    p.subsidy            = s.m_subsidy;
    p.donation           = s.m_donation;
    p.stale_info         = static_cast<uint8_t>(s.m_stale_info);
    p.desired_version    = s.m_desired_version;
    p.has_segwit         = s.m_segwit_data.has_value();
    if (p.has_segwit) p.segwit_data = s.m_segwit_data.value();
    p.merged_addresses     = s.m_merged_addresses;
    p.far_share_hash       = s.m_far_share_hash;
    p.max_bits             = s.m_max_bits;
    p.bits                 = s.m_bits;
    p.timestamp            = s.m_timestamp;
    p.absheight            = s.m_absheight;
    p.abswork              = s.m_abswork;
    p.merged_coinbase_info = s.m_merged_coinbase_info;
    p.merged_payout_hash   = s.m_merged_payout_hash;
    p.message_data         = s.m_message_data;
    return p;
}

// Extract the 32 ref_hash bytes from the gentx OP_RETURN (6a 28 <ref32><nonce8>).
uint256 op_return_ref_hash(const std::vector<unsigned char>& gentx_bytes)
{
    for (size_t i = 0; i + 42 <= gentx_bytes.size(); ++i) {
        if (gentx_bytes[i] == 0x6a && gentx_bytes[i + 1] == 0x28) {
            uint256 rh;
            std::memcpy(rh.data(), gentx_bytes.data() + i + 2, 32);
            return rh;
        }
    }
    return uint256::ZERO;
}
} // namespace (parity helpers)

TEST(DgbGentxSharePath, RefHashWorkPathMatchesVerifierOpReturn_NoSegwit)
{
    auto params = dgb::make_coin_params(/*testnet=*/false);
    dgb::ShareTracker tracker;                 // empty chain (null parent share)
    auto share = make_v36_share();             // v36, no segwit_data

    // Verification side: the ref_hash generate_share_transaction embeds.
    dgb::coin::GentxCoinbase gc;
    dgb::generate_share_transaction(
        share, tracker, params, /*dump_diag=*/false, /*v36_active=*/true, &gc);
    ASSERT_FALSE(gc.bytes.empty());
    uint256 verifier_ref = op_return_ref_hash(gc.bytes);
    ASSERT_FALSE(verifier_ref.IsNull()) << "no OP_RETURN ref commitment found in gentx";

    // Emission side: the work-generation SSOT the producer seam will call.
    auto [work_ref, nonce] = dgb::compute_ref_hash_for_work(
        ref_params_from_share(share), params);

    EXPECT_EQ(work_ref, verifier_ref)
        << "compute_ref_hash_for_work ref_hash != verifier OP_RETURN ref_hash "
           "(no-segwit v36 segwit-placeholder parity)";
}

// Guards the fix from regressing back to `if (p.has_segwit)`: toggling has_segwit
// MUST change the emitted ref_hash, proving the segwit field (value-or-
// placeholder) is now part of the preimage for ver >= SEGWIT_ACTIVATION_VERSION.
TEST(DgbGentxSharePath, RefHashWorkPathSegwitFieldIsLoadBearing)
{
    auto params = dgb::make_coin_params(/*testnet=*/false);
    auto share = make_v36_share();

    auto base = ref_params_from_share(share);
    base.has_segwit = false;
    auto [ref_placeholder, n0] = dgb::compute_ref_hash_for_work(base, params);

    auto withseg = base;
    withseg.has_segwit = true;                 // serialize SegwitData instead of placeholder
    // A DEFAULT SegwitData serializes byte-identically to the (empty branch,
    // zero root) placeholder, so give it a non-zero wtxid root to prove the
    // field is genuinely part of the preimage.
    withseg.segwit_data.m_wtxid_merkle_root.SetHex(
        "00000000000000000000000000000000000000000000000000000000deadbeef");
    auto [ref_value, n1] = dgb::compute_ref_hash_for_work(withseg, params);

    EXPECT_NE(ref_placeholder, ref_value)
        << "segwit field not reaching the ref preimage -- placeholder regressed away";
}

} // namespace
