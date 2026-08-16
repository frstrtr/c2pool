// SPDX-License-Identifier: AGPL-3.0-or-later
/// DASH daemonless COLD-CUT MN-payee bridge: anchor-header trust-anchor KAT.
///
/// THE INCIDENT (2026-08-16, vm905 wa0655re8, cut binary master 01dbba13 =
/// #1243+#1250, --coin-rpc removed, --embedded-null-arm, NO dashd). #1250 made
/// the header tip seed instantly AT the MN anchor (2513000), so the fold is
/// eligible at t~=0 (see test_dash_header_checkpoint_coincide). Yet the
/// embedded arm still NEVER served:
///     [EMBED-STATUS] arm=would-decline cause=no-tip populated=0 have_mn=0
///     bridge_wait=fold-mnlist-reply@h=2513000 hdr_tip=2517000
/// The bridge asks for a base=ZERO snapshot at the anchor; the peer answers;
/// the demux routes it to on_historical_snapshot; but DIP-4 authentication
/// step (b) — bind the snapshot's cbTx merkle proof to OUR PoW-verified
/// header's hashMerkleRoot — FAILS "block header not held" and the snapshot is
/// consumed-but-never-applied. The payee cursor never leaves the anchor,
/// have_mn stays 0, populated = have_tip AND have_mn stays 0, and on a
/// --coin-rpc-removed binary there is NO dashd fallback → NO template → rigs
/// shed before the first serve (reserve 25 -> 0 in ~14 min).
///
/// ROOT CAUSE. The #1250 fast-start seed built the anchor IndexEntry setting
/// ONLY hash/height/chain_work/prev_hash/status — it never set entry.header,
/// so entry.header.m_merkle_root is default (all-zero). main_dash.cpp's
/// set_merkle_root_at_fn returns get_header(anchor)->header.m_merkle_root, i.e.
/// a NULL root, and authenticate_historical_snapshot (historical_sml.hpp step
/// b) fails closed. Pre-#1250 the anchor header was crawled in from the older
/// 2400000 pin, so this root was present; #1250 dropped it while keeping the
/// (correct) instant-start.
///
/// THE FIX (this PR). Pin the anchor block's FULL 80-byte header alongside its
/// already release-pinned hash, and have the seed populate entry.header from
/// it — but ONLY after self-verifying X11(header) == hash. That mints no new
/// trust (the merkle root is derived from the already-approved hash) and fails
/// closed on a corrupt pin.
///
/// RED on master: the seeded anchor entry has a null merkleRoot (tests 1-2
/// use only master-present API, so they compile AND run on a pre-fix tree and
/// FAIL there). GREEN with the fix: the seed carries+verifies the header, so
/// the trust anchor is present at t~=0. Test 3 (fail-closed) is guarded on the
/// fix's feature macro so the file still compiles on master.
///
/// #143 note: FOLDED into the allowlisted test_dash_node_reception_wire target
/// (a standalone add_executable would silently report "Not Run"). #895 note:
/// no #ifdef around the RED/GREEN bodies, so a green tick means they ran.

#include <gtest/gtest.h>

#include <impl/dash/coin/header_chain.hpp>   // HeaderChain, make_dash_chain_params_mainnet, x11_hash

#include <core/uint256.hpp>

#include <optional>

using dash::coin::HeaderChain;
using dash::coin::make_dash_chain_params_mainnet;

namespace {

// The real hashMerkleRoot of mainnet block 2513000 (big-endian display), as
// reported by two independent chain sources and, decisively, as recomputed by
// X11 over the pinned 80-byte header inside the product itself.
constexpr const char* kAnchorMerkleRoot =
    "01470ce31e4ec9934a229f6eef4c9f561e42898be48d0bd646ab80f4bcc15b9c";
constexpr uint32_t kAnchorHeight = 2513000;

} // namespace

// ─────────────────────────────────────────────────────────────────────────
// 1. REGRESSION. After the cold seed, the anchor's header merkleRoot — the
//    DIP-4 trust anchor the MN-set bridge authenticates every historical
//    snapshot against — must be PRESENT and equal to the real block's root.
//    RED on master (seed leaves entry.header default -> null root -> bridge
//    fails closed -> have_mn never flips -> no embedded template).
// ─────────────────────────────────────────────────────────────────────────
TEST(DashAnchorHeaderMerkleRoot, ColdSeedPopulatesVerifiedAnchorMerkleRoot)
{
    HeaderChain hc(make_dash_chain_params_mainnet()); // db_path="" -> in-memory
    ASSERT_TRUE(hc.init());                            // seeds the fast-start checkpoint

    auto e = hc.get_header_by_height(kAnchorHeight);
    ASSERT_TRUE(e.has_value())
        << "the fast-start checkpoint did not seed the anchor entry at all";

    EXPECT_FALSE(e->header.m_merkle_root.IsNull())
        << "anchor merkleRoot is NULL: the seed populated only the hash, so "
           "authenticate_historical_snapshot step (b) fails 'block header not "
           "held' — the base=ZERO anchor snapshot is consumed but never "
           "applied, the payee cursor never leaves h=" << kAnchorHeight
        << ", have_mn stays 0 and the embedded arm never serves";

    uint256 expected;
    expected.SetHex(kAnchorMerkleRoot);
    EXPECT_EQ(e->header.m_merkle_root, expected)
        << "seeded anchor merkleRoot does not match mainnet block "
        << kAnchorHeight;
}

// ─────────────────────────────────────────────────────────────────────────
// 2. WIRE PARITY WITH THE BRIDGE. Reproduce EXACTLY the callback
//    main_dash.cpp installs as set_merkle_root_at_fn and feed it the anchor
//    hash: it must return the real, non-null root. This is the precise value
//    authenticate_historical_snapshot reads for its step-(b) proof. RED on
//    master (returns a null root).
// ─────────────────────────────────────────────────────────────────────────
TEST(DashAnchorHeaderMerkleRoot, MerkleRootCallbackYieldsAnchorRootForBridge)
{
    HeaderChain hc(make_dash_chain_params_mainnet());
    ASSERT_TRUE(hc.init());

    // Byte-for-byte the lambda from main_dash.cpp set_merkle_root_at_fn.
    auto merkle_root_of_hash =
        [&hc](const uint256& block_hash) -> std::optional<uint256> {
        if (auto e = hc.get_header(block_hash))
            return e->header.m_merkle_root;
        return std::nullopt;
    };

    auto cp = make_dash_chain_params_mainnet().fast_start_checkpoint;
    ASSERT_TRUE(cp.has_value());

    auto root = merkle_root_of_hash(cp->hash);
    ASSERT_TRUE(root.has_value())
        << "the anchor entry is not even in the header index";
    EXPECT_FALSE(root->IsNull())
        << "set_merkle_root_at_fn returns a NULL root for the anchor -> "
           "authenticate_historical_snapshot fails closed at step (b)";

    uint256 expected;
    expected.SetHex(kAnchorMerkleRoot);
    EXPECT_EQ(*root, expected);
}

#ifdef C2POOL_FAST_START_CHECKPOINT_HAS_HEADER
// ─────────────────────────────────────────────────────────────────────────
// 3. REWARD-SAFETY / FAIL-CLOSED. The seed must adopt the pinned header ONLY
//    when X11(header) == the pinned block hash. Corrupt one bit of the pinned
//    header and the seed must REFUSE it (leave the merkleRoot null) rather
//    than seed a header whose forged merkleRoot could authenticate a forged
//    SML. This is what makes the pin trust-neutral: the root is only trusted
//    once proven to hash to the already release-pinned hash.
//    (Guarded on the fix's feature macro so this file still compiles on a
//    pre-fix tree for the RED run of tests 1-2.)
// ─────────────────────────────────────────────────────────────────────────
TEST(DashAnchorHeaderMerkleRoot, CorruptPinnedHeaderIsRefusedFailClosed)
{
    auto params = make_dash_chain_params_mainnet();
    ASSERT_TRUE(params.fast_start_checkpoint.has_value());
    ASSERT_TRUE(params.fast_start_checkpoint->has_header)
        << "mainnet params must pin the anchor header for this guard to matter";

    // Flip one bit of the nonce: X11(header) no longer equals the pinned hash.
    params.fast_start_checkpoint->hdr_nonce ^= 1u;

    HeaderChain hc(params);
    ASSERT_TRUE(hc.init());

    auto e = hc.get_header_by_height(kAnchorHeight);
    ASSERT_TRUE(e.has_value());
    EXPECT_TRUE(e->header.m_merkle_root.IsNull())
        << "a header that does NOT hash to the pinned block hash was seeded "
           "anyway — a forged SML could then authenticate against its "
           "merkleRoot; the seed must fail closed";
}

// ─────────────────────────────────────────────────────────────────────────
// 4. SELF-CONSISTENCY. The pinned header actually hashes (X11) to the pinned
//    block hash — the whole basis for trusting its merkleRoot. Proven from the
//    product constant, not a fixture.
// ─────────────────────────────────────────────────────────────────────────
TEST(DashAnchorHeaderMerkleRoot, PinnedHeaderX11EqualsPinnedBlockHash)
{
    auto params = make_dash_chain_params_mainnet();
    ASSERT_TRUE(params.fast_start_checkpoint.has_value());
    const auto& cp = params.fast_start_checkpoint.value();
    ASSERT_TRUE(cp.has_header);

    dash::coin::BlockHeaderType hdr;
    hdr.m_version        = cp.hdr_version;
    hdr.m_previous_block = cp.hdr_prev_block;
    hdr.m_merkle_root    = cp.hdr_merkle_root;
    hdr.m_timestamp      = cp.hdr_time;
    hdr.m_bits           = cp.hdr_bits;
    hdr.m_nonce          = cp.hdr_nonce;

    EXPECT_EQ(dash::coin::x11_hash(hdr), cp.hash)
        << "pinned anchor header does not X11-hash to the pinned block hash";
}
#endif // C2POOL_FAST_START_CHECKPOINT_HAS_HEADER
