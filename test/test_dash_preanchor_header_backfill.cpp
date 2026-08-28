// SPDX-License-Identifier: AGPL-3.0-or-later
/// DASH daemonless COLD-START pre-anchor header backfill KAT (#1263 stack).
///
/// THE INCIDENT (2026-08-17, vm905, --coin-rpc removed, dashd ABSENT). The
/// #1263 getqrinfo straddle seed is FULLY WIRED — the cold node asks for the
/// rotated-quorum snapshot at the cycle base, the peer answers, the consumer
/// binds mnListDiffAtHMinusC at exactly B0-C-8 — yet the seed NEVER lands:
///
///     [MN-DIFF-DB] getqrinfo cycle diff 0 DIP-4 auth FAILED at work h=2512792
///     ...historical snapshot AUTH FAILED (block header not held)...
///
/// ROOT CAUSE. The three rotated quarter snapshots for cycle 2513088 are at
/// WORK blocks 2512792 / 2512504 / 2512216 — all BELOW the fast-start anchor
/// (2513000). At cold fast-start HeaderChain holds a LONE anchor and none of
/// those pre-anchor headers, so DIP-4 leg (b) — bind the snapshot's cbTx merkle
/// proof to OUR PoW-verified header's hashMerkleRoot — fails "block header not
/// held" and the snapshot is consumed-but-never-applied. The store caps below
/// the straddle, the resolver arms capped, the bridge falls to the network
/// payee lane → PAYEE DESYNC fail-closed → no embedded template. The forward
/// add_header path cannot fix this: a pre-anchor header's parent is not held,
/// so it orphan-rejects.
///
/// THE FIX (this PR, dashd-parity). At cold store-arm, once the qrinfo reply is
/// in hand, one-shot BACKWARD getheaders fetches the pre-anchor span and
/// HeaderChain::install_preanchor_span installs it by walking DOWN from the
/// trusted anchor: each parent is bound to its already-trusted child by an
/// X11 prev-hash link AND independently check_pow-verified — exactly the two
/// legs dashd requires of any header it stores (LookupBlockIndex over its full
/// header tree). DIP-4 leg (b) stays STRICT (header must be held); a
/// wrong/missing header installs nothing → leg (b) still fails closed → no bad
/// mint. The tip / best-work are never moved (pre-anchor headers never compete
/// for the tip; the synthetic-anchor daemon-tip honesty guards stay intact).
///
/// RED → GREEN is demonstrated WITHIN each test at runtime: BEFORE install,
/// get_header(work_block) == nullopt and the leg-(b) merkle_root_of_hash
/// callback returns nullopt ("block header not held"); AFTER install, the same
/// callback returns the header's real merkleRoot — the exact value
/// authenticate_historical_snapshot reads for its step-(b) proof. Fail-closed
/// tests prove a PoW-broken or anchor-detached batch installs nothing.
///
/// The whole file is guarded on the fix's feature macro so it still COMPILES
/// (empty) on a pre-fix tree that lacks install_preanchor_span. #143 note:
/// FOLDED into the allowlisted test_dash_node_reception_wire target (a
/// standalone add_executable would silently report "Not Run").

#include <gtest/gtest.h>

#include <impl/dash/coin/header_chain.hpp>   // HeaderChain, params, x11_hash, check_pow

#include <core/uint256.hpp>

#include <cstdio>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#ifdef C2POOL_PREANCHOR_SPAN_BACKFILL

using dash::coin::HeaderChain;
using dash::coin::DashChainParams;
using dash::coin::BlockHeaderType;
using dash::coin::make_dash_chain_params_mainnet;
using dash::coin::x11_hash;

namespace {

// bits = 0x207fffff decodes to target 0x7fffff·2^(8·29) (~2^255) — the largest
// compact-representable target. pow_limit is set EQUAL to that target so
// check_pow's `target > pow_limit` guard passes; roughly half of random X11
// hashes fall under it, so mine_hdr grinds the nonce a couple of times to make
// each synthetic header PoW-VALID. X11 identity + prev-hash linkage are
// exercised exactly as in production; only the difficulty is relaxed so a KAT
// needs no real proof-of-work.
constexpr uint32_t kEasyBits = 0x207fffffu;

DashChainParams make_easy_params()
{
    DashChainParams p = make_dash_chain_params_mainnet();
    p.pow_limit.SetHex(
        "7fffff0000000000000000000000000000000000000000000000000000000000");
    // Drop the mainnet fast-start pin; each test installs its own synthetic
    // anchor via set_dynamic_checkpoint so it controls the anchor header.
    p.fast_start_checkpoint.reset();
    p.genesis_hash = uint256::ZERO;   // no genesis stub — start empty
    return p;
}

// The distinct, non-null merkleRoot for the header at height `tag` — encoded so
// the leg-(b) assertion can prove the RIGHT header's root is returned.
uint256 tag_root(uint32_t tag)
{
    char buf[9];
    std::snprintf(buf, sizeof buf, "%08x", tag);
    std::string hex = "bb";
    hex += buf;
    hex.resize(64, '0');
    uint256 r;
    r.SetHex(hex);
    return r;
}

// A header linking to `prev`, tagged at height `tag`, WITHOUT grinding PoW.
// Used to plant a deliberately PoW-broken header (bits carry an impossible
// target).
BlockHeaderType raw_hdr(const uint256& prev, uint32_t bits, uint32_t tag)
{
    BlockHeaderType h;
    h.m_version        = 0x20000000u;
    h.m_previous_block = prev;
    h.m_merkle_root    = tag_root(tag);
    h.m_timestamp      = 1785000000u + tag;
    h.m_bits           = bits;
    h.m_nonce          = tag;
    return h;
}

// A PoW-VALID header: grind the nonce until X11(header) <= target(kEasyBits).
BlockHeaderType mine_hdr(const uint256& prev, const uint256& pow_limit,
                         uint32_t tag)
{
    BlockHeaderType h = raw_hdr(prev, kEasyBits, tag);
    for (uint32_t n = 0; ; ++n) {
        h.m_nonce = n;
        if (dash::coin::check_pow(x11_hash(h), h.m_bits, pow_limit))
            return h;
    }
}

struct SynthChain {
    DashChainParams params;
    uint32_t easy_bits{0};
    uint32_t anchor_height{0};
    uint256  anchor_hash;
    BlockHeaderType anchor_hdr;
    // batch = getheaders reply span [deepest .. anchor], anchor terminal
    std::vector<BlockHeaderType> batch;
    // hashes by height for assertions (heights below anchor)
    std::vector<std::pair<uint32_t, uint256>> below;   // {height, hash}
    std::vector<uint256> below_roots;                  // parallel merkleRoots
};

// Build a `count`-deep pre-anchor span below `anchor_height`. Header for the
// deepest block links to a parent NOT in the batch, so the downward walk stops
// there (the natural bottom of a bounded getheaders reply).
SynthChain build_chain(uint32_t anchor_height, int count)
{
    SynthChain c;
    c.params        = make_easy_params();
    c.easy_bits     = kEasyBits;
    c.anchor_height = anchor_height;

    const uint32_t bottom_h = anchor_height - static_cast<uint32_t>(count);
    // parent of the deepest header — intentionally absent from the batch.
    uint256 prev; prev.SetHex(
        "deadbeef00000000000000000000000000000000000000000000000000000000");

    std::vector<BlockHeaderType> chain;   // bottom → anchor
    for (uint32_t h = bottom_h; h <= anchor_height; ++h) {
        BlockHeaderType hd = mine_hdr(prev, c.params.pow_limit, /*tag=*/h);
        uint256 id = x11_hash(hd);
        if (h == anchor_height) {
            c.anchor_hdr  = hd;
            c.anchor_hash = id;
        } else {
            c.below.emplace_back(h, id);
            c.below_roots.push_back(hd.m_merkle_root);
        }
        chain.push_back(hd);
        prev = id;   // next header's parent
    }
    // getheaders returns ascending; the installer indexes by hash regardless.
    c.batch = chain;
    return c;
}

// Byte-for-byte the leg-(b) callback main_dash.cpp binds as `mroot` (the
// std::function signature of dash::coin::MerkleRootOfHashFn).
std::function<std::optional<uint256>(const uint256&)>
leg_b(const HeaderChain& hc)
{
    return [&hc](const uint256& b) -> std::optional<uint256> {
        if (auto e = hc.get_header(b))
            return e->header.m_merkle_root;
        return std::nullopt;
    };
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────
// 1. RED → GREEN. Before install the three pre-anchor work-block headers are
//    absent and leg (b) fails "block header not held"; after
//    install_preanchor_span walks them down from the trusted anchor, leg (b)
//    returns each real merkleRoot — the seed authenticates.
// ─────────────────────────────────────────────────────────────────────────
TEST(DashPreanchorHeaderBackfill, InstallMakesLegBConsultPreanchorHeaders)
{
    SynthChain c = build_chain(/*anchor_height=*/2513000, /*count=*/3);
    HeaderChain hc(c.params);
    ASSERT_TRUE(hc.init());
    hc.set_dynamic_checkpoint(c.anchor_height, c.anchor_hash);   // lone anchor
    ASSERT_EQ(hc.height(), c.anchor_height);

    auto legb = leg_b(hc);

    // RED (in-test): every pre-anchor work-block header is absent → leg (b)
    // returns nullopt ("block header not held") → snapshot fails closed.
    for (const auto& [h, id] : c.below) {
        EXPECT_FALSE(hc.has_header(id))
            << "pre-anchor header at h=" << h << " must be absent at cold start";
        EXPECT_FALSE(legb(id).has_value())
            << "leg (b) must fail closed for the un-held header at h=" << h;
    }

    // Install the pre-anchor span walking DOWN from the trusted anchor.
    const size_t n = hc.install_preanchor_span(c.anchor_hash, c.batch);
    EXPECT_EQ(n, c.below.size())
        << "every X11-linked + PoW-verified pre-anchor header must install";

    // GREEN (in-test): leg (b) now returns each header's REAL merkleRoot.
    for (size_t i = 0; i < c.below.size(); ++i) {
        const auto& [h, id] = c.below[i];
        ASSERT_TRUE(hc.has_header(id))
            << "pre-anchor header at h=" << h << " must be held after install";
        auto root = legb(id);
        ASSERT_TRUE(root.has_value())
            << "leg (b) must now find the installed header at h=" << h;
        EXPECT_EQ(*root, c.below_roots[i])
            << "leg (b) must return the header's real merkleRoot at h=" << h;
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 2. TIP UNMOVED. Pre-anchor headers never compete for the tip: the install
//    must leave m_tip / height at the anchor so the synthetic-anchor daemon-
//    tip honesty guards stay intact.
// ─────────────────────────────────────────────────────────────────────────
TEST(DashPreanchorHeaderBackfill, InstallDoesNotMoveTheTip)
{
    SynthChain c = build_chain(2513000, 5);
    HeaderChain hc(c.params);
    ASSERT_TRUE(hc.init());
    hc.set_dynamic_checkpoint(c.anchor_height, c.anchor_hash);

    const uint32_t tip_before = hc.height();
    auto           head_before = hc.tip();
    ASSERT_TRUE(head_before.has_value());

    ASSERT_EQ(hc.install_preanchor_span(c.anchor_hash, c.batch), c.below.size());

    EXPECT_EQ(hc.height(), tip_before) << "the tip height must not move";
    auto head_after = hc.tip();
    ASSERT_TRUE(head_after.has_value());
    EXPECT_EQ(head_after->hash, head_before->hash)
        << "the tip hash must stay at the anchor";
    EXPECT_EQ(head_after->hash, c.anchor_hash);
}

// ─────────────────────────────────────────────────────────────────────────
// 3. FAIL-CLOSED: broken PoW. A header in the span whose bits FAIL check_pow
//    stops the downward walk; nothing at or below it installs, so leg (b)
//    still fails closed for those heights — never a bad mint.
// ─────────────────────────────────────────────────────────────────────────
TEST(DashPreanchorHeaderBackfill, PoWBrokenHeaderStopsWalkFailClosed)
{
    SynthChain c = build_chain(2513000, 4);
    HeaderChain hc(c.params);
    ASSERT_TRUE(hc.init());
    hc.set_dynamic_checkpoint(c.anchor_height, c.anchor_hash);

    // c.below is {anchor-1, anchor-2, anchor-3, anchor-4} in ascending height.
    // Break PoW on the SECOND header below the anchor (anchor-2): a compact
    // bits encoding a near-zero target that no X11 hash can satisfy. Its X11
    // id changes, so re-key the batch AND the anchor's child links accordingly
    // by rebuilding from the corrupted header up to the anchor.
    // Simplest faithful corruption: rebuild the chain, flipping one header's
    // bits to an impossible target, and re-link everything above it.
    const uint32_t impossible  = 0x03000001u;   // target ~ 1 → X11 hash > target
    const uint32_t bottom_h    = c.anchor_height - 4;
    uint256 prev; prev.SetHex(
        "deadbeef00000000000000000000000000000000000000000000000000000000");
    std::vector<BlockHeaderType> batch;
    uint256 anchor_hash;
    uint256 broken_id, below_top_id;   // anchor-2 (broken), anchor-1
    for (uint32_t h = bottom_h; h <= c.anchor_height; ++h) {
        const bool is_broken = (h == c.anchor_height - 2);
        // Good headers are PoW-mined; the broken one carries an impossible
        // target (no nonce can satisfy it) so check_pow rejects it.
        BlockHeaderType hd = is_broken
            ? raw_hdr(prev, impossible, /*tag=*/h)
            : mine_hdr(prev, c.params.pow_limit, /*tag=*/h);
        uint256 id = x11_hash(hd);
        if (h == c.anchor_height)      anchor_hash   = id;
        if (h == c.anchor_height - 2)  broken_id     = id;
        if (h == c.anchor_height - 1)  below_top_id  = id;
        batch.push_back(hd);
        prev = id;
    }
    HeaderChain hc2(c.params);
    ASSERT_TRUE(hc2.init());
    hc2.set_dynamic_checkpoint(c.anchor_height, anchor_hash);

    const size_t n = hc2.install_preanchor_span(anchor_hash, batch);
    // Only anchor-1 (directly below the anchor, PoW-good) installs; the walk
    // hits the impossible-PoW anchor-2 and STOPS.
    EXPECT_EQ(n, 1u) << "walk must stop at the first PoW-broken header";
    EXPECT_TRUE(hc2.has_header(below_top_id))
        << "the PoW-good header directly below the anchor installs";
    EXPECT_FALSE(hc2.has_header(broken_id))
        << "a PoW-broken header must NEVER be installed (fail closed)";
    EXPECT_FALSE(leg_b(hc2)(broken_id).has_value())
        << "leg (b) must fail closed for the rejected header";
}

// ─────────────────────────────────────────────────────────────────────────
// 4. FAIL-CLOSED: batch never reaches the anchor. A span whose top header is
//    NOT the trusted anchor (a lying peer, or a wrong stop hash) yields no
//    downward linkage from the anchor → zero installs → leg (b) unchanged.
// ─────────────────────────────────────────────────────────────────────────
TEST(DashPreanchorHeaderBackfill, BatchWithoutAnchorInstallsNothing)
{
    SynthChain c = build_chain(2513000, 3);
    HeaderChain hc(c.params);
    ASSERT_TRUE(hc.init());
    hc.set_dynamic_checkpoint(c.anchor_height, c.anchor_hash);

    // Drop the terminal (anchor) header from the batch: the walk can find no
    // trusted root to descend from.
    std::vector<BlockHeaderType> no_anchor(c.batch.begin(), c.batch.end() - 1);
    EXPECT_EQ(hc.install_preanchor_span(c.anchor_hash, no_anchor), 0u)
        << "a batch that never reaches the anchor must install nothing";

    // Entirely unrelated garbage installs nothing either.
    std::vector<BlockHeaderType> garbage;
    garbage.push_back(mine_hdr(uint256::ZERO, c.params.pow_limit, /*tag=*/777u));
    EXPECT_EQ(hc.install_preanchor_span(c.anchor_hash, garbage), 0u)
        << "a batch with no linkage to the anchor must install nothing";

    for (const auto& [h, id] : c.below) {
        (void)h;
        EXPECT_FALSE(leg_b(hc)(id).has_value())
            << "leg (b) stays fail-closed when the span never authenticated";
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 5. ANCHOR MUST BE HELD. If the claimed anchor is not in the header index,
//    the install refuses outright (no trust root) — installs nothing.
// ─────────────────────────────────────────────────────────────────────────
TEST(DashPreanchorHeaderBackfill, UnheldAnchorInstallsNothing)
{
    SynthChain c = build_chain(2513000, 3);
    HeaderChain hc(c.params);
    ASSERT_TRUE(hc.init());
    // NOTE: do NOT seed the anchor — it is unheld.
    EXPECT_FALSE(hc.has_header(c.anchor_hash));
    EXPECT_EQ(hc.install_preanchor_span(c.anchor_hash, c.batch), 0u)
        << "install must refuse when the anchor (trust root) is not held";
}

#endif // C2POOL_PREANCHOR_SPAN_BACKFILL
