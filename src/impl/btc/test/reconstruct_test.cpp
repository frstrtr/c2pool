// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::coin::reconstruct_won_block / select_won_block_merkle_link /
// make_reconstruct_closure test (#744 broadcaster arc, faithful as_block
// composition + run-loop closure -- slice 5/7).
//
// Slice 4 (block_assembly_test.cpp) pinned the FRAMING half (merkle-root
// reconstruction + [gentx]++other_txs ordering + body/header fail-closed guard +
// conditional witness codec). This slice pins the COMPOSITION that feeds it:
//   * select_won_block_merkle_link -- the SEGWIT link selection SSOT
//     (share_check.hpp:674-692): segwit-activated shares with segwit_data walk
//     segwit_data.txid_merkle_link, legacy (or segwit-active-but-no-segwit_data)
//     shares walk merkle_link. The framer takes an ALREADY-resolved link, so the
//     selection is exercised HERE, in the caller;
//   * reconstruct_won_block -- select link + assemble_won_block, round-tripping
//     through the live BlockType wire codec, with the captured GBT template as
//     the non-coinbase tx source (NOT tx_hash_refs);
//   * make_reconstruct_closure -- the run-loop WonBlockReconstructor: fail-closed
//     (std::nullopt, never throw) on a malformed gentx or a body/header mismatch,
//     and WIRED end-to-end into make_on_block_found (won_block_dispatch.hpp) so
//     the dispatch dual-path carries the reconstructed block.
//
// Fixtures mirror block_assembly_test.cpp (self-derived via the same Hash() the
// merkle walk uses, independent of any fixture file). Rides the already-
// allowlisted btc_share_test executable, so no build.yml --target change is
// needed. p2pool-merged-v36 surface: NONE.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>

#include <impl/btc/coin/reconstruct_won_block.hpp>
#include <impl/btc/coin/won_block_dispatch.hpp>
#include <impl/btc/config_pool.hpp>

namespace {

using btc::coin::BlockType;
using btc::coin::SmallBlockHeaderType;
using btc::coin::MutableTransaction;
using btc::coin::TxIn;
using btc::coin::TxOut;
using btc::coin::other_tx_txid;
using btc::coin::ReconstructedWonBlock;
using btc::coin::WonShareReconstructFields;
using btc::coin::reconstruct_won_block;
using btc::coin::select_won_block_merkle_link;
using btc::coin::make_reconstruct_closure;
using btc::coin::make_on_block_found;
using btc::coin::unpack_gentx_coinbase;

constexpr uint64_t SEGWIT_VER  = btc::PoolConfig::SEGWIT_ACTIVATION_VERSION;       // 33
constexpr uint64_t LEGACY_VER  = btc::PoolConfig::SEGWIT_ACTIVATION_VERSION - 1;   // 32

// --- fixtures (identical shapes to block_assembly_test.cpp) -------------------
MutableTransaction make_gentx()
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = 5000000000LL;
    tx.vout.push_back(out);
    return tx;
}

MutableTransaction make_tx(int64_t value)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = value;
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

uint256 combine(const uint256& cur, const uint256& branch, bool branch_left)
{
    PackStream ps;
    if (branch_left) { ps << branch; ps << cur; }
    else             { ps << cur; ps << branch; }
    auto sp = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ps.data()), ps.size());
    return Hash(sp);
}
uint256 pair_hash(const uint256& a, const uint256& b) { return combine(a, b, false); }

// The non-witness gentx bytes the SSOT serializer would hand the closure.
// NB: keep the PackStream in a NAMED local -- get_span() aliases its buffer, so
// a `pack(...).get_span()` temporary would dangle (cf. block_assembly.hpp).
std::vector<unsigned char> gentx_nonwitness_bytes(const MutableTransaction& tx)
{
    auto packed = pack(btc::coin::TX_NO_WITNESS(tx));
    auto sp = packed.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

uint256 gentx_txid(const MutableTransaction& tx)
{
    return Hash(pack(btc::coin::TX_NO_WITNESS(tx)).get_span());
}

::btc::MerkleLink one_branch_link(const uint256& sibling)
{
    ::btc::MerkleLink link;
    link.m_branch.push_back(sibling);
    link.m_index = 0;
    return link;
}

std::string to_hex_lower(const std::vector<unsigned char>& b)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (unsigned char c : b) { s.push_back(d[c >> 4]); s.push_back(d[c & 0xf]); }
    return s;
}

// =============================================================================
// select_won_block_merkle_link -- the segwit selection SSOT
// =============================================================================

// --- Test 1: segwit-active share WITH segwit_data => txid_merkle_link ----------
TEST(BtcReconstructLinkSelect, SegwitPicksTxidLink)
{
    uint256 legacy_sib;  legacy_sib.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    uint256 segwit_sib;  segwit_sib.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
    auto merkle_link = one_branch_link(legacy_sib);
    std::optional<::btc::MerkleLink> txid_link = one_branch_link(segwit_sib);

    const auto& picked = select_won_block_merkle_link(SEGWIT_VER, merkle_link, txid_link);
    ASSERT_EQ(picked.m_branch.size(), 1u);
    EXPECT_EQ(picked.m_branch[0], segwit_sib);   // the txid link, not the legacy one
}

// --- Test 2: legacy share => merkle_link, even if a txid link is present -------
TEST(BtcReconstructLinkSelect, LegacyPicksMerkleLink)
{
    uint256 legacy_sib;  legacy_sib.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    uint256 segwit_sib;  segwit_sib.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
    auto merkle_link = one_branch_link(legacy_sib);
    std::optional<::btc::MerkleLink> txid_link = one_branch_link(segwit_sib);

    const auto& picked = select_won_block_merkle_link(LEGACY_VER, merkle_link, txid_link);
    ASSERT_EQ(picked.m_branch.size(), 1u);
    EXPECT_EQ(picked.m_branch[0], legacy_sib);
}

// --- Test 3: segwit-active but NO segwit_data (sentinel) => merkle_link --------
TEST(BtcReconstructLinkSelect, SegwitActiveNoSegwitDataPicksMerkleLink)
{
    uint256 legacy_sib;  legacy_sib.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    auto merkle_link = one_branch_link(legacy_sib);
    std::optional<::btc::MerkleLink> none = std::nullopt;

    const auto& picked = select_won_block_merkle_link(SEGWIT_VER, merkle_link, none);
    ASSERT_EQ(picked.m_branch.size(), 1u);
    EXPECT_EQ(picked.m_branch[0], legacy_sib);
}

// =============================================================================
// reconstruct_won_block -- select link + frame, round-trip through BlockType
// =============================================================================

// --- Test 4: coinbase-only (empty template) round-trips, single-tx block -------
TEST(BtcReconstructBody, CoinbaseOnlyRoundTrips)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gid = gentx_txid(gentx);
    ::btc::MerkleLink empty;   // empty branch => header root == gentx txid

    auto r = reconstruct_won_block(sh, LEGACY_VER, empty, std::nullopt, gentx, gid, {});
    EXPECT_EQ(r.hex, HexStr(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(r.bytes.data()), r.bytes.size())));

    PackStream ps(r.bytes);
    BlockType blk;
    ps >> blk;
    EXPECT_EQ(blk.m_merkle_root, gid);
    ASSERT_EQ(blk.m_txs.size(), 1u);
    EXPECT_EQ(blk.m_txs[0].vout[0].value, gentx.vout[0].value);
}

// --- Test 5: one template tx, [gentx]++other order, consistent link -----------
TEST(BtcReconstructBody, WithTemplateTxOrdered)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gid = gentx_txid(gentx);
    auto tx1 = make_tx(10);
    auto t1id = other_tx_txid(tx1);
    auto link = one_branch_link(t1id);          // leaf-0 branch for [gentx, t1]

    auto r = reconstruct_won_block(sh, LEGACY_VER, link, std::nullopt, gentx, gid, {tx1});
    PackStream ps(r.bytes);
    BlockType blk;
    ps >> blk;
    EXPECT_EQ(blk.m_merkle_root, pair_hash(gid, t1id));
    ASSERT_EQ(blk.m_txs.size(), 2u);
    EXPECT_EQ(blk.m_txs[0].vin[0].prevout.index, 0xffffffffu);   // coinbase index 0
    EXPECT_EQ(blk.m_txs[1].vout[0].value, 10);
}

// --- Test 6: the SEGWIT link is the one actually walked (selection is live) ----
// Build a share whose header root was committed over the txid_merkle_link. The
// legacy merkle_link is deliberately a garbage branch: if reconstruct wrongly
// used it, the framer's body/header guard would throw. Success proves the segwit
// link was selected.
TEST(BtcReconstructBody, SegwitLinkIsWalkedNotLegacy)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gid = gentx_txid(gentx);
    auto tx1 = make_tx(77);
    auto t1id = other_tx_txid(tx1);

    ::btc::MerkleLink good_txid_link = one_branch_link(t1id);        // matches body
    uint256 garbage; garbage.SetHex("dead00000000000000000000000000000000000000000000000000000000beef");
    ::btc::MerkleLink bad_legacy_link = one_branch_link(garbage);    // would mismatch

    auto r = reconstruct_won_block(sh, SEGWIT_VER, bad_legacy_link,
                                   std::optional<::btc::MerkleLink>(good_txid_link),
                                   gentx, gid, {tx1});
    PackStream ps(r.bytes);
    BlockType blk;
    ps >> blk;
    EXPECT_EQ(blk.m_merkle_root, pair_hash(gid, t1id));
    ASSERT_EQ(blk.m_txs.size(), 2u);
}

// --- Test 7: body/header mismatch propagates as a throw from the body ----------
TEST(BtcReconstructBody, MismatchThrows)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gid = gentx_txid(gentx);
    ::btc::MerkleLink empty;   // header commits coinbase-only, but body has a fee tx
    EXPECT_THROW(
        reconstruct_won_block(sh, LEGACY_VER, empty, std::nullopt, gentx, gid, {make_tx(5)}),
        std::runtime_error);
}

// =============================================================================
// make_reconstruct_closure -- the fail-closed run-loop WonBlockReconstructor
// =============================================================================

// --- Test 8: success path returns bytes == direct reconstruct_won_block --------
TEST(BtcReconstructClosure, SuccessMatchesDirectReconstruct)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gid = gentx_txid(gentx);
    auto tx1 = make_tx(10);
    auto t1id = other_tx_txid(tx1);
    auto link = one_branch_link(t1id);

    auto fields_fn = [&](const uint256&) {
        WonShareReconstructFields f;
        f.small_header = sh;
        f.share_version = LEGACY_VER;
        f.merkle_link = link;
        f.txid_merkle_link = std::nullopt;
        return f;
    };
    auto gentx_fn = [&](const uint256&) { return gentx_nonwitness_bytes(gentx); };
    auto tmpl_fn  = [&](const uint256&) { return std::vector<MutableTransaction>{tx1}; };

    auto recon = make_reconstruct_closure(fields_fn, gentx_fn, tmpl_fn);
    auto out = recon(uint256::ZERO);

    ASSERT_TRUE(out.has_value());
    auto direct = reconstruct_won_block(sh, LEGACY_VER, link, std::nullopt, gentx, gid, {tx1});
    EXPECT_EQ(out->first, direct.bytes);
    EXPECT_EQ(out->second, direct.hex);
    EXPECT_EQ(out->second, to_hex_lower(out->first));
}

// --- Test 9: malformed gentx (trailing bytes) => FAIL CLOSED (nullopt) ---------
TEST(BtcReconstructClosure, MalformedGentxFailsClosed)
{
    auto sh = make_small_header();
    auto fields_fn = [&](const uint256&) {
        WonShareReconstructFields f;
        f.small_header = sh;
        f.share_version = LEGACY_VER;
        return f;
    };
    // Append a trailing byte so unpack_gentx_coinbase throws std::out_of_range.
    auto bad_bytes = gentx_nonwitness_bytes(make_gentx());
    bad_bytes.push_back(0x00);
    auto gentx_fn = [&](const uint256&) { return bad_bytes; };
    auto tmpl_fn  = [&](const uint256&) { return std::vector<MutableTransaction>{}; };

    auto recon = make_reconstruct_closure(fields_fn, gentx_fn, tmpl_fn);
    EXPECT_FALSE(recon(uint256::ZERO).has_value());   // never throws out of the callback
}

// --- Test 10: body/header mismatch => FAIL CLOSED (nullopt), not a throw -------
TEST(BtcReconstructClosure, MerkleMismatchFailsClosed)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto fields_fn = [&](const uint256&) {
        WonShareReconstructFields f;
        f.small_header = sh;
        f.share_version = LEGACY_VER;
        f.merkle_link = ::btc::MerkleLink{};   // empty => coinbase-only header root
        f.txid_merkle_link = std::nullopt;
        return f;
    };
    auto gentx_fn = [&](const uint256&) { return gentx_nonwitness_bytes(gentx); };
    // But the template carries a fee tx => body root != header root => guard throws.
    auto tmpl_fn  = [&](const uint256&) { return std::vector<MutableTransaction>{make_tx(9)}; };

    auto recon = make_reconstruct_closure(fields_fn, gentx_fn, tmpl_fn);
    EXPECT_FALSE(recon(uint256::ZERO).has_value());
}

// =============================================================================
// WIRING: make_reconstruct_closure -> make_on_block_found -> BOTH dual-path arms
// =============================================================================

// --- Test 11: the closure drives the dispatch handler end-to-end ---------------
TEST(BtcReconstructWiring, ClosureDrivesDispatchDualPath)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gid = gentx_txid(gentx);
    ::btc::MerkleLink empty;

    auto fields_fn = [&](const uint256&) {
        WonShareReconstructFields f;
        f.small_header = sh;
        f.share_version = LEGACY_VER;
        f.merkle_link = empty;
        f.txid_merkle_link = std::nullopt;
        return f;
    };
    auto gentx_fn = [&](const uint256&) { return gentx_nonwitness_bytes(gentx); };
    auto tmpl_fn  = [&](const uint256&) { return std::vector<MutableTransaction>{}; };

    auto recon = make_reconstruct_closure(fields_fn, gentx_fn, tmpl_fn);

    std::vector<unsigned char> relayed;
    bool did_relay = false;
    std::string submitted;
    int submit_calls = 0;
    auto relay  = [&](const std::vector<unsigned char>& b) { did_relay = true; relayed = b; return true; };
    auto submit = [&](const std::string& h) { ++submit_calls; submitted = h; return true; };

    auto handler = make_on_block_found(recon, relay, submit);
    handler(uint256::ZERO);   // FORCE the won share through the real reconstructor

    // Both arms fired, carrying the byte-identical reconstructed block.
    auto direct = reconstruct_won_block(sh, LEGACY_VER, empty, std::nullopt, gentx, gid, {});
    ASSERT_TRUE(did_relay);
    EXPECT_EQ(relayed, direct.bytes);
    ASSERT_EQ(submit_calls, 1);
    EXPECT_EQ(submitted, direct.hex);
    EXPECT_EQ(to_hex_lower(relayed), submitted);   // cross-arm identity
}

// --- Test 12: a malformed won share reconstructs to nullopt => NEITHER arm -----
TEST(BtcReconstructWiring, FailClosedShareBroadcastsNothing)
{
    auto fields_fn = [&](const uint256&) {
        WonShareReconstructFields f;
        f.share_version = LEGACY_VER;
        return f;
    };
    auto bad_bytes = gentx_nonwitness_bytes(make_gentx());
    bad_bytes.push_back(0x00);                 // trailing byte => unpack throws
    auto gentx_fn = [&](const uint256&) { return bad_bytes; };
    auto tmpl_fn  = [&](const uint256&) { return std::vector<MutableTransaction>{}; };

    auto recon = make_reconstruct_closure(fields_fn, gentx_fn, tmpl_fn);

    bool did_relay = false;
    int submit_calls = 0;
    auto relay  = [&](const std::vector<unsigned char>&) { did_relay = true; return true; };
    auto submit = [&](const std::string&) { ++submit_calls; return true; };

    auto handler = make_on_block_found(recon, relay, submit);
    handler(uint256::ZERO);

    EXPECT_FALSE(did_relay);
    EXPECT_EQ(submit_calls, 0);
}

} // namespace
