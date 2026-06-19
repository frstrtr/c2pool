// ---------------------------------------------------------------------------
// nmc::coin::TemplateBuilder KATs (P1 PC - embedded template builder).
//
// Re-homed mirror of the BTC template-builder coverage, fenced to src/impl/nmc/.
// Pins the three structural pieces the embedded NMC block-template path is built
// on:
//   * get_block_subsidy()   - Namecoin's (= Bitcoin's) 50-coin / 210,000-block
//                             halving schedule, at and around the boundaries;
//   * compute_merkle_root() - the SHA256d ComputeMerkleRoot walk for 0 / 1 / 2 /
//                             odd-count leaf lists, with roots re-derived
//                             INDEPENDENTLY here (not by calling the function)
//                             so a fold/duplicate bug is caught, not mirrored;
//   * TemplateBuilder::build_template() - end-to-end on a small seeded
//                             HeaderChain + Mempool: a present tip yields a
//                             GBT-shaped WorkData; an empty chain yields nullopt.
//
// PC is the STRUCTURAL builder only; merge-mining commitment / dual-target
// (phase PD) are NOT exercised here.
//
// Per-coin isolation: src/impl/nmc/ only; btc tree consumed READ-ONLY. MUST
// appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist or it
// becomes a NOT_BUILT sentinel that reds master.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <ctime>
#include <optional>
#include <vector>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include "../coin/header_chain.hpp"
#include "../coin/mempool.hpp"
#include "../coin/template_builder.hpp"

namespace {

using nmc::coin::HeaderChain;
using nmc::coin::Mempool;
using nmc::coin::NMCChainParams;
using nmc::coin::BlockHeaderType;
using nmc::coin::TemplateBuilder;
using nmc::coin::compute_merkle_root;
using nmc::coin::get_block_subsidy;
using nmc::coin::block_hash;

// Build NMC params with a TEST-only pinned activation height so plain headers
// below it ADMIT (production stays the -1 sentinel). Mirror of the auxpow test
// fixture's params_activation().
static NMCChainParams params_pinned()
{
    NMCChainParams p = NMCChainParams::mainnet();
    p.aux_chain_id = 1;
    p.auxpow_activation_height = 19200;  // TEST-only pin
    return p;
}

static BlockHeaderType plain_header(const uint256& prev, uint32_t bits,
                                    uint32_t nonce, uint32_t ts)
{
    BlockHeaderType h{};
    h.m_version        = 1;
    h.m_previous_block = prev;
    h.m_bits           = bits;
    h.m_nonce          = nonce;
    h.m_timestamp      = ts;
    return h;
}

// Independent reference combine: double-SHA256 of l||r over the 64-byte
// concatenation, computed WITHOUT touching compute_merkle_root.
static uint256 combine(const uint256& l, const uint256& r)
{
    auto sl = std::span<const uint8_t>(l.data(), 32);
    auto sr = std::span<const uint8_t>(r.data(), 32);
    return Hash(sl, sr);
}

static uint256 leaf_of(unsigned char b)
{
    uint256 u; u.SetNull();
    *(u.begin()) = b;
    return u;
}

// ── get_block_subsidy ──────────────────────────────────────────────────────

TEST(NmcTemplateSubsidy, InitialAndHalvingBoundaries)
{
    constexpr uint64_t COIN = 100000000ULL;
    EXPECT_EQ(get_block_subsidy(0u),        50ULL * COIN);
    EXPECT_EQ(get_block_subsidy(1u),        50ULL * COIN);
    EXPECT_EQ(get_block_subsidy(209999u),   50ULL * COIN);   // last pre-halving block
    EXPECT_EQ(get_block_subsidy(210000u),   25ULL * COIN);   // first halving
    EXPECT_EQ(get_block_subsidy(419999u),   25ULL * COIN);
    EXPECT_EQ(get_block_subsidy(420000u),   12ULL * COIN + COIN / 2);  // 12.5 NMC
    EXPECT_EQ(get_block_subsidy(630000u),   6ULL * COIN + COIN / 4);   // 6.25 NMC
}

TEST(NmcTemplateSubsidy, SubsidyReachesZeroAfter64Halvings)
{
    constexpr uint32_t INTERVAL = 210000u;
    // 63 halvings: still > 0 (50 BTC >> 63 == 0 actually, but >>63 of 5e9 is 0).
    // The contract is: >= 64 halvings -> exactly 0.
    EXPECT_EQ(get_block_subsidy(64u * INTERVAL), 0ULL);
    EXPECT_EQ(get_block_subsidy(100u * INTERVAL), 0ULL);
}

// ── compute_merkle_root ────────────────────────────────────────────────────

TEST(NmcTemplateMerkle, EmptyListIsZero)
{
    EXPECT_EQ(compute_merkle_root({}), uint256::ZERO);
}

TEST(NmcTemplateMerkle, SingleLeafIsItself)
{
    uint256 a = leaf_of(0x11);
    EXPECT_EQ(compute_merkle_root({a}), a);
}

TEST(NmcTemplateMerkle, TwoLeavesFoldOnce)
{
    uint256 a = leaf_of(0x11), b = leaf_of(0x22);
    EXPECT_EQ(compute_merkle_root({a, b}), combine(a, b));
}

TEST(NmcTemplateMerkle, OddCountDuplicatesLast)
{
    // Three leaves: last is duplicated -> root = combine(combine(a,b), combine(c,c)).
    uint256 a = leaf_of(0x11), b = leaf_of(0x22), c = leaf_of(0x33);
    uint256 want = combine(combine(a, b), combine(c, c));
    EXPECT_EQ(compute_merkle_root({a, b, c}), want);
}

TEST(NmcTemplateMerkle, FourLeavesBalancedTree)
{
    uint256 a = leaf_of(0x11), b = leaf_of(0x22),
            c = leaf_of(0x33), d = leaf_of(0x44);
    uint256 want = combine(combine(a, b), combine(c, d));
    EXPECT_EQ(compute_merkle_root({a, b, c, d}), want);
}

// ── TemplateBuilder::build_template ─────────────────────────────────────────

TEST(NmcTemplateBuild, EmptyChainReturnsNullopt)
{
    HeaderChain chain(params_pinned());   // no headers added
    Mempool pool;
    auto wd = TemplateBuilder::build_template(chain, pool, /*is_testnet=*/false);
    EXPECT_FALSE(wd.has_value());
}

TEST(NmcTemplateBuild, SeededChainYieldsWorkData)
{
    HeaderChain chain(params_pinned());
    Mempool pool;

    // Seed a small chain with a recent timestamp so the tip is "fresh".
    auto now = static_cast<uint32_t>(std::time(nullptr));
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, 0x1d00ffffu, 1, now - 100);
    ASSERT_TRUE(chain.add_header(g));
    BlockHeaderType c = plain_header(block_hash(g), 0x1d00ffffu, 2, now - 50);
    ASSERT_TRUE(chain.add_header(c));
    ASSERT_EQ(chain.height(), 1u);

    auto wd = TemplateBuilder::build_template(chain, pool, /*is_testnet=*/false);
    ASSERT_TRUE(wd.has_value());

    const auto& d = wd->m_data;
    // Next block builds on the tip: height = tip.height + 1 = 2.
    EXPECT_EQ(d.at("height").get<int>(), 2);
    EXPECT_EQ(d.at("previousblockhash").get<std::string>(), block_hash(c).GetHex());
    // No mempool txs -> coinbasevalue == subsidy(2) == 50 NMC.
    EXPECT_EQ(d.at("coinbasevalue").get<int64_t>(),
              static_cast<int64_t>(get_block_subsidy(2u)));
    EXPECT_TRUE(d.at("transactions").is_array());
    EXPECT_EQ(d.at("transactions").size(), 0u);
    // bits hex is 8 lowercase hex chars; tip carried 0x1d00ffff which is below
    // the retarget interval so next_bits == tip_bits.
    EXPECT_EQ(d.at("bits").get<std::string>(), std::string("1d00ffff"));
    // Version floored to the BIP9 base.
    EXPECT_GE(static_cast<uint32_t>(d.at("version").get<int>()),
              TemplateBuilder::BIP9_BASE_VERSION);
    EXPECT_EQ(d.at("rules"), nlohmann::json::array({"segwit"}));
}

TEST(NmcTemplateBuild, StaleTipReportsNotSynced)
{
    // A chain whose tip is older than DEFAULT_MAX_TIP_AGE is not synced, but
    // build_template still produces a template (sync gating lives in the node
    // wrapper, not the builder). This pins that separation.
    HeaderChain chain(params_pinned());
    Mempool pool;
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, 0x1d00ffffu, 1, /*ts=*/1000000);  // ancient
    ASSERT_TRUE(chain.add_header(g));
    EXPECT_FALSE(chain.is_synced());
    auto wd = TemplateBuilder::build_template(chain, pool, /*is_testnet=*/false);
    EXPECT_TRUE(wd.has_value());
}

} // namespace
