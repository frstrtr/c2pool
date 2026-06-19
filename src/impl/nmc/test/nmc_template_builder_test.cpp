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
// PC is the STRUCTURAL builder only. Phase PD (the embedded IAuxChainBackend
// build-side: dual-target + the aux block-hash committed in the parent
// coinbase) is exercised by the NmcAuxChainEmbedded suite at the end.
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
#include "../coin/aux_chain_embedded.hpp"

#include <c2pool/merged/merged_mining.hpp>

namespace {

using nmc::coin::HeaderChain;
using nmc::coin::Mempool;
using nmc::coin::NMCChainParams;
using nmc::coin::BlockHeaderType;
using nmc::coin::TemplateBuilder;
using nmc::coin::compute_merkle_root;
using nmc::coin::get_block_subsidy;
using nmc::coin::block_hash;
using nmc::coin::AuxChainEmbedded;

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


// -- P1 PD: AuxChainEmbedded (embedded IAuxChainBackend build-side) ----------
//
// Pins the merge-mining aux-work the BTC parent pulls from the embedded NMC
// node: dual-target (aux PoW target from template bits), the aux block-hash
// committed in the parent coinbase (= NMC tip), and the consensus chain_id
// (= NMCChainParams::aux_chain_id, the SAME field the verify side pins). Sync
// gating: an empty chain yields empty work (no daemon, no leak of a stale tip).

static c2pool::merged::AuxChainConfig nmc_aux_config()
{
    c2pool::merged::AuxChainConfig cfg;
    cfg.symbol   = "NMC";
    cfg.chain_id = 1;
    return cfg;
}

// Seed a synced two-header chain (fresh tip) and return its tip hash via out-param.
static void seed_synced_chain(HeaderChain& chain, uint256& tip_hash_out)
{
    auto now = static_cast<uint32_t>(std::time(nullptr));
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, 0x1d00ffffu, 1, now - 100);
    ASSERT_TRUE(chain.add_header(g));
    BlockHeaderType c = plain_header(block_hash(g), 0x1d00ffffu, 2, now - 50);
    ASSERT_TRUE(chain.add_header(c));
    tip_hash_out = block_hash(c);
}

TEST(NmcAuxChainEmbedded, SyncedChainYieldsAuxWork)
{
    HeaderChain chain(params_pinned());
    Mempool pool;
    uint256 tip_hash;
    seed_synced_chain(chain, tip_hash);
    ASSERT_TRUE(chain.is_synced());

    AuxChainEmbedded backend(chain, pool, params_pinned(), nmc_aux_config(),
                             /*testnet=*/false);
    ASSERT_TRUE(backend.connect());

    auto work = backend.get_work_template();

    // Aux block-hash committed in the parent coinbase == NMC tip.
    EXPECT_EQ(work.block_hash, tip_hash);
    // chain_id is the consensus params value (1), not left at the default 0.
    EXPECT_EQ(work.chain_id, 1u);
    // Next block builds on the tip: height == 2.
    EXPECT_EQ(work.height, 2);
    EXPECT_EQ(work.coinbase_value, get_block_subsidy(2u));
    EXPECT_EQ(work.prev_block_hash, tip_hash.GetHex());

    // Dual-target: aux PoW target re-derived INDEPENDENTLY from bits 0x1d00ffff.
    uint256 expected_target; expected_target.SetCompact(0x1d00ffffu);
    EXPECT_EQ(work.target, expected_target);
    EXPECT_FALSE(work.target == uint256::ZERO);

    EXPECT_EQ(backend.get_best_block_hash(), tip_hash.GetHex());
    EXPECT_EQ(backend.config().symbol, std::string("NMC"));
}

TEST(NmcAuxChainEmbedded, EmptyChainYieldsEmptyWork)
{
    HeaderChain chain(params_pinned());   // no headers -> not synced
    Mempool pool;
    ASSERT_FALSE(chain.is_synced());

    AuxChainEmbedded backend(chain, pool, params_pinned(), nmc_aux_config());
    auto work = backend.get_work_template();

    // Sync gate fired: no template fields leaked.
    EXPECT_TRUE(work.block_template.is_null());
    EXPECT_EQ(work.height, 0);
    EXPECT_EQ(work.coinbase_value, 0u);
    EXPECT_EQ(backend.get_best_block_hash(), std::string(""));
}

TEST(NmcAuxChainEmbedded, CreateAuxBlockMatchesGetWorkTemplate)
{
    HeaderChain chain(params_pinned());
    Mempool pool;
    uint256 tip_hash;
    seed_synced_chain(chain, tip_hash);

    AuxChainEmbedded backend(chain, pool, params_pinned(), nmc_aux_config());
    // Embedded mode is always multiaddress: createauxblock == getblocktemplate.
    auto a = backend.create_aux_block("ignored-address");
    auto b = backend.get_work_template();
    EXPECT_EQ(a.block_hash, b.block_hash);
    EXPECT_EQ(a.target, b.target);
    EXPECT_EQ(a.chain_id, b.chain_id);
    EXPECT_EQ(a.height, b.height);
}

TEST(NmcAuxChainEmbedded, SubmitBlockCachesHexForRetrieval)
{
    HeaderChain chain(params_pinned());
    Mempool pool;
    AuxChainEmbedded backend(chain, pool, params_pinned(), nmc_aux_config());

    EXPECT_EQ(backend.get_block_hex("any"), std::string(""));
    const std::string hex(200, 'a');
    // PE never-silent-drop: with no relay wired the block is NOT broadcast, so
    // submit_block() must report failure - but the hex is still cached for
    // get_block_hex() diagnostics/retrieval.
    EXPECT_FALSE(backend.submit_block(hex));
    EXPECT_EQ(backend.get_block_hex("any"), hex);
    // No daemon peers in embedded mode.
    EXPECT_TRUE(backend.getpeerinfo().empty());
}

// PE submit path: P2P relay is primary. When a relay sink is wired and reaches
// >=1 peer, submit_block() reports success and the sink receives the exact hex.
TEST(NmcAuxChainEmbedded, SubmitBlockRelaysExactHexToPeers)
{
    HeaderChain chain(params_pinned());
    Mempool pool;
    AuxChainEmbedded backend(chain, pool, params_pinned(), nmc_aux_config());

    std::string relayed;
    backend.set_block_relay([&](const std::string& block_hex) -> size_t {
        relayed = block_hex;          // capture what the broadcaster would send
        return 2;                     // pretend 2 peers received it
    });

    const std::string hex(200, 'b');
    EXPECT_TRUE(backend.submit_block(hex));   // relayed to >=1 peer => success
    EXPECT_EQ(relayed, hex);                  // byte-exact hand-off to the sink
    EXPECT_EQ(backend.get_block_hex("any"), hex);
}

// PE never-silent-drop: a relay that reaches 0 peers must NOT be reported as a
// successful broadcast, even though the sink ran (mirrors BTC #162).
TEST(NmcAuxChainEmbedded, SubmitBlockNeverSilentDropOnZeroPeers)
{
    HeaderChain chain(params_pinned());
    Mempool pool;
    AuxChainEmbedded backend(chain, pool, params_pinned(), nmc_aux_config());

    bool sink_ran = false;
    backend.set_block_relay([&](const std::string&) -> size_t {
        sink_ran = true;
        return 0;                     // no peers connected
    });

    const std::string hex(200, 'c');
    EXPECT_FALSE(backend.submit_block(hex));  // 0 peers => not broadcast
    EXPECT_TRUE(sink_ran);                    // sink was consulted, not skipped
    EXPECT_EQ(backend.get_block_hex("any"), hex);  // hex still cached
}

// PE dual-path gate (integrator note #3): the FALLBACK leg. submit_block() above
// is the P2P-primary route; submit_aux_block() is the submitauxblock RPC fallback.
// In embedded mode there is no daemon to RPC, so the fallback acknowledges (the
// P2P relay leg is authoritative) WITHOUT claiming a daemon submission - and,
// crucially, unlike submit_block() it does NOT populate the block-hex cache.
// This pins the two legs as DISTINCT (P2P-primary cached vs RPC-fallback no-cache),
// the both-paths-fire gate proven at unit level ahead of the live .140 won-block
// soak (which is daemon-gated). A coin is not block-viable until both legs exist.
TEST(NmcAuxChainEmbedded, SubmitAuxBlockFallbackLegIsDistinctFromP2PRelay)
{
    HeaderChain chain(params_pinned());
    Mempool pool;
    AuxChainEmbedded backend(chain, pool, params_pinned(), nmc_aux_config());

    uint256 aux_hash; aux_hash.SetNull();
    const std::string auxpow_hex(120, static_cast<char>(0x64));

    // Fallback leg acknowledges: embedded has no daemon, P2P relay is primary,
    // so the caller is not hard-failed (the block already went out over P2P).
    EXPECT_TRUE(backend.submit_aux_block(aux_hash, auxpow_hex));
    // ...but the RPC-fallback leg leaves the P2P submit_block() hex cache UNTOUCHED:
    // the two broadcaster legs are independent, not aliases of one path.
    EXPECT_EQ(backend.get_block_hex("any"), std::string(""));
}


} // namespace
