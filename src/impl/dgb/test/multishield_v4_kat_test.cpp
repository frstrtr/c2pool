// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// DGB MultiShield V4 next-target KAT (#179).
//
// Golden oracle: 150 CONSECUTIVE real DigiByte mainnet block headers
// (heights 24155880..24156029, all 5 algos), captured from digiexplorer.info and
// re-derivable with /home/ubuntu/dgb179-vectors/{fetch_de,verify_v4}.py. The
// nBits each block carries is the value the NETWORK accepted, so "our next-target
// == the fixture's bits" is the strongest possible oracle -- byte-parity with
// DigiByte-Core's live consensus.
//
// Two axes:
//   1. AllAlgosGolden -- the pure port (dgb::coin::multishield_v4_next_bits) run
//      for EVERY algo (dgb_block_algo of the target block) over the fixture
//      window, asserted == the block's nBits. 89 vectors (every block with a
//      full 61-header window below it), covering nAdjustments >0/=0/<0. This is
//      exactly what verify_v4.py checks (89/89 there).
//   2. ScryptServedGolden -- the SERVED path the daemonless work source uses:
//      feed the fixture through HeaderChain::validate_and_append (the live ingest
//      SSOT) and assert HeaderChain::next_scrypt_bits() == the next block's nBits
//      at every Scrypt boundary (22 vectors), AND that it is never the fabricated
//      diff-1 0x1d00ffff. Proves the fix end-to-end: real bits on the wire,
//      replacing the invalid-block fabrication.
//
// Plus the compact round-trip (target_to_compact . compact_to_target == id over
// all 150 canonical nBits) and the powLimit compact pin (0x1e0fffff).
//
// Header-only math: includes only header_chain.hpp (std-only; pulls
// dgb_multishield.hpp + dgb_arith256.hpp), so this links GTest-only like the
// digishield_walk_test / arith256 guards -- NO btclibs. HeaderSample is built
// directly from the fixture (no make_header_sample / scrypt call), pow_hash left
// 0 so the ingest PoW gate is inert while the MTP + continuity dispositions run
// exactly as in production.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <impl/dgb/coin/header_chain.hpp>     // c2pool::dgb::HeaderChain / HeaderSample
#include <impl/dgb/coin/dgb_multishield.hpp>  // multishield_v4_next_bits, pow_limit
#include <impl/dgb/coin/dgb_arith256.hpp>     // compact_to_target / target_to_compact
#include <impl/dgb/coin/dgb_block_algo.hpp>   // dgb_block_algo

using dgb::coin::compact_to_target;
using dgb::coin::target_to_compact;
using dgb::coin::dgb_block_algo;
using dgb::coin::multishield_v4_next_bits;
using dgb::coin::multishield_pow_limit;
using dgb::coin::MultiShieldV4Params;
using dgb::coin::MsHeader;
using dgb::coin::MULTISHIELD_POW_LIMIT_COMPACT;

namespace {

struct FixtureHeader {
    uint32_t height;
    uint32_t version;
    int64_t  time;
    uint32_t bits;
};

// 150 consecutive DigiByte mainnet headers (24155880..24156029). See file header.
const FixtureHeader kFixture[] = {
    {24155880, 536874498u, 1788581092, 0x1b061689u},
    {24155881, 536872450u, 1788581160, 0x1a020fbfu},
    {24155882, 536872450u, 1788581391, 0x1a01d9f9u},
    {24155883, 536872962u, 1788581158, 0x1a1db51cu},
    {24155884, 536874498u, 1788581164, 0x1b062685u},
    {24155885, 536870914u, 1788581167, 0x1a5f80dau},
    {24155886, 536870914u, 1788581173, 0x1a558e21u},
    {24155887, 536874498u, 1788581183, 0x1b05ebe6u},
    {24155888, 714605058u, 1788581187, 0x190a11d9u},
    {24155889, 536874498u, 1788581203, 0x1b05708cu},
    {24155890, 536870914u, 1788581209, 0x1a5501bbu},
    {24155891, 536872450u, 1788581213, 0x1a023db3u},
    {24155892, 536870914u, 1788581227, 0x1a4e7e25u},
    {24155893, 536870914u, 1788581228, 0x1a4582eau},
    {24155894, 536874498u, 1788581230, 0x1b059965u},
    {24155895, 536872962u, 1788581246, 0x1a284ab6u},
    {24155896, 537338370u, 1788581253, 0x190b89dbu},
    {24155897, 536874498u, 1788581277, 0x1b0545fdu},
    {24155898, 594264578u, 1788581284, 0x190a64fau},
    {24155899, 584040962u, 1788581296, 0x1908f4cfu},
    {24155900, 536874498u, 1788581304, 0x1b04cf7fu},
    {24155901, 536874498u, 1788581307, 0x1b04036cu},
    {24155902, 536872450u, 1788581315, 0x1a02c47du},
    {24155903, 536872450u, 1788581599, 0x1a025181u},
    {24155904, 536872450u, 1788581674, 0x1a01f289u},
    {24155905, 536870914u, 1788581360, 0x1a59661cu},
    {24155906, 536872962u, 1788581365, 0x1a31485au},
    {24155907, 740106754u, 1788581368, 0x1909af5fu},
    {24155908, 536870914u, 1788581372, 0x1a4f918au},
    {24155909, 537428482u, 1788581378, 0x19086450u},
    {24155910, 536872450u, 1788581584, 0x1a01f480u},
    {24155911, 536870914u, 1788581434, 0x1a46d1b1u},
    {24155912, 536874498u, 1788581453, 0x1b04de48u},
    {24155913, 536870914u, 1788581455, 0x1a3c458fu},
    {24155914, 536872450u, 1788581488, 0x1a01d27du},
    {24155915, 537108994u, 1788581467, 0x190872bfu},
    {24155916, 536872962u, 1788581468, 0x1a3a0a87u},
    {24155917, 536870914u, 1788581470, 0x1a38687bu},
    {24155918, 536872962u, 1788581506, 0x1a322751u},
    {24155919, 536870914u, 1788581513, 0x1a30acf7u},
    {24155920, 536870914u, 1788581520, 0x1a279c67u},
    {24155921, 536872962u, 1788581524, 0x1a2bc5e9u},
    {24155922, 536872962u, 1788581533, 0x1a22c5f3u},
    {24155923, 536872962u, 1788581541, 0x1a1b8140u},
    {24155924, 536872450u, 1788581871, 0x1a020f72u},
    {24155925, 545260034u, 1788581558, 0x190990dfu},
    {24155926, 536874498u, 1788581584, 0x1b0672dcu},
    {24155927, 536872962u, 1788581595, 0x1a18a60bu},
    {24155928, 536872450u, 1788581619, 0x1a01d54au},
    {24155929, 536872962u, 1788581599, 0x1a1428d6u},
    {24155930, 536874498u, 1788581610, 0x1b05b89bu},
    {24155931, 551477762u, 1788581616, 0x19092714u},
    {24155932, 536874498u, 1788581620, 0x1b04adddu},
    {24155933, 572326402u, 1788581674, 0x19077c59u},
    {24155934, 536874498u, 1788581689, 0x1b03d3b4u},
    {24155935, 536872450u, 1788582059, 0x1a01d2f9u},
    {24155936, 536872450u, 1788581727, 0x1a016f3cu},
    {24155937, 536874498u, 1788581727, 0x1b034153u},
    {24155938, 536874498u, 1788581746, 0x1b028f57u},
    {24155939, 600031746u, 1788581796, 0x1907298fu},
    {24155940, 758211074u, 1788581784, 0x1905a837u},
    {24155941, 579609090u, 1788581808, 0x1904850fu},
    {24155942, 536870914u, 1788581845, 0x1a47e953u},
    {24155943, 536872450u, 1788581993, 0x1a01744fu},
    {24155944, 536870914u, 1788581874, 0x1a3cb09eu},
    {24155945, 536870914u, 1788581879, 0x1a312e2au},
    {24155946, 536870914u, 1788581908, 0x1a27f731u},
    {24155947, 536872962u, 1788581931, 0x1a1fddc8u},
    {24155948, 536872450u, 1788582306, 0x1a0163edu},
    {24155949, 536872450u, 1788582080, 0x1a0125b3u},
    {24155950, 536874498u, 1788581974, 0x1b0341a2u},
    {24155951, 536872962u, 1788581992, 0x1a1dbdedu},
    {24155952, 536872962u, 1788582000, 0x1a18d036u},
    {24155953, 536904194u, 1788582030, 0x1905d837u},
    {24155954, 536872450u, 1788582251, 0x1a0121c8u},
    {24155955, 536874498u, 1788582039, 0x1b03332eu},
    {24155956, 536872962u, 1788582055, 0x1a177206u},
    {24155957, 597164546u, 1788582069, 0x19059328u},
    {24155958, 536874498u, 1788582089, 0x1b02ef51u},
    {24155959, 536872450u, 1788582349, 0x1a011cc2u},
    {24155960, 536872450u, 1788582258, 0x1a00ee8bu},
    {24155961, 721273346u, 1788582184, 0x190540d1u},
    {24155962, 536872962u, 1788582191, 0x1a17f5e8u},
    {24155963, 536872962u, 1788582239, 0x1a143c5eu},
    {24155964, 589005314u, 1788582252, 0x1904db5bu},
    {24155965, 536872450u, 1788582414, 0x1a00eedcu},
    {24155966, 536874498u, 1788582281, 0x1b034e41u},
    {24155967, 536870914u, 1788582302, 0x1a4bc0c8u},
    {24155968, 536870914u, 1788582315, 0x1a41b429u},
    {24155969, 536872450u, 1788582424, 0x1a00e8bcu},
    {24155970, 536872962u, 1788582337, 0x1a165325u},
    {24155971, 536874498u, 1788582345, 0x1b035f2du},
    {24155972, 536872450u, 1788582602, 0x1a00dce9u},
    {24155973, 536874498u, 1788582399, 0x1b0312ccu},
    {24155974, 536874498u, 1788582402, 0x1b02b27du},
    {24155975, 537002498u, 1788582430, 0x19064f31u},
    {24155976, 536872962u, 1788582440, 0x1a183559u},
    {24155977, 536872962u, 1788582455, 0x1a158c7bu},
    {24155978, 536874498u, 1788582463, 0x1b02b19au},
    {24155979, 536870914u, 1788582471, 0x1a56cb50u},
    {24155980, 536872450u, 1788582754, 0x1a01026fu},
    {24155981, 536872962u, 1788582505, 0x1a157030u},
    {24155982, 536870914u, 1788582509, 0x1a53228du},
    {24155983, 536870914u, 1788582525, 0x1a49b798u},
    {24155984, 536870914u, 1788582541, 0x1a411d3cu},
    {24155985, 536872962u, 1788582557, 0x1a15540au},
    {24155986, 636805634u, 1788582575, 0x19085861u},
    {24155987, 614851074u, 1788582578, 0x19077768u},
    {24155988, 536870914u, 1788582655, 0x1a41c833u},
    {24155989, 537354754u, 1788582683, 0x1906e4efu},
    {24155990, 536874498u, 1788582712, 0x1b03ae8eu},
    {24155991, 536872962u, 1788582722, 0x1a16e426u},
    {24155992, 536874498u, 1788582729, 0x1b0360bdu},
    {24155993, 536870914u, 1788582743, 0x1a438945u},
    {24155994, 536870914u, 1788582753, 0x1a3c0a19u},
    {24155995, 536874498u, 1788582757, 0x1b0343beu},
    {24155996, 536874498u, 1788582801, 0x1b02ee97u},
    {24155997, 536870914u, 1788582823, 0x1a3a8b5cu},
    {24155998, 536872450u, 1788582997, 0x1a01c13eu},
    {24155999, 536870914u, 1788582835, 0x1a360ee4u},
    {24156000, 673145346u, 1788582870, 0x19091582u},
    {24156001, 536872450u, 1788583052, 0x1a01aca4u},
    {24156002, 536870914u, 1788582964, 0x1a33faa0u},
    {24156003, 536872450u, 1788583005, 0x1a018940u},
    {24156004, 643981826u, 1788582970, 0x190900a3u},
    {24156005, 536874498u, 1788582974, 0x1b03938cu},
    {24156006, 537281026u, 1788582978, 0x19089198u},
    {24156007, 536872962u, 1788582980, 0x1a2572c5u},
    {24156008, 536872450u, 1788583276, 0x1a01a15eu},
    {24156009, 536870914u, 1788583021, 0x1a3b719cu},
    {24156010, 620233218u, 1788583022, 0x1908b627u},
    {24156011, 536870914u, 1788583024, 0x1a37e007u},
    {24156012, 536874498u, 1788583052, 0x1b041afdu},
    {24156013, 777273858u, 1788583054, 0x19087e9eu},
    {24156014, 536870914u, 1788583062, 0x1a351b2cu},
    {24156015, 536872450u, 1788583388, 0x1a01cf76u},
    {24156016, 536872450u, 1788583083, 0x1a0196bbu},
    {24156017, 536872450u, 1788583194, 0x1a0162a0u},
    {24156018, 536872962u, 1788583093, 0x1a303494u},
    {24156019, 537223682u, 1788583096, 0x1908fccdu},
    {24156020, 728236546u, 1788583110, 0x1907c117u},
    {24156021, 536874498u, 1788583118, 0x1b04e2d1u},
    {24156022, 549454338u, 1788583138, 0x1906fc44u},
    {24156023, 536872962u, 1788583170, 0x1a30a7c1u},
    {24156024, 536872962u, 1788583179, 0x1a29de36u},
    {24156025, 536870914u, 1788583186, 0x1a43a4e9u},
    {24156026, 536870914u, 1788583188, 0x1a39ab18u},
    {24156027, 536870914u, 1788583193, 0x1a3129e6u},
    {24156028, 536874498u, 1788583200, 0x1b055019u},
    {24156029, 536872962u, 1788583215, 0x1a29cfebu},
};
constexpr std::size_t kN = sizeof(kFixture) / sizeof(kFixture[0]);

// Number of ancestors below the target block the V4 walk needs (50-back
// pindexFirst + its 10-ancestor MedianTimePast). Deriving bits for fixture index
// i needs indices 0..i-1 present, i.e. depth i >= 61.
constexpr std::size_t kMinWindow = 61;

} // namespace

// 1. Compact round-trip: target_to_compact(compact_to_target(x)) == x for every
//    canonical mainnet nBits in the fixture. This is what makes storing `target`
//    and recovering `bits` at the end of the V4 walk byte-exact.
TEST(MultiShieldV4Kat, CompactRoundTripAll150) {
    for (std::size_t i = 0; i < kN; ++i) {
        const uint32_t bits = kFixture[i].bits;
        EXPECT_EQ(target_to_compact(compact_to_target(bits)), bits)
            << "round-trip failed at height " << kFixture[i].height
            << " bits=0x" << std::hex << bits;
    }
}

// 2. powLimit compact pin: 0x1e0fffff, the DigiByte mainnet minimum difficulty.
TEST(MultiShieldV4Kat, PowLimitCompact) {
    EXPECT_EQ(target_to_compact(multishield_pow_limit()), 0x1e0fffffu);
    EXPECT_EQ(MULTISHIELD_POW_LIMIT_COMPACT, 0x1e0fffffu);
}

// 3. All-algos golden: the pure MultiShield V4 port, run for the target block's
//    OWN algo over the fixture window, equals the block's accepted nBits.
//    89 derivable vectors, byte-exact -- DigiByte-Core parity.
TEST(MultiShieldV4Kat, AllAlgosGolden) {
    int checked = 0;
    for (std::size_t i = kMinWindow; i < kN; ++i) {
        // Nearest-first accessor over the ancestors [0, i): at(0) == tip == i-1.
        const std::size_t depth = i;
        const auto at = [depth](std::size_t k) -> MsHeader {
            const FixtureHeader& f = kFixture[depth - 1 - k];
            return MsHeader{ static_cast<int32_t>(f.version), f.bits, f.time };
        };
        const dgb::coin::DgbAlgo algo =
            dgb_block_algo(static_cast<int32_t>(kFixture[i].version));
        const std::optional<uint32_t> got =
            multishield_v4_next_bits(at, depth, MultiShieldV4Params{}, algo);
        ASSERT_TRUE(got.has_value())
            << "no bits at height " << kFixture[i].height << " (window " << depth << ")";
        EXPECT_EQ(*got, kFixture[i].bits)
            << "V4 mismatch at height " << kFixture[i].height
            << " algo=" << static_cast<int>(algo)
            << " got=0x" << std::hex << *got
            << " want=0x" << kFixture[i].bits;
        ++checked;
    }
    EXPECT_EQ(checked, 89) << "expected 89 derivable golden vectors";
}

// 4. Scrypt served path: feed the fixture through the live ingest SSOT
//    (HeaderChain::validate_and_append) and assert next_scrypt_bits() at every
//    Scrypt boundary equals the next block's nBits AND is never the fabricated
//    diff-1. Proves the daemonless work source now stamps a REAL, network-valid
//    target instead of 0x1d00ffff (#179).
TEST(MultiShieldV4Kat, ScryptServedGoldenNotFabricated) {
    c2pool::dgb::HeaderChain chain;   // default-ctor: retarget gate unconfigured
    int scrypt_checked = 0;
    int rejected = 0;

    for (std::size_t i = 0; i < kN; ++i) {
        const FixtureHeader& f = kFixture[i];

        // Before appending f, the chain holds [0, i): tip == i-1, so
        // next_scrypt_bits() derives the target for block i. Check it whenever
        // block i is Scrypt and the window is deep enough.
        if (i >= kMinWindow &&
            dgb_block_algo(static_cast<int32_t>(f.version)) == dgb::coin::DgbAlgo::SCRYPT) {
            const std::optional<uint32_t> served = chain.next_scrypt_bits();
            ASSERT_TRUE(served.has_value())
                << "served bits absent at Scrypt height " << f.height;
            EXPECT_EQ(*served, f.bits)
                << "served Scrypt bits mismatch at height " << f.height
                << " got=0x" << std::hex << *served << " want=0x" << f.bits;
            EXPECT_NE(*served, 0x1d00ffffu)
                << "served the FABRICATED diff-1 at height " << f.height
                << " -- the #179 regression is back";
            ++scrypt_checked;
        }

        c2pool::dgb::HeaderSample s;
        s.n_version  = static_cast<int32_t>(f.version);
        s.n_time     = f.time;
        s.target     = compact_to_target(f.bits);
        s.pow_hash   = 0;   // inert PoW gate (0 <= any target)
        s.n_bits     = f.bits;
        if (chain.validate_and_append(s) == c2pool::dgb::IngestResult::REJECTED)
            ++rejected;
    }

    EXPECT_EQ(rejected, 0) << "no fixture header should be rejected by ingest";
    EXPECT_EQ(scrypt_checked, 22) << "expected 22 Scrypt served-path vectors";
}

// 5. Short window -> truthful absence (never fabrication). Before 61 headers are
//    ingested next_scrypt_bits() must return nullopt so the caller holds work.
TEST(MultiShieldV4Kat, ShortWindowReturnsNulloptNotFabrication) {
    c2pool::dgb::HeaderChain chain;
    for (std::size_t i = 0; i < kMinWindow - 1 && i < kN; ++i) {
        // Under the min window the derive must abstain regardless of tip algo.
        EXPECT_FALSE(chain.next_scrypt_bits().has_value())
            << "derived bits with only " << i << " headers (< 61)";
        c2pool::dgb::HeaderSample s;
        const FixtureHeader& f = kFixture[i];
        s.n_version = static_cast<int32_t>(f.version);
        s.n_time    = f.time;
        s.target    = compact_to_target(f.bits);
        s.pow_hash  = 0;
        s.n_bits    = f.bits;
        chain.validate_and_append(s);
    }
}
