// SPDX-License-Identifier: AGPL-3.0-or-later
// dgb_template_builder_test — guards the dgb::coin::build_work_template SSOT
// (Stage 4c extraction). The work-template assembly was lifted out of
// DGBWorkSource::get_current_work_template() into coin/template_builder.hpp so
// the stratum work source and the embedded path emit ONE template object and
// cannot diverge. These tests pin the truthfulness invariants the assembly
// must hold: the Scrypt lane is pinned, the consensus coinbasevalue passes
// through verbatim, mintime tracks median-time-past (0 on an empty chain),
// transactions[] stays empty, bits is never emitted, and previousblockhash is
// a truthful conditional (present only when a real tip hash is supplied).
//
// Pure-shaping function -> guard-weight test (no chain/mempool fixture).

#include <cstdint>
#include <limits>
#include <optional>
#include <string>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <impl/dgb/coin/template_builder.hpp>
#include <impl/dgb/coin/dgb_block_algo.hpp>

using dgb::coin::WorkTemplateInputs;
using dgb::coin::build_work_template;

namespace {

// A fully-populated set of inputs mirroring a mid-chain template build.
WorkTemplateInputs make_inputs()
{
    WorkTemplateInputs in;
    in.next_height      = 17722;
    in.coinbasevalue    = 625000000ULL;   // arbitrary post-resolve reward
    in.median_time_past = 1750000000;      // a concrete MTP
    in.curtime          = 1750000075;      // MTP + ~one block period
    in.previousblockhash =
        "00000000000000000a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778";
    return in;
}

} // namespace

// version MUST be BIP9 base OR'd with the all-zero Scrypt algo nibble. A DGB
// template that is not Scrypt-pinned would be a block this V36 binary never mines.
TEST(DgbTemplateBuilder, ScryptLanePinnedVersion)
{
    auto t = build_work_template(make_inputs());
    static constexpr uint32_t BIP9_BASE = 0x20000000u;
    const uint32_t expect =
        BIP9_BASE | static_cast<uint32_t>(dgb::coin::DGB_BLOCK_VERSION_SCRYPT);
    EXPECT_EQ(t.at("version").get<uint32_t>(), expect);
    EXPECT_EQ(expect, 0x20000000u);  // Scrypt == all-zero codepoint
    // The version nibble must classify back to Scrypt through the SSOT.
    EXPECT_TRUE(dgb::coin::is_scrypt_header(t.at("version").get<int32_t>()));
}

// The consensus-bearing reward is resolved upstream (#207 SSOT) and must pass
// through the builder byte-for-byte — the builder never recomputes or scales it.
TEST(DgbTemplateBuilder, CoinbaseValuePassesThroughVerbatim)
{
    auto in = make_inputs();
    in.coinbasevalue = 0xCAFEBABEDEADBEEFULL;
    auto t = build_work_template(in);
    EXPECT_EQ(t.at("coinbasevalue").get<uint64_t>(), 0xCAFEBABEDEADBEEFULL);
    EXPECT_EQ(t.at("height").get<uint32_t>(), in.next_height);
}

// mintime = median_time_past + 1 (DGB Core's nTime > MTP lower bound).
TEST(DgbTemplateBuilder, MintimeIsMtpPlusOne)
{
    auto in = make_inputs();
    in.median_time_past = 1750000000;
    auto t = build_work_template(in);
    EXPECT_EQ(t.at("mintime").get<int64_t>(), 1750000001);
    EXPECT_EQ(t.at("curtime").get<int64_t>(), in.curtime);
}

// Empty chain reports MTP == INT64_MIN (unconstrained) -> mintime emits 0,
// never INT64_MIN+1 (which would underflow-adjacent and be meaningless to GBT).
TEST(DgbTemplateBuilder, EmptyChainMintimeIsZero)
{
    auto in = make_inputs();
    in.median_time_past = std::numeric_limits<int64_t>::min();
    auto t = build_work_template(in);
    EXPECT_EQ(t.at("mintime").get<int64_t>(), 0);
}

// transactions[] is an empty array BY DEFAULT (no tx source wired into the
// inputs); bits is NEVER emitted (MultiShield V4 next-target is V37 — a
// Scrypt-only walk would be a known-wrong difficulty).
TEST(DgbTemplateBuilder, EmptyTransactionsAndNoBits)
{
    auto t = build_work_template(make_inputs());
    ASSERT_TRUE(t.at("transactions").is_array());
    EXPECT_TRUE(t.at("transactions").empty());
    EXPECT_FALSE(t.contains("bits"));
}

// previousblockhash is a truthful conditional: emitted verbatim when a real
// tip hash is supplied, omitted entirely when absent (never a fabricated id).
TEST(DgbTemplateBuilder, PreviousblockhashConditionalEmit)
{
    auto with = build_work_template(make_inputs());
    ASSERT_TRUE(with.contains("previousblockhash"));
    EXPECT_EQ(with.at("previousblockhash").get<std::string>(),
              make_inputs().previousblockhash.value());

    auto in = make_inputs();
    in.previousblockhash = std::nullopt;
    auto without = build_work_template(in);
    EXPECT_FALSE(without.contains("previousblockhash"));
}

// transactions[] is a caller-supplied pass-through: a shaped array round-trips
// into the template VERBATIM (the seam a wired mempool source emits through),
// while an unset input stays an empty array (truthful absence by default). This
// is the same conditional-shape contract previousblockhash holds.
TEST(DgbTemplateBuilder, TransactionsPassThroughVerbatim)
{
    auto in = make_inputs();
    nlohmann::json tx = nlohmann::json::object();
    tx["data"] = "0100000001abcd";
    tx["txid"] = std::string(64, '1');
    tx["hash"] = std::string(64, '1');
    tx["fee"]  = 4200;
    in.transactions = nlohmann::json::array();
    in.transactions.push_back(tx);

    auto t = build_work_template(in);
    ASSERT_TRUE(t.at("transactions").is_array());
    ASSERT_EQ(t.at("transactions").size(), 1u);
    // byte-identical pass-through: the builder shapes nothing of its own.
    EXPECT_EQ(t.at("transactions").dump(), in.transactions.dump());
    EXPECT_EQ(t.at("transactions")[0].at("fee").get<int64_t>(), 4200);

    // Unset -> empty array (default): never absent, never fabricated.
    auto def = build_work_template(make_inputs());
    ASSERT_TRUE(def.at("transactions").is_array());
    EXPECT_TRUE(def.at("transactions").empty());
}

// Divergence guard: identical inputs -> byte-identical template. This is the
// whole point of the SSOT — the work source and embedded path cannot diverge.
TEST(DgbTemplateBuilder, DeterministicForIdenticalInputs)
{
    EXPECT_EQ(build_work_template(make_inputs()).dump(),
              build_work_template(make_inputs()).dump());
}