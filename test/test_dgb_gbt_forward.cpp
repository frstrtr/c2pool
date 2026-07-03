// test_dgb_gbt_forward — Stage 4b/4c daemon-GBT-forward SSOT KAT.
//
// Guards dgb::coin::select_work_template: the choke point where
// DGBWorkSource::get_current_work_template() chooses between the embedded
// Scrypt-only template and the authoritative external digibyted
// getblocktemplate result. Header-only (mirrors test_dgb_coinbase_value) — no
// dgb runtime link.

#include <gtest/gtest.h>

#include <optional>
#include <nlohmann/json.hpp>

#include <impl/dgb/coin/gbt_forward.hpp>

using nlohmann::json;

namespace {

// Deterministic stand-in subsidy schedule (5 DGB per block, 1e8 sat units) —
// only its RETURN matters here, not the real oracle decay curve.
core::SubsidyFunc make_subsidy(uint64_t per_block)
{
    return [per_block](uint32_t /*height*/) -> uint64_t { return per_block; };
}

json embedded_template()
{
    // Shape build_work_template emits on the embedded Scrypt-only path: no
    // bits, version pinned to the Scrypt lane, coinbasevalue from subsidy.
    return json{
        {"version", 0},
        {"curtime", 1751500000},
        {"mintime", 0},
        {"coinbasevalue", 500000000ULL},
        {"transactions", json::array()},
    };
}

json daemon_gbt()
{
    // Shape digibyted getblocktemplate returns: REAL bits + version +
    // previousblockhash the embedded walk holds back.
    return json{
        {"version", 0x20000002},
        {"previousblockhash", "00000000000000000abc123def4560000000000000000000000000000000000ff"},
        {"bits", "1a0abbcc"},
        {"curtime", 1751500123},
        {"mintime", 1751499000},
        {"coinbasevalue", 512345678ULL},
        {"height", 264},
        {"transactions", json::array({ json{{"data","deadbeef"},{"txid","aa"},{"hash","aa"},{"fee",1000}} })},
    };
}

} // namespace

// (1) No external RPC sink -> embedded template passes through byte-identical.
TEST(DgbGbtForward, UnboundReturnsEmbeddedVerbatim)
{
    auto sub = make_subsidy(500000000ULL);
    json out = dgb::coin::select_work_template(sub, 264, embedded_template(), std::nullopt);
    EXPECT_EQ(out, embedded_template());
    EXPECT_FALSE(out.contains("bits"));  // Scrypt-only walk holds bits back
}

// (2) Daemon GBT present -> forwarded authoritative, incl bits/version/prevhash.
TEST(DgbGbtForward, DaemonGbtForwardsAuthoritativeFields)
{
    auto sub = make_subsidy(500000000ULL);
    json out = dgb::coin::select_work_template(sub, 264, embedded_template(),
                                               std::optional<json>{daemon_gbt()});
    EXPECT_EQ(out.at("bits").get<std::string>(), "1a0abbcc");
    EXPECT_EQ(out.at("version").get<uint32_t>(), 0x20000002u);
    EXPECT_EQ(out.at("previousblockhash").get<std::string>(),
              "00000000000000000abc123def4560000000000000000000000000000000000ff");
    EXPECT_EQ(out.at("transactions").size(), 1u);
}

// (3) Present daemon coinbasevalue is authoritative and reconciled verbatim
//     through the #207 SSOT (NOT overwritten by the embedded subsidy).
TEST(DgbGbtForward, DaemonCoinbasevalueIsAuthoritative)
{
    auto sub = make_subsidy(500000000ULL);  // embedded would say 5.0 DGB
    json out = dgb::coin::select_work_template(sub, 264, embedded_template(),
                                               std::optional<json>{daemon_gbt()});
    EXPECT_EQ(out.at("coinbasevalue").get<uint64_t>(), 512345678ULL);  // daemon persists
}

// (4) Malformed/absent daemon coinbasevalue -> falls back to embedded subsidy
//     derivation (never fabricates from a bad daemon value).
TEST(DgbGbtForward, MalformedDaemonCoinbasevalueFallsBackToSubsidy)
{
    auto sub = make_subsidy(777000000ULL);
    json g = daemon_gbt();
    g.erase("coinbasevalue");
    json out = dgb::coin::select_work_template(sub, 264, embedded_template(),
                                               std::optional<json>{g});
    EXPECT_EQ(out.at("coinbasevalue").get<uint64_t>(), 777000000ULL);  // subsidy(264)+0
    EXPECT_EQ(out.at("bits").get<std::string>(), "1a0abbcc");          // still forwarded
}
