// ---------------------------------------------------------------------------
// dgb M3 softfork-detection regression guard.
//
// Pins collect_softfork_names() (softfork_check.hpp), the parser NodeRPC uses
// to decide whether "segwit" (and friends) are active on the external
// digibyted BEFORE c2pool-dgb trusts the Scrypt getblocktemplate path. The
// parser must tolerate all three getblockchaininfo["softforks"]/["bip9_softforks"]
// encodings shipped by different DigiByte Core versions:
//
//   1. array of objects:  [{"id":"segwit",...}, ...]   (modern digibyted)
//   2. array of strings:  ["segwit","taproot", ...]    (compact form)
//   3. object with keys:  {"segwit":{...}, ...}         (BIP9 style)
//
// It also pins collect_deployment_names(), which reads the getdeploymentinfo
// RPC ("deployments" object) used as the readiness-gate source on DigiByte
// Core 8.26.2 (Bitcoin Core 26 base), where getblockchaininfo no longer
// carries the "softforks" field.
//
// Header-only + nlohmann + gtest -- no boost::beast/jsonrpccxx transport, so it
// builds standalone without entering the dgb OBJECT lib (same gate-safe shape
// as rpc_request_test.cpp).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/dgb/coin/softfork_check.hpp>

#include <set>
#include <string>

using dgb::coin::collect_softfork_names;
using dgb::coin::collect_deployment_names;
using json = nlohmann::json;

// --- Format 1: array of objects (modern digibyted) --------------------------

TEST(DgbSoftforkCheck, ArrayOfObjectsCollectsIds)
{
    auto v = json::parse(R"([{"id":"segwit","active":true},{"id":"taproot"}])");
    std::set<std::string> out;
    collect_softfork_names(v, out);
    EXPECT_EQ(out, (std::set<std::string>{"segwit", "taproot"}));
}

TEST(DgbSoftforkCheck, ArrayObjectMissingOrNonStringIdSkipped)
{
    // An object without a string "id" must be ignored, not crash the parse.
    auto v = json::parse(R"([{"id":"segwit"},{"name":"noid"},{"id":42}])");
    std::set<std::string> out;
    collect_softfork_names(v, out);
    EXPECT_EQ(out, (std::set<std::string>{"segwit"}));
}

// --- Format 2: array of strings (compact form) ------------------------------

TEST(DgbSoftforkCheck, ArrayOfStringsCollectsValues)
{
    auto v = json::parse(R"(["segwit","taproot"])");
    std::set<std::string> out;
    collect_softfork_names(v, out);
    EXPECT_EQ(out, (std::set<std::string>{"segwit", "taproot"}));
}

// --- Format 3: object keyed by softfork name (BIP9 style) -------------------

TEST(DgbSoftforkCheck, ObjectCollectsKeys)
{
    auto v = json::parse(R"({"segwit":{"status":"active"},"taproot":{"status":"defined"}})");
    std::set<std::string> out;
    collect_softfork_names(v, out);
    EXPECT_EQ(out, (std::set<std::string>{"segwit", "taproot"}));
}

// --- The contract that actually matters: segwit is detectable in every form -

TEST(DgbSoftforkCheck, SegwitDetectedAcrossAllThreeEncodings)
{
    for (const auto& src : {R"([{"id":"segwit"}])", R"(["segwit"])", R"({"segwit":{}})"})
    {
        std::set<std::string> out;
        collect_softfork_names(json::parse(src), out);
        EXPECT_TRUE(out.count("segwit")) << "segwit not found in: " << src;
    }
}

// --- Accumulation + robustness ---------------------------------------------

TEST(DgbSoftforkCheck, AccumulatesIntoExistingSet)
{
    // Caller merges the "softforks" and "bip9_softforks" fields into one set;
    // collect_softfork_names must append, never clear.
    std::set<std::string> out{"preexisting"};
    collect_softfork_names(json::parse(R"(["segwit"])"), out);
    EXPECT_EQ(out, (std::set<std::string>{"preexisting", "segwit"}));
}

TEST(DgbSoftforkCheck, EmptyContainersYieldNothing)
{
    std::set<std::string> out;
    collect_softfork_names(json::parse("[]"), out);
    collect_softfork_names(json::parse("{}"), out);
    EXPECT_TRUE(out.empty());
}

TEST(DgbSoftforkCheck, ScalarValueIsNoOp)
{
    // A missing field deserialized as null/number/string must be a safe no-op
    // (the field may be absent on very old daemons).
    std::set<std::string> out;
    collect_softfork_names(json(nullptr), out);
    collect_softfork_names(json(7), out);
    collect_softfork_names(json("segwit"), out);  // bare scalar, not a container
    EXPECT_TRUE(out.empty());
}

// --- getdeploymentinfo path (DigiByte Core 8.26.2 / Bitcoin Core 26) --------
//
// On Core-26 daemons getblockchaininfo drops "softforks"/"bip9_softforks";
// the readiness gate must instead read getdeploymentinfo["deployments"], an
// object keyed by deployment name. collect_deployment_names() bridges that
// result into the same name set the gate already consumes.

TEST(DgbDeploymentInfo, Core26DeploymentsObjectCollectsAllNames)
{
    // Shape mirrors DigiByte 8.26.2 getdeploymentinfo: each deployment is an
    // object (buried or bip9), keyed by name. The DGB-specific algo forks
    // (reservealgo, odo) and nversionbips appear here even before activation.
    auto v = json::parse(R"({
        "hash": "00ff",
        "height": 123,
        "deployments": {
            "csv": {"type":"buried","active":true,"height":1},
            "segwit": {"type":"buried","active":true,"height":1},
            "taproot": {"type":"bip9","bip9":{"status":"defined","bit":2},"active":false},
            "nversionbips": {"type":"bip9","bip9":{"status":"started","bit":1},"active":false},
            "reservealgo": {"type":"bip9","bip9":{"status":"defined","bit":3},"active":false},
            "odo": {"type":"bip9","bip9":{"status":"defined","bit":4},"active":false}
        }
    })");
    std::set<std::string> out;
    collect_deployment_names(v, out);
    EXPECT_EQ(out, (std::set<std::string>{
        "csv", "segwit", "taproot", "nversionbips", "reservealgo", "odo"}));
}

TEST(DgbDeploymentInfo, RegressionGateForksDetectableFromDeployments)
{
    // The exact set the readiness gate was reporting "missing" on testnet4 when
    // it could only read getblockchaininfo/GBT-rules (csv/segwit). All four
    // required forks must be recoverable from the getdeploymentinfo result.
    auto v = json::parse(R"({"deployments":{
        "csv":{"active":true},"segwit":{"active":true},
        "taproot":{"active":false},"nversionbips":{"active":false},
        "reservealgo":{"active":false},"odo":{"active":false}}})");
    std::set<std::string> out;
    collect_deployment_names(v, out);
    for (const char* req : {"taproot", "nversionbips", "reservealgo", "odo"})
        EXPECT_TRUE(out.count(req)) << "required fork not detected: " << req;
}

TEST(DgbDeploymentInfo, MissingDeploymentsKeyIsNoOp)
{
    // A result lacking "deployments" (older daemon, or a non-conforming
    // response) must be a safe no-op so the caller can fall through to GBT.
    std::set<std::string> out{"segwit"};
    collect_deployment_names(json::parse(R"({"hash":"00","height":1})"), out);
    EXPECT_EQ(out, (std::set<std::string>{"segwit"}));
}

TEST(DgbDeploymentInfo, NonObjectResultIsNoOp)
{
    // null / scalar / array results (e.g. a swallowed RPC error) are no-ops.
    std::set<std::string> out;
    collect_deployment_names(json(nullptr), out);
    collect_deployment_names(json(7), out);
    collect_deployment_names(json::parse("[]"), out);
    EXPECT_TRUE(out.empty());
}

TEST(DgbDeploymentInfo, AccumulatesIntoExistingSet)
{
    // Like collect_softfork_names, must append (never clear) so the gate can
    // merge multiple sources.
    std::set<std::string> out{"preexisting"};
    collect_deployment_names(json::parse(R"({"deployments":{"segwit":{}}})"), out);
    EXPECT_EQ(out, (std::set<std::string>{"preexisting", "segwit"}));
}
