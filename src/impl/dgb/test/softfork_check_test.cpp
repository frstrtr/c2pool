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
// Header-only + nlohmann + gtest -- no boost::beast/jsonrpccxx transport, so it
// builds standalone without entering the dgb OBJECT lib (same gate-safe shape
// as rpc_request_test.cpp).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/dgb/coin/softfork_check.hpp>

#include <set>
#include <string>

using dgb::coin::collect_softfork_names;
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
