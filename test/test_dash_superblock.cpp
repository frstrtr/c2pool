// SPDX-License-Identifier: AGPL-3.0-or-later
/// E-SUPERBLOCK — daemonless superblock payee sourcing KATs.
///
/// Pins the reused dashcore superblock logic (governance-classes.cpp
/// CSuperblock::ParsePaymentSchedule + ParsePaymentAmount +
/// CSuperblockManager::GetSuperblockPayments + CalcSuperblockBudget,
/// governance/common.cpp Governance::Object::GetHash, governance/vote.h vote
/// digests) against FROM-WIRE testnet vectors captured from dashd
/// @192.168.86.52 (RPC 19998):
///
///   validateaddress yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A
///     -> scriptPubKey 76a914c69a0bda7daaae481be8def95e5f347a1d00a4b488ac
///   validateaddress 8xXa3NUojYA423boXJFnBx7CfjySQL7BRX          (P2SH, ver 19)
///     -> scriptPubKey a914c69a0bda7daaae481be8def95e5f347a1d00a4b487
///   validateaddress 7kWm63awbzmRZkBYT3FpjaHqnECcBZXEwT (mainnet P2SH, ver 16)
///     -> INVALID on testnet ("Invalid prefix") — chain-strictness vector
///   block 1519800 coinbase vout[0] ycn2gNExGVmcwJALr4PciWqWuN1DEsUBEN
///     -> scriptPubKey 76a914b489115851ca07a26a5ad8bac3cec3c7dbebd83188ac
///   getsuperblockbudget 1519824  -> 14.28625704 DASH == 1428625704 duffs (cycle 24)
///   getgovernanceinfo -> superblockcycle 24, fundingthreshold 17,
///                        governanceminquorum 1
///   gobject list all -> two governance objects pinning govobject_hash
///   gobject getcurrentvotes -> two votes pinning govvote_identity_hash
///
/// Tests:
///   1. ParsePaymentSchedule: a trigger's plaintext JSON -> the exact
///      (scriptPubKey, amount) vector dashd would place in the coinbase,
///      incl. P2SH payees (mainnet '7…' treasury-class + testnet '8…') and
///      CHAIN-STRICT wrong-chain rejection.
///   2. core::address_to_script DASH-P2SH regression (R1 shared-core fix) +
///      cross-coin non-collision (LTC/DOGE/BTC/DASH byte-exact).
///   3. govobject_hash / govvote_identity_hash byte-exact vs from-wire dashd
///      data (R2); govvote_signature_hash structural pin (R3 digest).
///   4. superblock_budget == dashd getsuperblockbudget.
///   5. GetBestSuperblock fail-closed ladder: weight-seam unset, sub-threshold
///      tally, unknown threshold, over-budget — all refuse; EvoNode 4x weight
///      + membership-at-tally + max(minQuorum, weighted/10) threshold (R4).
///   6. ParsePaymentAmount grammar (dashcore-exact) + malformed triggers.
///   7. build_embedded_workdata emits the superblock outputs + augments the
///      coinbase value at a funded superblock height (template wiring).
///   8. R5 completeness gate: provider + flag alone can NEVER open the serve
///      path; the sync-complete predicate must be present AND true.
///   9. R6 superblock desync cross-check: mismatched coinbase at a superblock
///      height clears + latches; no false-fire off superblock heights.

#include <gtest/gtest.h>

#include <impl/dash/coin/utxo_adapter.hpp>          // dash_txid (subsidy.hpp template dep)
#include <impl/dash/coin/governance_object.hpp>
#include <impl/dash/coin/governance_store.hpp>
#include <impl/dash/coin/superblock.hpp>
#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/coin_state_maintainer.hpp>
#include <impl/dash/coin/block_producer.hpp>        // compute_merkle_root (block binding)

#include <core/uint256.hpp>
#include <core/address_utils.hpp>                   // core::address_to_script (R1 KAT)

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace dash::coin;

namespace {

// Hex-encode a plaintext string (to build RPC-style DataHex).
std::string to_hex(const std::string& s) {
    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(s.size() * 2);
    for (unsigned char c : s) { out.push_back(H[c >> 4]); out.push_back(H[c & 0xf]); }
    return out;
}

// RPC-displayed hash hex (big-endian display) -> internal uint256 bytes.
uint256 uint256_from_rpc_hex(const std::string& hex) {
    uint256 h;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    for (size_t i = 0; i < 32 && i * 2 + 1 < hex.size(); ++i) {
        int hi = nib(hex[i * 2]), lo = nib(hex[i * 2 + 1]);
        h.data()[31 - i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return h;
}

std::vector<uint8_t> plain_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// Real from-wire scripts (see file header).
const std::vector<uint8_t> kScriptYeRZ = {
    0x76,0xa9,0x14,0xc6,0x9a,0x0b,0xda,0x7d,0xaa,0xae,0x48,0x1b,0xe8,
    0xde,0xf9,0x5e,0x5f,0x34,0x7a,0x1d,0x00,0xa4,0xb4,0x88,0xac};
const std::vector<uint8_t> kScriptYcn2 = {
    0x76,0xa9,0x14,0xb4,0x89,0x11,0x58,0x51,0xca,0x07,0xa2,0x6a,0x5a,
    0xd8,0xba,0xc3,0xce,0xc3,0xc7,0xdb,0xeb,0xd8,0x31,0x88,0xac};
// P2SH script over the same hash160 as yeRZ… — dashd-confirmed byte-exact:
// validateaddress 8xXa3NUojYA423boXJFnBx7CfjySQL7BRX (testnet, ver 19).
const std::vector<uint8_t> kScriptP2Sh = {
    0xa9,0x14,0xc6,0x9a,0x0b,0xda,0x7d,0xaa,0xae,0x48,0x1b,0xe8,
    0xde,0xf9,0x5e,0x5f,0x34,0x7a,0x1d,0x00,0xa4,0xb4,0x87};

// Base58check forms of hash160 c69a0bda7daaae481be8def95e5f347a1d00a4b4 under
// the version bytes of every supported coin family (checksums verified):
const char* kDashP2ShMain   = "7kWm63awbzmRZkBYT3FpjaHqnECcBZXEwT";  // ver 0x10
const char* kDashP2ShTest   = "8xXa3NUojYA423boXJFnBx7CfjySQL7BRX";  // ver 0x13
const char* kDashP2PkhMain  = "XtnxAZUECpZzdkYjvDEwq6d3YVfCszttB2";  // ver 0x4c
const char* kLtcP2Sh        = "MS1GZjijk8XDNUvVHJafDqYbBNxgRVUr9z";  // ver 0x32
const char* kLtcP2Pkh       = "LdL4bX8AKmbTjceKETv2Fb11vNSnzPBnaJ";  // ver 0x30
const char* kDogeP2Sh       = "AAYNzhNfs5YgUM24bZFjeKvZZFkGU4X5gJ";  // ver 0x16
const char* kBtcP2Sh        = "3Ko8FrJmo1fnZyebBRbKQCJBrgNELkTuaS";  // ver 0x05

// A syntactically-valid proposal hash (64 hex chars) for trigger JSON.
const char* kPropHash =
    "38e7621be9ca265288095a324dc185b6ba739fe3846858e3133f775c12a91306";

uint256 hash_of(uint64_t n) {
    uint256 h;
    h.data()[0] = static_cast<unsigned char>(n & 0xff);
    h.data()[1] = static_cast<unsigned char>((n >> 8) & 0xff);
    return h;
}

// Weight fn granting every outpoint key regular (1x) weight — the KAT stand-in
// for a wired membership seam (production default is UNSET => weight 0).
int weight_all_regular(const std::string&) { return DASH_VOTE_WEIGHT_REGULAR; }

std::string trigger_json(int height, const std::string& addrs,
                         const std::string& amts, const std::string& props) {
    return std::string("{\"event_block_height\":") + std::to_string(height) +
           ",\"payment_addresses\":\"" + addrs + "\",\"payment_amounts\":\"" +
           amts + "\",\"proposal_hashes\":\"" + props + "\",\"type\":2}";
}

} // namespace

// ── 1. ParsePaymentSchedule (single payee, from-wire script) ────────────────
TEST(DashSuperblock, ParseSinglePayeeMatchesWireScript) {
    const std::string json = trigger_json(
        1519824, "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", "5.00000000", kPropHash);
    auto trig = parse_superblock_trigger(json, hash_of(1), /*testnet=*/true);
    ASSERT_TRUE(trig.has_value());
    EXPECT_EQ(trig->event_block_height, 1519824);
    ASSERT_EQ(trig->payments.size(), 1u);
    EXPECT_EQ(trig->payments[0].script, kScriptYeRZ);        // byte-exact vs dashd
    EXPECT_EQ(trig->payments[0].amount, 500'000'000LL);      // 5 DASH
}

// ── 1b. Multi-payee ordered schedule ────────────────────────────────────────
TEST(DashSuperblock, ParseMultiPayeeOrdered) {
    const std::string json = trigger_json(
        1519824,
        "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A|ycn2gNExGVmcwJALr4PciWqWuN1DEsUBEN",
        "1.11626384|0.59531072",
        std::string(kPropHash) + "|" + kPropHash);
    auto trig = parse_superblock_trigger(json, hash_of(2), /*testnet=*/true);
    ASSERT_TRUE(trig.has_value());
    ASSERT_EQ(trig->payments.size(), 2u);
    EXPECT_EQ(trig->payments[0].script, kScriptYeRZ);
    EXPECT_EQ(trig->payments[0].amount, 111'626'384LL);
    EXPECT_EQ(trig->payments[1].script, kScriptYcn2);
    EXPECT_EQ(trig->payments[1].amount, 59'531'072LL);
    EXPECT_EQ(trig->total_amount(), 171'157'456LL);
}

// ── 1c. P2SH payees (R1) — the mainnet treasury-multisig class ──────────────
TEST(DashSuperblock, ParseP2ShPayeeByteExact) {
    // Testnet '8…' P2SH — script dashd-confirmed via validateaddress.
    {
        const std::string json =
            trigger_json(1519824, kDashP2ShTest, "5.0", kPropHash);
        auto trig = parse_superblock_trigger(json, hash_of(3), /*testnet=*/true);
        ASSERT_TRUE(trig.has_value());
        ASSERT_EQ(trig->payments.size(), 1u);
        EXPECT_EQ(trig->payments[0].script, kScriptP2Sh);    // a914…87, NOT 76a9…88ac
    }
    // Mainnet '7…' P2SH (same hash160) under the mainnet chain.
    {
        const std::string json =
            trigger_json(2128896, kDashP2ShMain, "5.0", kPropHash);
        auto trig = parse_superblock_trigger(json, hash_of(4), /*testnet=*/false);
        ASSERT_TRUE(trig.has_value());
        ASSERT_EQ(trig->payments.size(), 1u);
        EXPECT_EQ(trig->payments[0].script, kScriptP2Sh);
    }
    // Mainnet 'X…' P2PKH under the mainnet chain -> P2PKH script.
    {
        const std::string json =
            trigger_json(2128896, kDashP2PkhMain, "5.0", kPropHash);
        auto trig = parse_superblock_trigger(json, hash_of(5), /*testnet=*/false);
        ASSERT_TRUE(trig.has_value());
        EXPECT_EQ(trig->payments[0].script, kScriptYeRZ);    // same h160 => same P2PKH
    }
}

// ── 1d. CHAIN-STRICT rejection (dashd DecodeDestination parity) ─────────────
TEST(DashSuperblock, ChainStrictRejectsWrongChainAddresses) {
    // Mainnet '7…' on testnet: dashd-confirmed "Invalid prefix" => trigger fails.
    EXPECT_FALSE(parse_superblock_trigger(
        trigger_json(1519824, kDashP2ShMain, "5.0", kPropHash),
        hash_of(6), /*testnet=*/true).has_value());
    // Testnet 'y…' P2PKH on mainnet: reject.
    EXPECT_FALSE(parse_superblock_trigger(
        trigger_json(2128896, "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", "5.0", kPropHash),
        hash_of(7), /*testnet=*/false).has_value());
    // Testnet '8…' P2SH on mainnet: reject.
    EXPECT_FALSE(parse_superblock_trigger(
        trigger_json(2128896, kDashP2ShTest, "5.0", kPropHash),
        hash_of(8), /*testnet=*/false).has_value());
    // Another coin's base58 (LTC 'M…' P2SH) on either chain: reject.
    EXPECT_FALSE(parse_superblock_trigger(
        trigger_json(2128896, kLtcP2Sh, "5.0", kPropHash),
        hash_of(9), /*testnet=*/false).has_value());
    // bech32 (no DASH concept): reject.
    EXPECT_FALSE(parse_superblock_trigger(
        trigger_json(2128896, "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs2907q", "5.0",
                     kPropHash),
        hash_of(10), /*testnet=*/false).has_value());
}

// ── 2. R1 shared-core regression: core::address_to_script DASH P2SH ─────────
// Before the fix, DASH P2SH versions 0x10/0x13 fell through the core P2SH
// whitelist to "p2pkh" and produced 76a914<scripthash>88ac — a scriptPubKey
// dashd rejects at a superblock height (bad superblock payee => lost block).
TEST(DashSuperblock, CoreAddressToScriptHandlesDashP2Sh) {
    auto expect_script = [](const char* addr, const std::vector<uint8_t>& want) {
        auto got = ::core::address_to_script(addr);
        ASSERT_EQ(got.size(), want.size()) << addr;
        EXPECT_TRUE(std::equal(want.begin(), want.end(), got.begin())) << addr;
    };
    const std::vector<uint8_t> p2pkh = kScriptYeRZ;   // 76a914<h160>88ac
    const std::vector<uint8_t> p2sh  = kScriptP2Sh;   // a914<h160>87
    // DASH P2SH — the fix under test (mainnet 0x10 + testnet 0x13).
    expect_script(kDashP2ShMain, p2sh);
    expect_script(kDashP2ShTest, p2sh);
    // Cross-coin non-collision: every other supported coin's version byte
    // must keep decoding EXACTLY as before (same hash160 pinned throughout).
    expect_script(kDashP2PkhMain, p2pkh);  // DASH mainnet P2PKH 0x4c
    expect_script(kLtcP2Sh,  p2sh);        // LTC  mainnet P2SH  0x32
    expect_script(kLtcP2Pkh, p2pkh);       // LTC  mainnet P2PKH 0x30
    expect_script(kDogeP2Sh, p2sh);        // DOGE mainnet P2SH  0x16
    expect_script(kBtcP2Sh,  p2sh);        // BTC  mainnet P2SH  0x05
    expect_script("yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", p2pkh); // DASH testnet P2PKH 0x8c
}

// ── 3. govobject_hash — dashcore Governance::Object::GetHash (R2) ───────────
// Byte-exact against two FROM-WIRE testnet governance objects (`gobject list
// all`, dashd @192.168.86.52). Proposals carry hashParent=0, revision=1,
// time=CreationTime, a default masternodeOutpoint (null txid, index
// 0xffffffff) and an empty vchSig — every preimage component except vchData
// content is exercised, including the legacy dummy bytes and the
// HexStr(vchData) string layer.
TEST(DashSuperblock, GovObjectHashMatchesDashd) {
    const uint256 null_txid;   // default outpoint hash
    // Object 1: 4fe428f7… time 1784231522. vchData = the RPC DataString bytes
    // (the wire's plaintext; RPC DataHex is hex OF these bytes).
    {
        const std::string plain_json =
            "{\"name\":\"infraclaw-delete-test-20260716\","
            "\"url\":\"https://www.dash.org\","
            "\"payment_address\":\"yayNmZ5cFj14wPdWeG4DWu7zrnsVuF3XJC\","
            "\"payment_amount\":1,\"start_epoch\":1784231522,"
            "\"end_epoch\":1784836322,\"type\":1}";
        auto h = govobject_hash(uint256(), 1, 1784231522, plain_bytes(plain_json),
                                null_txid, 0xffffffffu, {});
        EXPECT_EQ(h.GetHex(),
            "4fe428f7b538ce0b3c08caf187894afcd7c867877495d0b28872c9f9e7e4140f");
    }
    // Object 2: c6f5059c… time 1748276768.
    {
        const std::string plain_json =
            "{\"end_epoch\":1800847498,\"name\":\"testing\","
            "\"payment_address\":\"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A\","
            "\"payment_amount\":20,\"start_epoch\":1749337898,\"type\":1,"
            "\"url\":\"https://secondarytesting.com\"}";
        auto h = govobject_hash(uint256(), 1, 1748276768, plain_bytes(plain_json),
                                null_txid, 0xffffffffu, {});
        EXPECT_EQ(h.GetHex(),
            "c6f5059ca0055fb327a6a0b15b9dd80c64b8c0956c1621061b294f8b93edab7f");
    }
}

// ── 3b. govvote_identity_hash — dashcore CGovernanceVote::GetHash ───────────
// Byte-exact against two FROM-WIRE testnet votes (`gobject getcurrentvotes
// c6f5059c…`): the RPC map key IS the vote identity hash.
TEST(DashSuperblock, GovVoteIdentityHashMatchesDashd) {
    const uint256 parent = uint256_from_rpc_hex(
        "c6f5059ca0055fb327a6a0b15b9dd80c64b8c0956c1621061b294f8b93edab7f");
    {
        const uint256 outpoint_txid = uint256_from_rpc_hex(
            "3efc16d756edba48884ae59974ea4496244ed6433fef111adf4b7496e23d6673");
        auto h = govvote_identity_hash(outpoint_txid, 0, parent,
                                       VOTE_OUTCOME_YES, VOTE_SIGNAL_FUNDING,
                                       1760356129);
        EXPECT_EQ(h.GetHex(),
            "10937cb513fbe8317b739ae00081b506cb41b580d6f2313057add15efce329df");
    }
    {
        const uint256 outpoint_txid = uint256_from_rpc_hex(
            "4ee3ff5074723d995f4cb957a954587c6c637a42655ada8f4054037b28d1e7a8");
        auto h = govvote_identity_hash(outpoint_txid, 18, parent,
                                       VOTE_OUTCOME_YES, VOTE_SIGNAL_FUNDING,
                                       1748357340);
        EXPECT_EQ(h.GetHex(),
            "6b8c21da906ecd08926ccfbd761a5a44e652ed2d08e1423a49e03fd944e0a62b");
    }
}

// ── 3c. govvote_signature_hash — structural pin (R3 digest) ─────────────────
// The BLS signing digest = the vote serialization minus vchSig (outcome BEFORE
// signal, NO legacy dummies). Every field encoding is already proven by the
// identity-hash KAT above (same encoders); this pins the field ORDER so a
// silent swap breaks the build. End-to-end BLS verification against a
// from-wire vote + operator-key pair is the gated follow-up (the verifier
// seam stays UNSET until then).
TEST(DashSuperblock, GovVoteSignatureHashPinned) {
    const uint256 parent = uint256_from_rpc_hex(
        "c6f5059ca0055fb327a6a0b15b9dd80c64b8c0956c1621061b294f8b93edab7f");
    const uint256 outpoint_txid = uint256_from_rpc_hex(
        "3efc16d756edba48884ae59974ea4496244ed6433fef111adf4b7496e23d6673");
    auto h = govvote_signature_hash(outpoint_txid, 0, parent,
                                    VOTE_OUTCOME_YES, VOTE_SIGNAL_FUNDING,
                                    1760356129);
    EXPECT_EQ(h.GetHex(),
        "3d4eeb64f79150a5007e54cae3f2bd3c3c55e850a31e04bc2c54eabbd43e49f2");
    // And it must differ from the identity hash (different preimages).
    auto id = govvote_identity_hash(outpoint_txid, 0, parent,
                                    VOTE_OUTCOME_YES, VOTE_SIGNAL_FUNDING,
                                    1760356129);
    EXPECT_NE(h, id);
}

// ── 2b. vchData hex round-trip (RPC DataHex vector helper) ──────────────────
TEST(DashSuperblock, GovDataHexRoundTrip) {
    const std::string json = trigger_json(
        1519824, "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", "5.00000000", kPropHash);
    auto plain = govdata_hex_to_plain(to_hex(json));
    ASSERT_TRUE(plain.has_value());
    EXPECT_EQ(*plain, json);
    auto trig = parse_superblock_trigger(*plain, hash_of(11), /*testnet=*/true);
    ASSERT_TRUE(trig.has_value());
    EXPECT_EQ(trig->payments[0].script, kScriptYeRZ);
}

// ── 4. superblock_budget == dashd getsuperblockbudget ───────────────────────
TEST(DashSuperblock, BudgetMatchesDashd) {
    // Testnet: getsuperblockbudget 1519824 == 14.28625704 DASH, cycle 24.
    EXPECT_EQ(superblock_budget(1519824, DASH_SUPERBLOCK_CYCLE_TESTNET),
              1'428'625'704LL);
    // Mainnet cycle 16616: a large but well-defined value; assert positive and
    // formula-stable (a from-daemon mainnet pin is a soak-scope item).
    EXPECT_GT(superblock_budget(2'128'896, DASH_SUPERBLOCK_CYCLE_MAINNET), 0);
}

// ── 5. GetBestSuperblock + FAIL-CLOSED ladder (R4 tally semantics) ──────────
TEST(DashSuperblock, FailClosedUntilFundingThreshold) {
    GovernanceStore store;
    store.set_funding_threshold(17);   // dashd getgovernanceinfo.fundingthreshold

    const std::string json = trigger_json(
        1519824, "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", "5.00000000", kPropHash);
    auto trig = parse_superblock_trigger(json, hash_of(20), /*testnet=*/true);
    ASSERT_TRUE(trig.has_value());
    ASSERT_TRUE(store.add_trigger(*trig));

    const int64_t budget = superblock_budget(1519824, DASH_SUPERBLOCK_CYCLE_TESTNET);

    // Weight/membership seam UNSET (production default): even a flood of
    // "verified" votes counts 0 -> FAIL CLOSED.
    for (int i = 0; i < 40; ++i)
        store.add_verified_funding_vote(hash_of(20), "mn-" + std::to_string(i),
                                        VOTE_OUTCOME_YES, 1000 + i);
    EXPECT_EQ(store.absolute_yes_count(hash_of(20)), 0);
    EXPECT_FALSE(get_superblock_payments(store, 1519824, budget).has_value());

    // Seam wired (all-regular weights): 40 yes-votes now tally.
    store.set_vote_weight_fn(weight_all_regular);
    EXPECT_EQ(store.absolute_yes_count(hash_of(20)), 40);
    auto pay = get_superblock_payments(store, 1519824, budget);
    ASSERT_TRUE(pay.has_value());
    ASSERT_EQ(pay->size(), 1u);
    EXPECT_EQ((*pay)[0].script, kScriptYeRZ);
    EXPECT_EQ((*pay)[0].amount, 500'000'000LL);

    // Fresh store: walk the threshold boundary exactly.
    GovernanceStore s2;
    s2.set_funding_threshold(17);
    s2.set_vote_weight_fn(weight_all_regular);
    ASSERT_TRUE(s2.add_trigger(*trig));
    for (int i = 0; i < 16; ++i)
        s2.add_verified_funding_vote(hash_of(20), "mn-" + std::to_string(i),
                                     VOTE_OUTCOME_YES, 1000 + i);
    EXPECT_EQ(s2.absolute_yes_count(hash_of(20)), 16);
    EXPECT_FALSE(get_superblock_payments(s2, 1519824, budget).has_value());
    s2.add_verified_funding_vote(hash_of(20), "mn-16", VOTE_OUTCOME_YES, 2000);
    EXPECT_EQ(s2.absolute_yes_count(hash_of(20)), 17);
    EXPECT_TRUE(get_superblock_payments(s2, 1519824, budget).has_value());
    // A NO vote drops the absolute-yes tally back below threshold -> refuse.
    s2.add_verified_funding_vote(hash_of(20), "mn-no", VOTE_OUTCOME_NO, 3000);
    EXPECT_EQ(s2.absolute_yes_count(hash_of(20)), 16);
    EXPECT_FALSE(get_superblock_payments(s2, 1519824, budget).has_value());
}

// ── 5b. EvoNode 4x weight + membership-at-tally (R4) ────────────────────────
TEST(DashSuperblock, WeightedTallyEvoAndMembership) {
    GovernanceStore store;
    store.set_funding_threshold(5);
    const std::string json = trigger_json(
        1519824, "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", "5.0", kPropHash);
    auto trig = parse_superblock_trigger(json, hash_of(21), /*testnet=*/true);
    ASSERT_TRUE(store.add_trigger(*trig));
    store.add_verified_funding_vote(hash_of(21), "evo-1", VOTE_OUTCOME_YES, 1);
    store.add_verified_funding_vote(hash_of(21), "reg-1", VOTE_OUTCOME_YES, 2);

    // 1 EvoNode (4x) + 1 regular (1x) = 5 >= threshold 5.
    bool evo_in_set = true;
    store.set_vote_weight_fn([&evo_in_set](const std::string& k) {
        if (k == "evo-1") return evo_in_set ? DASH_VOTE_WEIGHT_EVO : 0;
        return DASH_VOTE_WEIGHT_REGULAR;
    });
    EXPECT_EQ(store.absolute_yes_count(hash_of(21)), 5);
    EXPECT_TRUE(store.get_best_superblock(1519824).has_value());

    // The EvoNode leaves the valid set: its vote no longer counts (dashcore
    // membership-at-tally) -> 1 < 5 -> refuse.
    evo_in_set = false;
    EXPECT_EQ(store.absolute_yes_count(hash_of(21)), 1);
    EXPECT_FALSE(store.get_best_superblock(1519824).has_value());
}

// ── 5c. Threshold formula (R4) — dashcore UpdateSentinelVariables ───────────
TEST(DashSuperblock, FundingThresholdFormula) {
    // Live testnet posture: fundingthreshold 17 == weighted/10 with minQuorum 1.
    EXPECT_EQ(governance_funding_threshold(170, DASH_GOV_MIN_QUORUM_TESTNET), 17);
    EXPECT_EQ(governance_funding_threshold(179, DASH_GOV_MIN_QUORUM_TESTNET), 17);
    // Mainnet min-quorum floor: a tiny list still needs 10 weighted yes.
    EXPECT_EQ(governance_funding_threshold(50, DASH_GOV_MIN_QUORUM_MAINNET), 10);
    EXPECT_EQ(governance_funding_threshold(5000, DASH_GOV_MIN_QUORUM_MAINNET), 500);
    // Unknown inputs => 0 => fail closed (get_best_superblock refuses on 0).
    EXPECT_EQ(governance_funding_threshold(0, DASH_GOV_MIN_QUORUM_MAINNET), 0);
    EXPECT_EQ(governance_funding_threshold(-1, DASH_GOV_MIN_QUORUM_MAINNET), 0);
    EXPECT_EQ(governance_funding_threshold(100, 0), 0);  // gov params never set
}

// ── 5d. Unknown threshold (0) always fails closed ───────────────────────────
TEST(DashSuperblock, UnknownThresholdFailsClosed) {
    GovernanceStore store;   // threshold defaults to 0 => unknown
    store.set_vote_weight_fn(weight_all_regular);
    const std::string json = trigger_json(
        1519824, "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", "5.0", kPropHash);
    auto trig = parse_superblock_trigger(json, hash_of(22), /*testnet=*/true);
    ASSERT_TRUE(trig.has_value());
    ASSERT_TRUE(store.add_trigger(*trig));
    for (int i = 0; i < 100; ++i)
        store.add_verified_funding_vote(hash_of(22), "mn-" + std::to_string(i),
                                        VOTE_OUTCOME_YES, i);
    EXPECT_FALSE(store.get_best_superblock(1519824).has_value());
}

// ── 5e. Over-budget trigger rejected ────────────────────────────────────────
TEST(DashSuperblock, OverBudgetRejected) {
    GovernanceStore store;
    store.set_funding_threshold(1);
    store.set_vote_weight_fn(weight_all_regular);
    const std::string json = trigger_json(
        1519824, "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", "1000.0", kPropHash);
    auto trig = parse_superblock_trigger(json, hash_of(23), /*testnet=*/true);
    ASSERT_TRUE(trig.has_value());
    ASSERT_TRUE(store.add_trigger(*trig));
    store.add_verified_funding_vote(hash_of(23), "mn-0", VOTE_OUTCOME_YES, 1);
    const int64_t budget = superblock_budget(1519824, DASH_SUPERBLOCK_CYCLE_TESTNET);
    EXPECT_FALSE(get_superblock_payments(store, 1519824, budget).has_value());
}

// ── 5f. Highest-yes trigger wins among competitors ──────────────────────────
TEST(DashSuperblock, BestSuperblockPicksHighestYes) {
    GovernanceStore store;
    store.set_funding_threshold(2);
    store.set_vote_weight_fn(weight_all_regular);
    auto mk = [&](uint64_t id, const char* amt, int yes) {
        auto t = parse_superblock_trigger(
            trigger_json(1519824, "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", amt,
                         kPropHash),
            hash_of(id), /*testnet=*/true);
        ASSERT_TRUE(t.has_value());
        ASSERT_TRUE(store.add_trigger(*t));
        for (int i = 0; i < yes; ++i)
            store.add_verified_funding_vote(hash_of(id),
                                            "mn-" + std::to_string(id * 100 + i),
                                            VOTE_OUTCOME_YES, i);
    };
    mk(30, "1.0", 3);
    mk(31, "2.0", 9);   // most yes -> winner
    mk(32, "3.0", 5);
    auto best = store.get_best_superblock(1519824);
    ASSERT_TRUE(best.has_value());
    EXPECT_EQ(best->object_hash, hash_of(31));
    EXPECT_EQ(best->payments[0].amount, 200'000'000LL);
}

// ── 5g. Trigger store is bounded (F2) ───────────────────────────────────────
TEST(DashSuperblock, TriggerStoreBounded) {
    GovernanceStore store;
    GovernanceTrigger t;
    t.event_block_height = 1519824;
    t.payments.push_back({kScriptYeRZ, 1});
    for (size_t i = 0; i < GovernanceStore::MAX_TRIGGERS; ++i) {
        t.object_hash = hash_of(1000 + i);
        EXPECT_TRUE(store.add_trigger(t));
    }
    t.object_hash = hash_of(5000);
    EXPECT_FALSE(store.add_trigger(t)) << "store must reject past the bound";
    EXPECT_EQ(store.trigger_count(), GovernanceStore::MAX_TRIGGERS);
    // Re-adding a KNOWN hash is still fine (idempotent update, no growth).
    t.object_hash = hash_of(1000);
    EXPECT_TRUE(store.add_trigger(t));
    EXPECT_EQ(store.trigger_count(), GovernanceStore::MAX_TRIGGERS);
    // prune_executed frees the cycle.
    store.prune_executed(1519824);
    EXPECT_EQ(store.trigger_count(), 0u);
}

// ── 6. Malformed trigger inputs fail closed (dashd-reject parity) ───────────
TEST(DashSuperblock, MalformedFailsClosed) {
    const bool tn = true;
    // not a trigger (type 1 = proposal)
    EXPECT_FALSE(parse_superblock_trigger(
        R"({"event_block_height":1,"payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A","payment_amounts":"1.0","proposal_hashes":")"
            + std::string(kPropHash) + R"(","type":1})",
        hash_of(40), tn).has_value());
    // type MISSING (dashd: obj["type"].getInt() throws)
    EXPECT_FALSE(parse_superblock_trigger(
        R"({"event_block_height":1,"payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A","payment_amounts":"1.0","proposal_hashes":")"
            + std::string(kPropHash) + R"("})",
        hash_of(41), tn).has_value());
    // proposal_hashes MISSING (dashd: get_str() throws)
    EXPECT_FALSE(parse_superblock_trigger(
        R"({"event_block_height":1,"payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A","payment_amounts":"1.0","type":2})",
        hash_of(42), tn).has_value());
    // proposal_hashes count mismatch
    EXPECT_FALSE(parse_superblock_trigger(
        trigger_json(1, "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", "1.0",
                     std::string(kPropHash) + "|" + kPropHash),
        hash_of(43), tn).has_value());
    // proposal hash not a valid uint256 hex ("abc" — a trigger dashd REJECTS)
    EXPECT_FALSE(parse_superblock_trigger(
        trigger_json(1, "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", "1.0", "abc"),
        hash_of(44), tn).has_value());
    // address/amount count mismatch
    EXPECT_FALSE(parse_superblock_trigger(
        trigger_json(1,
            "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A|ycn2gNExGVmcwJALr4PciWqWuN1DEsUBEN",
            "1.0", kPropHash),
        hash_of(45), tn).has_value());
    // bad address
    EXPECT_FALSE(parse_superblock_trigger(
        trigger_json(1, "not_an_address", "1.0", kPropHash),
        hash_of(46), tn).has_value());
    // missing event_block_height
    EXPECT_FALSE(parse_superblock_trigger(
        R"({"payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A","payment_amounts":"1.0","proposal_hashes":")"
            + std::string(kPropHash) + R"(","type":2})",
        hash_of(47), tn).has_value());
    // event_block_height as a STRING (dashd getInt<int> throws on strings)
    EXPECT_FALSE(parse_superblock_trigger(
        R"({"event_block_height":"1519824","payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A","payment_amounts":"1.0","proposal_hashes":")"
            + std::string(kPropHash) + R"(","type":2})",
        hash_of(48), tn).has_value());
    // legacy nested-array form: REJECTED outright (dead format, fail closed)
    EXPECT_FALSE(parse_superblock_trigger(
        R"([["trigger",{"event_block_height":1519824,"payment_addresses":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A","payment_amounts":"1.0","proposal_hashes":")"
            + std::string(kPropHash) + R"(","type":2}]])",
        hash_of(49), tn).has_value());
    // zero amount ("0" parses in dashd's grammar but a zero payment is refused)
    EXPECT_FALSE(parse_superblock_trigger(
        trigger_json(1, "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", "0", kPropHash),
        hash_of(50), tn).has_value());
    // non-JSON
    EXPECT_FALSE(parse_superblock_trigger("not json at all", hash_of(51), tn)
                     .has_value());
    // odd-length hex (RPC DataHex helper)
    EXPECT_FALSE(govdata_hex_to_plain("abc").has_value());
}

// ── 6b. ParsePaymentAmount grammar — dashcore-exact (parser hardening) ──────
TEST(DashSuperblock, PaymentAmountGrammar) {
    // Accepted by dashd's grammar:
    EXPECT_EQ(parse_payment_amount("1").value(), 100'000'000LL);
    EXPECT_EQ(parse_payment_amount("1.0").value(), 100'000'000LL);
    EXPECT_EQ(parse_payment_amount("0.5").value(), 50'000'000LL);
    EXPECT_EQ(parse_payment_amount("0.00000001").value(), 1LL);
    EXPECT_EQ(parse_payment_amount("14.28625704").value(), 1'428'625'704LL);
    EXPECT_EQ(parse_payment_amount("21000000").value(), DASH_MAX_MONEY);
    EXPECT_EQ(parse_payment_amount("0").value(), 0LL);  // parses; trigger rejects 0
    // Rejected by dashd (ParsePaymentAmount / ParseFixedPoint):
    EXPECT_FALSE(parse_payment_amount("").has_value());
    EXPECT_FALSE(parse_payment_amount("+5.0").has_value());   // '+' not in charset
    EXPECT_FALSE(parse_payment_amount("-1.0").has_value());   // '-' not in charset
    EXPECT_FALSE(parse_payment_amount(".5").has_value());     // leading '.'
    EXPECT_FALSE(parse_payment_amount("5.").has_value());     // no digits after '.'
    EXPECT_FALSE(parse_payment_amount("007").has_value());    // leading zeros
    EXPECT_FALSE(parse_payment_amount("01.0").has_value());   // leading zero
    EXPECT_FALSE(parse_payment_amount("1.234567890").has_value()); // 9 frac digits
    EXPECT_FALSE(parse_payment_amount("1.2.3").has_value());  // two dots
    EXPECT_FALSE(parse_payment_amount("1e8").has_value());    // exponent
    EXPECT_FALSE(parse_payment_amount("1 0").has_value());    // space
    EXPECT_FALSE(parse_payment_amount("21000001").has_value());     // > MoneyRange
    EXPECT_FALSE(parse_payment_amount("123456789012345678901").has_value()); // >20 chars
    EXPECT_FALSE(parse_payment_amount("abc").has_value());
}

// ── 7. build_embedded_workdata emits superblock outputs + bumps value ───────
TEST(DashSuperblock, TemplateEmitsSuperblockOutputs) {
    MnStateMachine mn;   // empty MN set (no MN payee) — isolates the superblock path
    Mempool mp;

    const uint32_t next_h = 1519824;
    // Baseline (no superblock schedule): capture coinbase value.
    DashWorkData base = build_embedded_workdata(
        next_h - 1, uint256::ZERO, mn, mp,
        /*bits*/0x1e0ffff0, /*mtp*/1'700'000'000u,
        /*addr_ver*/140, /*addr_p2sh*/19,
        /*curtime*/1'700'000'100u, /*version*/0x20000000u,
        /*underfill*/nullptr, /*sml*/nullptr, /*qmgr*/nullptr,
        /*bestcl_h*/0, k_zero_cl_sig, /*credit_pool*/0,
        DASH_MN_RR_HEIGHT_TESTNET, /*superblock_payments*/nullptr);

    // Funded superblock: one payee of 5 DASH.
    std::vector<SuperblockPayment> sched = {{kScriptYeRZ, 500'000'000LL}};
    DashWorkData sb = build_embedded_workdata(
        next_h - 1, uint256::ZERO, mn, mp,
        0x1e0ffff0, 1'700'000'000u, 140, 19,
        1'700'000'100u, 0x20000000u,
        nullptr, nullptr, nullptr, 0, k_zero_cl_sig, 0,
        DASH_MN_RR_HEIGHT_TESTNET, &sched);

    // Coinbase value augmented by exactly the superblock total.
    EXPECT_EQ(sb.m_coinbase_value, base.m_coinbase_value + 500'000'000ULL);
    // The superblock payee output is present (base58 form of yeRZ...).
    bool found = false;
    for (const auto& pp : sb.m_packed_payments)
        if (pp.amount == 500'000'000ULL &&
            pp.payee == "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A")
            found = true;
    EXPECT_TRUE(found);
    // And it is an ADDED output vs baseline.
    EXPECT_EQ(sb.m_packed_payments.size(), base.m_packed_payments.size() + 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// R5 / R6 — NodeCoinState + CoinStateMaintainer harness
// ═══════════════════════════════════════════════════════════════════════════
namespace {

uint256 raw256(uint8_t base) {
    uint256 h;
    for (size_t i = 0; i < 32; ++i)
        h.data()[i] = static_cast<unsigned char>(base + i);
    return h;
}

std::vector<unsigned char> p2pkh_script(uint8_t hashseed) {
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(static_cast<unsigned char>(hashseed + i));
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

std::vector<std::pair<uint256, MNState>> single_mn(
    const std::vector<unsigned char>& payout) {
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 1'519'000;
    s.nLastPaidHeight = 0;
    s.scriptPayout.m_data = payout;
    return {{raw256(0x01), s}};
}

void bind_block(BlockType& b) {
    std::vector<uint256> ids;
    for (const auto& tx : b.m_txs) ids.push_back(dash_txid(tx));
    b.m_merkle_root = compute_merkle_root(ids);
}

MutableTransaction make_cb(int64_t value,
                           const std::vector<unsigned char>& script) {
    MutableTransaction tx;
    tx.version = 1; tx.type = 0; tx.locktime = 0;
    ::bitcoin_family::coin::TxIn in;
    in.prevout.hash = uint256::ZERO; in.prevout.index = 0xffffffffu;
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    ::bitcoin_family::coin::TxOut o;
    o.value = value;
    o.scriptPubKey.m_data = script;
    tx.vout.push_back(o);
    return tx;
}

constexpr uint32_t SBH = 1'519'824;  // the superblock height under test

// Arm a maintainer's governance view so superblock_schedule(SBH) resolves.
void arm_trigger_confident(CoinStateMaintainer& m) {
    m.set_gov_params(/*testnet=*/true, DASH_GOV_MIN_QUORUM_TESTNET);
    m.set_superblock_ctx(
        [](uint32_t h) { return h == SBH; },
        [](uint32_t h) {
            return superblock_budget(h, DASH_SUPERBLOCK_CYCLE_TESTNET);
        });
    auto trig = parse_superblock_trigger(
        trigger_json(static_cast<int>(SBH),
                     "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", "5.0", kPropHash),
        hash_of(60), /*testnet=*/true);
    ASSERT_TRUE(trig.has_value());
    ASSERT_TRUE(m.gov_store().add_trigger(*trig));
    // set_gov_params reseeded the threshold from the (empty) SML => 0; pin a
    // known threshold + weight seam for the KAT so the trigger is confident.
    m.gov_store().set_funding_threshold(1);
    m.gov_store().set_vote_weight_fn(weight_all_regular);
    m.gov_store().add_verified_funding_vote(hash_of(60), "mn-0",
                                            VOTE_OUTCOME_YES, 1);
    ASSERT_TRUE(m.superblock_schedule(SBH).has_value());
}

} // namespace

// ── 8. R5: the completeness gate is structural ──────────────────────────────
// Wiring the provider + flipping --embedded-superblock (and even a confident
// trigger) must NOT open the serve path: without the sync-complete predicate
// the superblock height still refuses to the dashd fallback. This is the
// invariant that makes "vote-verify lands alone" incapable of serving.
TEST(DashSuperblock, CompletenessGateIsRequiredToServe) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    m.on_new_tip(SBH - 1, raw256(0xAB), 0x1e0ffff0u, 1'700'000'000u,
                 /*addr_ver*/140, /*addr_p2sh*/19, 1'700'000'100u, 0x20000000u);
    ASSERT_TRUE(m.live());
    ASSERT_TRUE(st.make_embedded_work_inputs().viable()) << "baseline viable";

    // Superblock height guard alone (old behaviour): refuse.
    st.set_is_superblock_fn([](uint32_t h) { return h == SBH; });
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());

    // Provider + flag + trigger-confident view — but NO completeness fn:
    // R5 requires this to STILL refuse.
    arm_trigger_confident(m);
    st.set_superblock_provider([&m](uint32_t h) { return m.superblock_schedule(h); });
    st.set_require_superblock_provider(true);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "provider+flag without the completeness gate must NOT serve (R5)";

    // Completeness fn present but FALSE: still refuse.
    bool complete = false;
    st.set_superblock_sync_complete_fn([&complete]() { return complete; });
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());

    // Completeness proven: the arm may serve, and the template carries the
    // trigger's schedule.
    complete = true;
    auto e = st.make_embedded_work_inputs();
    ASSERT_TRUE(e.viable());
    ASSERT_EQ(e.superblock_payments.size(), 1u);
    EXPECT_EQ(e.superblock_payments[0].script, kScriptYeRZ);
    EXPECT_EQ(e.superblock_payments[0].amount, 500'000'000LL);
}

// ── 9. R6: superblock desync cross-check ────────────────────────────────────
// A network-accepted block at a superblock height whose coinbase does NOT
// carry our trigger-confident schedule proves our governance view wrong: the
// maintainer must clear the store, LATCH the superblock arm closed, and
// demote — never serve a guessed superblock schedule again.
TEST(DashSuperblock, SuperblockDesyncClearsLatchesAndDemotes) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    m.on_new_tip(SBH - 1, raw256(0xAB), 0x1e0ffff0u, 1'700'000'000u,
                 140, 19, 1'700'000'100u, 0x20000000u);
    ASSERT_TRUE(m.live());
    arm_trigger_confident(m);
    EXPECT_FALSE(m.gov_desync_latched());

    // The accepted superblock coinbase pays the projected MN (so the MN
    // payee-desync axis stays quiet) but NOT our superblock payee.
    BlockType blk;
    blk.m_txs.push_back(make_cb(500'000'000, p2pkh_script(0x30)));
    bind_block(blk);
    m.on_block_connected(blk, SBH);

    EXPECT_TRUE(m.gov_desync_latched()) << "mismatch must latch the desync";
    EXPECT_EQ(m.gov_store().trigger_count(), 0u) << "store must be cleared";
    EXPECT_FALSE(m.superblock_schedule(SBH).has_value())
        << "a latched arm must never resolve a schedule";
    // The latch PERSISTS: even a freshly re-ingested trigger with a passing
    // tally must not re-open the superblock path (only a restart / an explicit
    // future re-proof path may unlatch — a proven-wrong view is never trusted
    // again by accretion).
    auto trig2 = parse_superblock_trigger(
        trigger_json(static_cast<int>(SBH) + 24,
                     "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", "5.0", kPropHash),
        hash_of(61), /*testnet=*/true);
    ASSERT_TRUE(trig2.has_value());
    ASSERT_TRUE(m.gov_store().add_trigger(*trig2));
    m.gov_store().set_funding_threshold(1);
    m.gov_store().set_vote_weight_fn(weight_all_regular);
    m.gov_store().add_verified_funding_vote(hash_of(61), "mn-0",
                                            VOTE_OUTCOME_YES, 1);
    EXPECT_FALSE(m.superblock_schedule(SBH + 24).has_value())
        << "the desync latch must survive re-ingestion";
    // The MN axis is untouched (the coinbase paid the projected MN): the
    // embedded arm may keep serving NON-superblock heights; superblock
    // heights refuse via the latch (superblock_schedule => nullopt =>
    // NodeCoinState resolve_superblock fails closed to dashd).
}

// ── 9b. R6: an ACCEPTED block matching our schedule does not latch ──────────
TEST(DashSuperblock, SuperblockMatchDoesNotLatchAndPrunes) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    m.on_new_tip(SBH - 1, raw256(0xAB), 0x1e0ffff0u, 1'700'000'000u,
                 140, 19, 1'700'000'100u, 0x20000000u);
    ASSERT_TRUE(m.live());
    arm_trigger_confident(m);

    // Coinbase carries the MN payment AND our exact superblock (script,amount).
    BlockType blk;
    auto cb = make_cb(500'000'000, p2pkh_script(0x30));
    ::bitcoin_family::coin::TxOut sb_out;
    sb_out.value = 500'000'000LL;
    sb_out.scriptPubKey.m_data.assign(kScriptYeRZ.begin(), kScriptYeRZ.end());
    cb.vout.push_back(sb_out);
    blk.m_txs.push_back(cb);
    bind_block(blk);
    m.on_block_connected(blk, SBH);

    EXPECT_FALSE(m.gov_desync_latched()) << "a matching coinbase must not latch";
    // The executed cycle is pruned (store bounded across cycles).
    EXPECT_EQ(m.gov_store().trigger_count(), 0u);
}

// ── 9c. R6: no false-fire off superblock heights ────────────────────────────
TEST(DashSuperblock, DesyncCheckDoesNotFireOffSuperblockHeights) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    m.on_new_tip(SBH - 2, raw256(0xAB), 0x1e0ffff0u, 1'700'000'000u,
                 140, 19, 1'700'000'100u, 0x20000000u);
    ASSERT_TRUE(m.live());
    arm_trigger_confident(m);

    // A NON-superblock height whose coinbase (naturally) lacks the superblock
    // payee: the predicate guard must keep the cross-check silent.
    BlockType blk;
    blk.m_txs.push_back(make_cb(500'000'000, p2pkh_script(0x30)));
    bind_block(blk);
    m.on_block_connected(blk, SBH - 1);

    EXPECT_FALSE(m.gov_desync_latched());
    EXPECT_EQ(m.gov_store().trigger_count(), 1u) << "no pruning off-cycle";
    EXPECT_TRUE(m.superblock_schedule(SBH).has_value());
}
