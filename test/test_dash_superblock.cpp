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
#include <impl/dash/coin/govsync_status.hpp>        // R5 completeness determination
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
        /*qc_commitments*/nullptr, /*quorum_root_override*/nullptr,
        DASH_MN_RR_HEIGHT_TESTNET, /*superblock_payments*/nullptr);

    // Funded superblock: one payee of 5 DASH.
    std::vector<SuperblockPayment> sched = {{kScriptYeRZ, 500'000'000LL}};
    DashWorkData sb = build_embedded_workdata(
        next_h - 1, uint256::ZERO, mn, mp,
        0x1e0ffff0, 1'700'000'000u, 140, 19,
        1'700'000'100u, 0x20000000u,
        nullptr, nullptr, nullptr, 0, k_zero_cl_sig, 0,
        /*qc_commitments*/nullptr, /*quorum_root_override*/nullptr,
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
// HISTORICAL BYTE-PARITY (the acceptance gate) — MAINNET superblock 2525632.
//
// Ground truth (Mauritius oracle dashd 192.168.86.165:9998, verbosity-2
// getblock 0000000000000017221e577f37bb5d47a54b403e34ea1c5655e0cdf45b7328a1):
// the on-chain coinbase txid 79030312ea976c901fa5e0d223ff1edecf71649b7f3e7f8e10f0c356f60ce3e1
// pays vout[0]=miner, vout[1]=OP_RETURN(platform), vout[2]=MN, and
// vout[3..16]= the 14 governance/treasury outputs of the funded superblock.
// This KAT reconstructs the winning trigger's payment schedule from that
// on-chain payee set (faithful because dashd validates a superblock coinbase
// against exactly ParsePaymentSchedule(vchData), and address->script is
// deterministic — the winning-trigger gobject itself is cycle-ephemeral and
// long since erased network-wide), feeds it through the daemonless pipeline
// parse_superblock_trigger -> GovernanceStore -> get_superblock_payments ->
// build_embedded_workdata, and asserts the produced superblock coinbase
// outputs are BYTE-IDENTICAL to the real vout[3..16] slice: same scripts,
// same amounts, same ORDER (including the duplicate P2SH 7mUyau75… at
// positions 4 and 12), same 20% treasury total (6817 DASH), under the
// getsuperblockbudget cap (6828.26378160 DASH).
// ═══════════════════════════════════════════════════════════════════════════
namespace {

// hex scriptPubKey -> raw bytes (the coinbase-serialized script form).
std::vector<uint8_t> hb(const std::string& hex) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<uint8_t>((nib(hex[i]) << 4) | nib(hex[i + 1])));
    return out;
}

// The 14 governance outputs of superblock 2525632 in ON-CHAIN ORDER:
//   {mainnet payee address, DASH-amount string, on-chain scriptPubKey hex,
//    duffs}. Note the SAME P2SH payee (7mUyau75…) appears at index 3 and 11.
struct SbVec { const char* addr; const char* amt; const char* spk; int64_t duffs; };
const std::vector<SbVec> kSb2525632 = {
    {"XoLMVTXpDWvLe4yKcj989nZ2vddE2zJQ6q","60",   "76a9148ab9a867903e835e86d0e4f417d968c5c78fa7ba88ac",  6000000000LL},
    {"XgNfgrEB9n6uCY9Pi1hb2foimxPdtiZ4Z2","350",  "76a9143e60cc82015c846a4ff43fc80e587850dd248e8d88ac", 35000000000LL},
    {"Xebhp13RsUPU8sqzAPiurHUh1kGCJ7zabs","200",  "76a9142ae7ba2caf2a0578aa1b4ee9431dcaac2c56805388ac", 20000000000LL},
    {"7mUyau75ATy1c6LoZeG3D57jKBkR4iHJkE","4832", "a914d13bc5c4b8ca8073d08e12baf57690d3eebc6f7987",    483200000000LL},
    {"Xx1DY36sQjrmvRTPw7kyTZ9Xg9dyVp3h7C","45",   "76a914e9d43ee3ac25faf34f1776f1d1e23e6ea28543ac88ac", 4500000000LL},
    {"XjRx5Xj9G4kE4gvLT6GQKmvWMrtGPtUjkS","530",  "76a9145fe81b4ddaafdffbd6f70cdb7464b9567e15301d88ac", 53000000000LL},
    {"XogmURyyvkE8DXdhZGUd1qgYwgvwZ8WCxR","100",  "76a9148e95ff1957118b3209f4b40b8e63f5bc42edd5bb88ac", 10000000000LL},
    {"XjdnZBUedF4q8EzgWWAGsZrHteEgEUybbo","250",  "76a914622526095b3f27d9b8f7a6f975956d9a63586a9c88ac", 25000000000LL},
    {"Xhf1d5nmRreWC3YkvQXWswFbPdpGyU6rRB","1",    "76a9144c7038928ca5ad481a348a4dc74270026f82568c88ac", 100000000LL},
    {"Xr3EjtyMzJRcb5dkshjbjg6zXd2EY1662Y","85",   "76a914a865540d8b036f34b8fd60f328177a4c22f39a4d88ac", 8500000000LL},
    {"XvQMESjyfJEW2hsSXNRvbXwBVizZgdNXkw","32",   "76a914d843fc6fdfd071c2fab8b94dcd8143cec67dcb1788ac", 3200000000LL},
    {"7mUyau75ATy1c6LoZeG3D57jKBkR4iHJkE","200",  "a914d13bc5c4b8ca8073d08e12baf57690d3eebc6f7987",     20000000000LL},
    {"XoccKgfVCBRWqu2GYWctDAdLGRybr2zbhP","82",   "76a9148dccb1a4f3d32a7bdb997d18ff53bea78723ab2488ac", 8200000000LL},
    {"XcAY5amfZ4qr8WrzppGxLQ3uGpCYFb19zC","50",   "76a9141034f40bf6fe1543f2290d9c3e515b6698dff80f88ac", 5000000000LL},
};

std::string join_pipe(const std::vector<std::string>& v) {
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) { if (i) out += "|"; out += v[i]; }
    return out;
}

} // namespace

TEST(DashSuperblockHistorical, Mainnet2525632CoinbaseBytesMatchOnChain) {
    constexpr int32_t H = 2'525'632;
    // 1) Reconstruct the winning trigger's plaintext JSON schedule from the
    //    on-chain payee set (mainnet addresses, chain order). proposal_hashes
    //    is a well-formed-but-arbitrary per-payee filler (the dashd parser
    //    requires one valid uint256 hex per payee; it never affects the payee
    //    math — get_superblock_payments consumes only script+amount).
    std::vector<std::string> addrs, amts, props;
    for (const auto& e : kSb2525632) {
        addrs.emplace_back(e.addr);
        amts.emplace_back(e.amt);
        props.emplace_back(kPropHash);
    }
    const std::string json =
        trigger_json(H, join_pipe(addrs), join_pipe(amts), join_pipe(props));

    // 2) Parse via the daemonless dashd-exact parser (MAINNET chain-strict).
    auto trig = parse_superblock_trigger(json, hash_of(2525632), /*testnet=*/false);
    ASSERT_TRUE(trig.has_value()) << "mainnet trigger must parse";
    ASSERT_EQ(trig->event_block_height, H);
    ASSERT_EQ(trig->payments.size(), kSb2525632.size());

    // 3) Feed the GovernanceStore and resolve the winning schedule under the
    //    real getsuperblockbudget cap. superblock_budget(2525632, 16616) is
    //    KAT-pinned below to the oracle's 6828.26378160 DASH.
    const int64_t budget = superblock_budget(H, DASH_SUPERBLOCK_CYCLE_MAINNET);
    EXPECT_EQ(budget, 682'826'378'160LL);  // dashd getsuperblockbudget 2525632

    GovernanceStore store;
    ASSERT_TRUE(store.add_trigger(*trig));
    store.set_funding_threshold(1);
    store.set_vote_weight_fn(weight_all_regular);
    store.add_verified_funding_vote(hash_of(2525632), "mn-0", VOTE_OUTCOME_YES, 1);

    auto sched = get_superblock_payments(store, H, budget);
    ASSERT_TRUE(sched.has_value()) << "trigger-confident schedule must resolve";
    ASSERT_EQ(sched->size(), kSb2525632.size());

    // 4) BYTE-PARITY: the resolved (scriptPubKey, amount) vector is exactly the
    //    on-chain coinbase vout[3..16] slice — order-exact, incl. the duplicate
    //    P2SH at positions 3 and 11, to the duff.
    int64_t total = 0;
    for (size_t i = 0; i < kSb2525632.size(); ++i) {
        const auto expected_script = hb(kSb2525632[i].spk);
        EXPECT_EQ((*sched)[i].script, expected_script)
            << "payee " << i << " (" << kSb2525632[i].addr
            << ") scriptPubKey diverges from on-chain coinbase";
        EXPECT_EQ((*sched)[i].amount, kSb2525632[i].duffs)
            << "payee " << i << " amount diverges from on-chain coinbase";
        total += kSb2525632[i].duffs;
    }
    // 20% treasury total: 6817 DASH, under the 6828.26378160 DASH budget.
    EXPECT_EQ(total, 681'700'000'000LL);
    EXPECT_LE(total, budget);

    // 5) TEMPLATE WIRING: the embedded coinbase builder appends those payees as
    //    ADDED outputs (mainnet address versions 76 / 16) and augments
    //    coinbasevalue by exactly the treasury total — a valid CreateNewBlock-
    //    equivalent superblock coinbase built daemonlessly.
    MnStateMachine mn;   // empty MN set isolates the superblock outputs
    Mempool mp;
    DashWorkData base = build_embedded_workdata(
        static_cast<uint32_t>(H) - 1, uint256::ZERO, mn, mp,
        /*bits*/0x1a0ffff0, /*mtp*/1'700'000'000u,
        /*addr_ver*/76, /*addr_p2sh*/16,
        /*curtime*/1'700'000'100u, /*version*/0x20000000u,
        /*underfill*/nullptr, /*sml*/nullptr, /*qmgr*/nullptr,
        /*bestcl_h*/0, k_zero_cl_sig, /*credit_pool*/0,
        /*qc_commitments*/nullptr, /*quorum_root_override*/nullptr,
        DASH_MN_RR_HEIGHT_MAINNET, /*superblock_payments*/nullptr);
    DashWorkData sb = build_embedded_workdata(
        static_cast<uint32_t>(H) - 1, uint256::ZERO, mn, mp,
        0x1a0ffff0, 1'700'000'000u, 76, 16,
        1'700'000'100u, 0x20000000u,
        nullptr, nullptr, nullptr, 0, k_zero_cl_sig, 0,
        nullptr, nullptr, DASH_MN_RR_HEIGHT_MAINNET, &*sched);

    EXPECT_EQ(sb.m_coinbase_value,
              base.m_coinbase_value + static_cast<uint64_t>(total));
    ASSERT_EQ(sb.m_packed_payments.size(),
              base.m_packed_payments.size() + kSb2525632.size());
    // The appended superblock outputs are in schedule order, each carrying the
    // exact on-chain amount for its position (the duplicate 200-DASH / 4832-DASH
    // P2SH pair distinguishes an order-preserving append from a set-merge).
    const size_t off = base.m_packed_payments.size();
    for (size_t i = 0; i < kSb2525632.size(); ++i) {
        EXPECT_EQ(sb.m_packed_payments[off + i].amount,
                  static_cast<uint64_t>(kSb2525632[i].duffs))
            << "appended superblock output " << i << " amount/order diverges";
    }
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
    // Hand-seeded fixture: zero operator split, declared PROVEN as every
    // real ingest path does (h=2516595 serve gate).
    s.payoutSplitProvenance = MNState::SPLIT_KNOWN;
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

// ── 8a. R5: the GovSyncStatus completeness DETERMINATION (production logic) ──
// Unit-drive the real predicate (dashcore CMasternodeSync governance-phase
// model): completeness requires peer coverage + a settle floor + quiescence.
// Every under-covered / not-settled / not-quiesced view is INCOMPLETE.
TEST(DashSuperblock, GovSyncStatusCompletenessDetermination) {
    GovSyncStatus s;
    // min_peers=2, settle=60s, quiesce=30s (the mainnet-ish defaults).
    s.set_params(/*min_peers=*/2, /*settle=*/60, /*quiesce=*/30);

    const int64_t t0 = 1'700'000'000;
    // Default (nothing requested) => INCOMPLETE.
    EXPECT_FALSE(s.is_complete(t0));

    // One peer requested; even long after, one peer can never be complete
    // (partial-view hazard: a single peer may withhold the winning trigger).
    s.note_govsync_requested("peerA", t0);
    EXPECT_FALSE(s.is_complete(t0 + 10'000)) << "single-peer view is never complete";

    // Second distinct peer covered, but the settle floor has not elapsed.
    s.note_govsync_requested("peerB", t0 + 5);
    EXPECT_FALSE(s.is_complete(t0 + 30)) << "not settled (60s floor since first req)";

    // Settled, but an object just arrived => not quiesced.
    s.note_object_arrival(t0 + 61);
    EXPECT_FALSE(s.is_complete(t0 + 70)) << "recent object arrival re-arms quiescence";

    // Settled AND quiesced (>=30s since last activity) AND >=2 peers => COMPLETE.
    EXPECT_TRUE(s.is_complete(t0 + 61 + 30));

    // A fresh vote arrival re-opens the sync (mid-stream again) => INCOMPLETE.
    s.note_vote_arrival(t0 + 200);
    EXPECT_FALSE(s.is_complete(t0 + 210));
    EXPECT_TRUE(s.is_complete(t0 + 200 + 30)) << "quiesces again after the vote";

    // reset() (desync / reorg) forces the view back to INCOMPLETE.
    s.reset();
    EXPECT_FALSE(s.is_complete(t0 + 100'000));
    EXPECT_EQ(s.requested_peer_count(), 0u);
}

// ── 8b. R5: the maintainer's PRODUCTION predicate drives the serve path ──────
// End-to-end: wire NodeCoinState::set_superblock_sync_complete_fn to the REAL
// maintainer->gov_sync_complete() (as main_dash does), with an injected clock.
// A mid-sync governance view REFUSES; only a peer-covered + settled + quiesced
// view lets the trigger-confident superblock serve.
TEST(DashSuperblock, MaintainerGovSyncCompleteGatesServe) {
    NodeCoinState st;
    CoinStateMaintainer m(st);

    // Injected clock so settle/quiesce windows are deterministic.
    int64_t now = 1'700'000'000;
    m.set_now_fn([&now]() { return now; });
    m.set_gov_sync_params(/*min_peers=*/2, /*settle=*/60, /*quiesce=*/30);

    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    m.on_new_tip(SBH - 1, raw256(0xAB), 0x1e0ffff0u, 1'700'000'000u,
                 /*addr_ver*/140, /*addr_p2sh*/19, 1'700'000'100u, 0x20000000u);
    ASSERT_TRUE(m.live());

    // Trigger-confident view + provider + flag, and the PRODUCTION completeness
    // predicate (not a fake toggle).
    arm_trigger_confident(m);
    st.set_is_superblock_fn([](uint32_t h) { return h == SBH; });
    st.set_superblock_provider([&m](uint32_t h) { return m.superblock_schedule(h); });
    st.set_require_superblock_provider(true);
    st.set_superblock_sync_complete_fn([&m]() { return m.gov_sync_complete(); });

    // Nothing synced yet => INCOMPLETE => refuse.
    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "no govsync => incomplete => must refuse";

    // One peer only => still incomplete (under-covered).
    m.note_govsync_requested("peerA");
    now += 10'000;
    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "single-peer govsync is never complete";

    // Second peer, but not yet settled/quiesced.
    m.note_govsync_requested("peerB");
    now += 5;
    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "two peers but not settled/quiesced => refuse";

    // Settle + quiesce elapse with no new arrivals => COMPLETE => serve.
    now += 100;
    auto e = st.make_embedded_work_inputs();
    ASSERT_TRUE(e.viable()) << "peer-covered + settled + quiesced => serve";
    ASSERT_EQ(e.superblock_payments.size(), 1u);
    EXPECT_EQ(e.superblock_payments[0].script, kScriptYeRZ);

    // A late govobject arrival re-opens the sync => refuse again (proves the
    // reception path re-arms the production predicate).
    m.on_govobject(hash_of(99), GOVERNANCE_OBJECT_TRIGGER, {});
    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "a fresh govobject re-arms quiescence => mid-sync => refuse";
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

// ── MAINNET live superblock 2542248 — DERIVATION KAT (not comparison) ────────
// Observed from dashd v230107 (winning trigger 0db58cd0, AbsoluteYesCount 3134):
// 15 payees, total 6810.00000000 DASH = 681000000000 duffs, mixed P2PKH+P2SH,
// repeated addresses, order-sensitive. This test proves c2pool DERIVES the
// superblock from state: (1) the scriptPubKeys from the addresses (byte-exact vs
// dashd validateaddress), (2) WHICH trigger wins by weighted-yes tally, and it is
// falsifiable — flipping the tally changes the selected winner.
TEST(DashSuperblock, MainnetSuperblock2542248DerivedAndSelected) {
    const std::string addrs =
        "XogmURyyvkE8DXdhZGUd1qgYwgvwZ8WCxR|XjRx5Xj9G4kE4gvLT6GQKmvWMrtGPtUjkS|"
        "XoLMVTXpDWvLe4yKcj989nZ2vddE2zJQ6q|XjdnZBUedF4q8EzgWWAGsZrHteEgEUybbo|"
        "XotUg4YUzzRNhXhC4tvg72d8guh2Sg6WJJ|XeACkWmBosZSxPYNH8YTfQurKXuGNGv9B8|"
        "Xebhp13RsUPU8sqzAPiurHUh1kGCJ7zabs|7mUyau75ATy1c6LoZeG3D57jKBkR4iHJkE|"
        "Xx1DY36sQjrmvRTPw7kyTZ9Xg9dyVp3h7C|XjRx5Xj9G4kE4gvLT6GQKmvWMrtGPtUjkS|"
        "Xhf1d5nmRreWC3YkvQXWswFbPdpGyU6rRB|XvQMESjyfJEW2hsSXNRvbXwBVizZgdNXkw|"
        "7mUyau75ATy1c6LoZeG3D57jKBkR4iHJkE|XykqpKJsXDCENcqXpm8iAeAwbHqNoezQ3C|"
        "XogmURyyvkE8DXdhZGUd1qgYwgvwZ8WCxR";
    const std::string amts =
        "200.00000000|530.00000000|60.00000000|100.00000000|200.00000000|"
        "60.00000000|200.00000000|4832.00000000|45.00000000|200.00000000|"
        "1.00000000|32.00000000|200.00000000|100.00000000|50.00000000";
    std::string props;
    for (int i = 0; i < 15; ++i) props += (i ? "|" : "") + std::string(kPropHash);

    // (1) DERIVE scripts+amounts from the trigger (mainnet => testnet=false).
    auto trig = parse_superblock_trigger(
        trigger_json(2542248, addrs, amts, props), hash_of(0xDB58), /*testnet=*/false);
    ASSERT_TRUE(trig.has_value());
    EXPECT_EQ(trig->event_block_height, 2542248);
    ASSERT_EQ(trig->payments.size(), 15u);
    const char* exp_script[15] = {
        "76a9148e95ff1957118b3209f4b40b8e63f5bc42edd5bb88ac",  // XogmU  200
        "76a9145fe81b4ddaafdffbd6f70cdb7464b9567e15301d88ac",  // XjRx5  530
        "76a9148ab9a867903e835e86d0e4f417d968c5c78fa7ba88ac",  // XoLMV   60
        "76a914622526095b3f27d9b8f7a6f975956d9a63586a9c88ac",  // XjdnZ  100
        "76a91490ccf6eb1b5c26c28b6cd5640d4c97e4b89db3aa88ac",  // XotUg  200
        "76a914261511ed18435168874a24bb32768fc7d77a14bb88ac",  // XeACk   60
        "76a9142ae7ba2caf2a0578aa1b4ee9431dcaac2c56805388ac",  // Xebhp  200
        "a914d13bc5c4b8ca8073d08e12baf57690d3eebc6f7987",      // 7mUya P2SH 4832
        "76a914e9d43ee3ac25faf34f1776f1d1e23e6ea28543ac88ac",  // Xx1DY   45
        "76a9145fe81b4ddaafdffbd6f70cdb7464b9567e15301d88ac",  // XjRx5  200 (repeat)
        "76a9144c7038928ca5ad481a348a4dc74270026f82568c88ac",  // Xhf1d    1
        "76a914d843fc6fdfd071c2fab8b94dcd8143cec67dcb1788ac",  // XvQME   32
        "a914d13bc5c4b8ca8073d08e12baf57690d3eebc6f7987",      // 7mUya P2SH 200 (repeat)
        "76a914fd0c8b1b8361a389bdcd96359fb84d64bf480f0088ac",  // Xykqp  100
        "76a9148e95ff1957118b3209f4b40b8e63f5bc42edd5bb88ac",  // XogmU   50 (repeat)
    };
    const int64_t exp_amount[15] = {
        20000000000LL, 53000000000LL, 6000000000LL, 10000000000LL, 20000000000LL,
        6000000000LL, 20000000000LL, 483200000000LL, 4500000000LL, 20000000000LL,
        100000000LL, 3200000000LL, 20000000000LL, 10000000000LL, 5000000000LL,
    };
    auto hx = [](const char* h) {
        auto nyb = [](char c) { return (c <= '9') ? (c - '0') : ((c | 0x20) - 'a' + 10); };
        std::vector<uint8_t> v;
        for (size_t i = 0; h[i] && h[i + 1]; i += 2)
            v.push_back(static_cast<uint8_t>((nyb(h[i]) << 4) | nyb(h[i + 1])));
        return v;
    };
    for (size_t i = 0; i < 15; ++i) {
        EXPECT_EQ(trig->payments[i].script, hx(exp_script[i])) << "payee " << i;
        EXPECT_EQ(trig->payments[i].amount, exp_amount[i]) << "payee " << i;
    }
    EXPECT_EQ(trig->total_amount(), 681000000000LL);  // 6810.0 DASH

    // (2) DERIVE the winning trigger by weighted-yes tally: the real trigger beats
    //     a synthetic competitor at the SAME height with FEWER yes votes.
    auto other = parse_superblock_trigger(
        trigger_json(2542248, "XjRx5Xj9G4kE4gvLT6GQKmvWMrtGPtUjkS", "1.00000000", kPropHash),
        hash_of(0x4553), /*testnet=*/false);
    ASSERT_TRUE(other.has_value());
    GovernanceStore store;
    store.set_funding_threshold(2);
    store.set_vote_weight_fn(weight_all_regular);
    ASSERT_TRUE(store.add_trigger(*trig));
    ASSERT_TRUE(store.add_trigger(*other));
    for (int i = 0; i < 9; ++i)
        store.add_verified_funding_vote(hash_of(0xDB58), "mn-real-" + std::to_string(i), VOTE_OUTCOME_YES, i);
    for (int i = 0; i < 3; ++i)
        store.add_verified_funding_vote(hash_of(0x4553), "mn-other-" + std::to_string(i), VOTE_OUTCOME_YES, i);
    auto best = store.get_best_superblock(2542248);
    ASSERT_TRUE(best.has_value());
    EXPECT_EQ(best->object_hash, hash_of(0xDB58));       // selected the REAL winner
    EXPECT_EQ(best->payments.size(), 15u);
    EXPECT_EQ(best->total_amount(), 681000000000LL);

    // (4) FALSIFIABILITY: flip the tally so the competitor wins -> selection changes.
    //     Proves (2) tests derivation, not a hardcoded answer.
    GovernanceStore flip;
    flip.set_funding_threshold(2);
    flip.set_vote_weight_fn(weight_all_regular);
    ASSERT_TRUE(flip.add_trigger(*trig));
    ASSERT_TRUE(flip.add_trigger(*other));
    for (int i = 0; i < 2; ++i)
        flip.add_verified_funding_vote(hash_of(0xDB58), "r" + std::to_string(i), VOTE_OUTCOME_YES, i);
    for (int i = 0; i < 9; ++i)
        flip.add_verified_funding_vote(hash_of(0x4553), "o" + std::to_string(i), VOTE_OUTCOME_YES, i);
    auto flipbest = flip.get_best_superblock(2542248);
    ASSERT_TRUE(flipbest.has_value());
    EXPECT_EQ(flipbest->object_hash, hash_of(0x4553));   // winner changed with the tally
}

// ── Dash Core v24 (S4): payee multiplicity at a superblock ──────────────────
// From v24 each expected masternode output consumes a DISTINCT coinbase output
// (payments.cpp FindUnmatchedMasternodePayment, strict) and each superblock
// payment is matched from the output after the previous match
// (superblock.cpp CSuperblock::IsValid, is_v24). A v3 payee whose operator
// takes 50% at the payout script (two equal MN outputs at one script) and a
// superblock with two identical payments: the template's packed payments --
// emitted one output each by every builder (compute_dash_payouts,
// build_v36_gentx) -- satisfy both checks.
TEST(DashSuperblock, V24PayoutSetAndDuplicateSuperblockPaymentsUnderStrictMultiplicity) {
    MNState st;
    st.isValid = true;
    st.nRegisteredHeight = 1;
    st.nVersion = 3;
    vendor::MasternodePayoutShare p;
    p.scriptPayout.m_data = kScriptYcn2;
    p.reward = 10000;
    st.v24.payouts = {p};
    st.nOperatorReward = 5000;
    st.scriptOperatorPayout.m_data = kScriptYcn2;
    st.payoutSplitProvenance = MNState::SPLIT_KNOWN;
    MnStateMachine mn;
    uint256 pro;
    pro.SetHex("51238bb9e2b68fc8000000000000000000000000000000000000000000000001");
    mn.load(std::vector<std::pair<uint256, MNState>>{{pro, st}});
    Mempool mp;
    std::vector<SuperblockPayment> sched = {{kScriptYeRZ, 500'000'000LL}, {kScriptYeRZ, 500'000'000LL}};
    DashWorkData w = build_embedded_workdata(
        1519824 - 1, uint256::ZERO, mn, mp,
        0x1e0ffff0, 1'700'000'000u, 140, 19,
        1'700'000'100u, 0x20000000u,
        nullptr, nullptr, nullptr, 0, k_zero_cl_sig, 0,
        nullptr, nullptr, DASH_MN_RR_HEIGHT_TESTNET, &sched);

    struct Out { int64_t value; OPScript scriptPubKey; };
    std::vector<Out> vout;
    vout.push_back({1, {}});                                   // the miners' output(s)
    vout.back().scriptPubKey.m_data = kScriptYcn2;             // even at a payee's script
    for (const auto& pp : w.m_packed_payments) {
        Out o;
        o.value = static_cast<int64_t>(pp.amount);
        o.scriptPubKey.m_data = pp.payee == "!6a" ? std::vector<unsigned char>{0x6a}
                                                  : ::core::address_to_script(pp.payee);
        ASSERT_FALSE(o.scriptPubKey.m_data.empty()) << pp.payee;
        vout.push_back(o);
    }
    // Strict masternode match: both equal halves need their own output.
    const auto R = v24::match_mn_payment(st, vout);
    ASSERT_TRUE(R.has_value());
    EXPECT_EQ(*R, static_cast<int64_t>(w.m_payment_amount));
    const auto due = v24::expected_mn_outputs(st, *R);
    ASSERT_EQ(due.size(), 2u);
    EXPECT_EQ(due[0], due[1]) << "two equal outputs at one script";
    // The v24 superblock scan: each payment past the previous match.
    int idx = -1;
    for (const auto& sp : sched) {
        bool found = false;
        for (int j = idx + 1; j < static_cast<int>(vout.size()); ++j) {
            if (vout[j].scriptPubKey.m_data == sp.script && vout[j].value == sp.amount) {
                idx = j;
                found = true;
                break;
            }
        }
        EXPECT_TRUE(found) << "superblock payment not matched past index " << idx;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TRI-STATE superblock verdict (Triggered / NotTriggered / Unknown)
// Dash Core v24: FillBlockPayments adds superblock outputs only when
// IsSuperblockTriggered (masternode/payments.cpp:448-454); a synced validator
// with nothing triggered accepts a normal coinbase (payments.cpp:365-373).
// A wrong verdict either way is a rejected block, so the unfunded verdict is
// asserted only when PROVABLE: threshold known, R5 complete, nothing held
// aside (C2/C3), strict absence (C1).
// ═══════════════════════════════════════════════════════════════════════════
namespace {

constexpr int32_t TSH = 1'519'824;   // a testnet superblock height (cycle 24)

GovernanceTrigger mk_trig(uint64_t id, int32_t h, const char* amt = "5.0") {
    auto t = parse_superblock_trigger(
        trigger_json(h, "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", amt, kPropHash),
        hash_of(id), /*testnet=*/true);
    EXPECT_TRUE(t.has_value());
    return t ? *t : GovernanceTrigger{};
}

int64_t tbudget(int32_t h) { return superblock_budget(h, DASH_SUPERBLOCK_CYCLE_TESTNET); }

std::string trig_plain(int32_t h, const char* amt = "5.0") {
    return trigger_json(h, "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", amt, kPropHash);
}

CoinStateMaintainer::GovObjectContext trig_obj(uint64_t id, const std::string& plain) {
    CoinStateMaintainer::GovObjectContext o;
    o.object_hash = hash_of(id);
    o.object_type = GOVERNANCE_OBJECT_TRIGGER;
    o.vch_data    = plain_bytes(plain);
    return o;
}

CoinStateMaintainer::GovVoteContext fund_vote(const uint256& parent, int32_t outcome,
                                             int64_t t = 100) {
    CoinStateMaintainer::GovVoteContext v;
    v.parent_hash = parent;
    v.outcome     = outcome;
    v.signal      = VOTE_SIGNAL_FUNDING;
    v.time        = t;
    return v;
}

// Maintainer with the superblock ctx wired (cycle-24 predicate), a pinned
// threshold + weight seam, and an injected clock driving R5 to COMPLETE
// (two distinct peers, settled, quiesced). `now` must outlive `m`.
void arm_tristate(CoinStateMaintainer& m, int64_t& now, int threshold = 1) {
    m.set_now_fn([&now]() { return now; });
    m.set_gov_sync_params(/*min_peers=*/2, /*settle=*/60, /*quiesce=*/30);
    m.set_gov_params(/*testnet=*/true, DASH_GOV_MIN_QUORUM_TESTNET);
    m.set_superblock_ctx(
        [](uint32_t h) { return h % DASH_SUPERBLOCK_CYCLE_TESTNET == 0; },
        [](uint32_t h) { return superblock_budget(h, DASH_SUPERBLOCK_CYCLE_TESTNET); });
    m.gov_store().set_funding_threshold(threshold);
    m.gov_store().set_vote_weight_fn(weight_all_regular);
    m.note_govsync_requested("peerA");
    m.note_govsync_requested("peerB");
    now += 100;
    ASSERT_TRUE(m.gov_sync_complete());
}

} // namespace

// ── T1. every branch of the tri-state, store level ───────────────────────────
TEST(DashSuperblockTriState, EachVerdictBranch) {
    GovernanceStore s;
    // Threshold unknown => Unknown, whatever else holds.
    auto r = resolve_superblock_payments(s, TSH, tbudget(TSH), /*sync_complete=*/true);
    EXPECT_EQ(r.verdict, SuperblockVerdict::Unknown);
    EXPECT_EQ(r.reason, "trigger-threshold-unknown");

    s.set_funding_threshold(2);
    s.set_vote_weight_fn(weight_all_regular);
    // Empty store, R5 incomplete => Unknown (a missing trigger is not proof).
    r = resolve_superblock_payments(s, TSH, tbudget(TSH), false);
    EXPECT_EQ(r.verdict, SuperblockVerdict::Unknown);
    EXPECT_EQ(r.reason, "govsync-incomplete");
    // The optional view defaults sync_complete=false: never the unfunded verdict.
    EXPECT_FALSE(get_superblock_payments(s, TSH, tbudget(TSH)).has_value());

    // Empty store, R5 complete => NotTriggered => {} (normal coinbase).
    r = resolve_superblock_payments(s, TSH, tbudget(TSH), true);
    EXPECT_EQ(r.verdict, SuperblockVerdict::NotTriggered);
    EXPECT_EQ(r.reason, "not-triggered");
    auto ov = get_superblock_payments(s, TSH, tbudget(TSH), true);
    ASSERT_TRUE(ov.has_value());
    EXPECT_TRUE(ov->empty());

    // A funded trigger => Triggered => its schedule.
    ASSERT_TRUE(s.add_trigger(mk_trig(70, TSH)));
    s.add_verified_funding_vote(hash_of(70), "mn-1", VOTE_OUTCOME_YES, 1);
    s.add_verified_funding_vote(hash_of(70), "mn-2", VOTE_OUTCOME_YES, 1);
    r = resolve_superblock_payments(s, TSH, tbudget(TSH), true);
    ASSERT_EQ(r.verdict, SuperblockVerdict::Triggered);
    ASSERT_EQ(r.payments.size(), 1u);
    EXPECT_EQ(r.payments[0].script, kScriptYeRZ);
    EXPECT_EQ(r.payments[0].amount, 500'000'000LL);
    // A different superblock height is unaffected by it.
    EXPECT_EQ(resolve_superblock_payments(s, TSH + 24, tbudget(TSH + 24), true).verdict,
              SuperblockVerdict::NotTriggered);

    // Funded but over budget => Unknown, never paid (CSuperblock::IsValid).
    GovernanceStore ob;
    ob.set_funding_threshold(1);
    ob.set_vote_weight_fn(weight_all_regular);
    ASSERT_TRUE(ob.add_trigger(mk_trig(71, TSH, "1000.0")));
    ob.add_verified_funding_vote(hash_of(71), "mn-1", VOTE_OUTCOME_YES, 1);
    r = resolve_superblock_payments(ob, TSH, tbudget(TSH), true);
    EXPECT_EQ(r.verdict, SuperblockVerdict::Unknown);
    EXPECT_EQ(r.reason, "trigger-invalid-best");
    // An unknown (0) budget cap is never "no cap".
    r = resolve_superblock_payments(s, TSH, /*budget_cap=*/0, true);
    EXPECT_EQ(r.verdict, SuperblockVerdict::Unknown);
}

// ── T2. C1 strict absence: a sub-threshold trigger with any yes is AMBIGUOUS ──
TEST(DashSuperblockTriState, StrictAbsenceAmbiguityC1) {
    auto fresh = []() {
        GovernanceStore s;
        s.set_funding_threshold(5);
        s.set_vote_weight_fn([](const std::string& k) {
            return k.rfind("ghost", 0) == 0 ? 0 : DASH_VOTE_WEIGHT_REGULAR;
        });
        return s;
    };
    auto verdict = [](const GovernanceStore& s) {
        return resolve_superblock_payments(s, TSH, tbudget(TSH), true);
    };
    // A trigger at H with NO counted votes: nothing proves it voted down.
    {
        auto s = fresh();
        ASSERT_TRUE(s.add_trigger(mk_trig(72, TSH)));
        auto r = verdict(s);
        EXPECT_EQ(r.verdict, SuperblockVerdict::Unknown);
        EXPECT_EQ(r.reason, "trigger-ambiguous");
    }
    // Sub-threshold with yes votes (abs 2 < 5): AMBIGUOUS, not "unfunded".
    {
        auto s = fresh();
        ASSERT_TRUE(s.add_trigger(mk_trig(73, TSH)));
        s.add_verified_funding_vote(hash_of(73), "mn-1", VOTE_OUTCOME_YES, 1);
        s.add_verified_funding_vote(hash_of(73), "mn-2", VOTE_OUTCOME_YES, 1);
        EXPECT_EQ(verdict(s).reason, "trigger-ambiguous");
    }
    // abs-yes 0 (1 yes, 1 no): still a YES on record => ambiguous.
    {
        auto s = fresh();
        ASSERT_TRUE(s.add_trigger(mk_trig(74, TSH)));
        s.add_verified_funding_vote(hash_of(74), "mn-1", VOTE_OUTCOME_YES, 1);
        s.add_verified_funding_vote(hash_of(74), "mn-2", VOTE_OUTCOME_NO, 1);
        EXPECT_EQ(s.absolute_yes_count(hash_of(74)), 0);
        EXPECT_EQ(verdict(s).reason, "trigger-ambiguous");
    }
    // A YES from a voter our weight seam cannot resolve (weight 0) still counts
    // as a YES on record (raw) => ambiguous.
    {
        auto s = fresh();
        ASSERT_TRUE(s.add_trigger(mk_trig(75, TSH)));
        s.add_verified_funding_vote(hash_of(75), "ghost-1", VOTE_OUTCOME_YES, 1);
        s.add_verified_funding_vote(hash_of(75), "mn-2", VOTE_OUTCOME_NO, 1);
        EXPECT_EQ(s.absolute_yes_count(hash_of(75)), -1);
        EXPECT_EQ(verdict(s).reason, "trigger-ambiguous");
    }
    // POSITIVELY voted down (counted NO, zero YES): provably not triggered.
    {
        auto s = fresh();
        ASSERT_TRUE(s.add_trigger(mk_trig(76, TSH)));
        s.add_verified_funding_vote(hash_of(76), "mn-1", VOTE_OUTCOME_NO, 1);
        s.add_verified_funding_vote(hash_of(76), "mn-2", VOTE_OUTCOME_ABSTAIN, 1);
        EXPECT_EQ(verdict(s).verdict, SuperblockVerdict::NotTriggered);
        // ...but not while a vote on it is still unverifiable.
        s.note_unverifiable_vote(hash_of(76), "mn-3");
        EXPECT_EQ(verdict(s).reason, "trigger-unverified-votes");
        // a verified vote from that voter supersedes the unverifiable record
        s.add_verified_funding_vote(hash_of(76), "mn-3", VOTE_OUTCOME_NO, 2);
        EXPECT_EQ(verdict(s).verdict, SuperblockVerdict::NotTriggered);
    }
    // A trigger for ANOTHER height never blocks H.
    {
        auto s = fresh();
        ASSERT_TRUE(s.add_trigger(mk_trig(77, TSH + 24)));
        s.add_verified_funding_vote(hash_of(77), "mn-1", VOTE_OUTCOME_YES, 1);
        EXPECT_EQ(verdict(s).verdict, SuperblockVerdict::NotTriggered);
    }
    // An unverifiable vote blocks the TRIGGERED verdict as well: its weight
    // could put a competitor ahead of our winner.
    {
        auto s = fresh();
        s.set_funding_threshold(1);
        ASSERT_TRUE(s.add_trigger(mk_trig(78, TSH)));
        s.add_verified_funding_vote(hash_of(78), "mn-1", VOTE_OUTCOME_YES, 1);
        ASSERT_EQ(verdict(s).verdict, SuperblockVerdict::Triggered);
        ASSERT_TRUE(s.add_trigger(mk_trig(79, TSH, "4.0")));
        s.note_unverifiable_vote(hash_of(79), "mn-9");
        EXPECT_EQ(verdict(s).reason, "trigger-unverified-votes");
    }
}

// ── T3. C2/C3 outstanding objects block BOTH verdicts, and clear by cycle ────
TEST(DashSuperblockTriState, OutstandingObjectsBlockBothVerdicts) {
    GovernanceStore s;
    s.set_funding_threshold(1);
    s.set_vote_weight_fn(weight_all_regular);
    auto verdict = [&s](int32_t h) {
        return resolve_superblock_payments(s, h, tbudget(h), true);
    };
    ASSERT_EQ(verdict(TSH).verdict, SuperblockVerdict::NotTriggered);

    // Unparsed (unknown height): every height of the cycle is Unknown...
    s.note_outstanding(hash_of(90), GovOutstandingKind::Unparsed, 0);
    EXPECT_EQ(verdict(TSH).reason, "trigger-unparsed");
    EXPECT_EQ(verdict(TSH + 24).reason, "trigger-unparsed");
    // ...including a height our store holds a FUNDED trigger for.
    ASSERT_TRUE(s.add_trigger(mk_trig(91, TSH)));
    s.add_verified_funding_vote(hash_of(91), "mn-1", VOTE_OUTCOME_YES, 1);
    EXPECT_EQ(verdict(TSH).verdict, SuperblockVerdict::Unknown);
    // The superblock connects: the cycle's unknown-height records end.
    s.prune_cycle();
    EXPECT_EQ(verdict(TSH).verdict, SuperblockVerdict::Triggered);
    s.prune_executed(TSH);
    ASSERT_EQ(verdict(TSH + 24).verdict, SuperblockVerdict::NotTriggered);

    // Height-bound records (store full / pending) block only their height and
    // are pruned with it.
    s.note_outstanding(hash_of(92), GovOutstandingKind::StoreFull, TSH + 24);
    s.note_outstanding(hash_of(93), GovOutstandingKind::UnverifiedPending, TSH + 48);
    EXPECT_EQ(verdict(TSH + 24).reason, "trigger-store-full");
    EXPECT_EQ(verdict(TSH + 48).reason, "trigger-unverified-pending");
    EXPECT_EQ(verdict(TSH + 72).verdict, SuperblockVerdict::NotTriggered);
    s.prune_executed(TSH + 24);
    EXPECT_EQ(verdict(TSH + 24).verdict, SuperblockVerdict::NotTriggered);
    EXPECT_EQ(verdict(TSH + 48).reason, "trigger-unverified-pending");
    EXPECT_TRUE(s.is_erased(hash_of(92)));

    // Overflow of the outstanding ledger is itself a blocker.
    GovernanceStore o;
    o.set_funding_threshold(1);
    for (size_t i = 0; i <= GovernanceStore::MAX_OUTSTANDING; ++i)
        o.note_outstanding(hash_of(5000 + i), GovOutstandingKind::StoreFull, TSH + 2400);
    EXPECT_TRUE(o.outstanding_overflow());
    EXPECT_EQ(resolve_superblock_payments(o, TSH, tbudget(TSH), true).reason,
              "trigger-outstanding-overflow");
    o.prune_cycle();
    EXPECT_FALSE(o.outstanding_overflow());
}

// ── T4. dashd tie-break: memcmp order of the raw hash, not arithmetic ────────
TEST(DashSuperblockTriState, TieBreakFollowsDashdMemcmpOrder) {
    // a: low byte 0x02, nothing else  => arithmetically SMALL, memcmp LARGE
    // b: low byte 0x01, top byte 0x01 => arithmetically LARGE, memcmp SMALL
    uint256 a, b;
    a.data()[0] = 0x02;
    b.data()[0] = 0x01;
    b.data()[31] = 0x01;
    ASSERT_TRUE(a < b) << "fixture: arithmetic order";
    ASSERT_TRUE(gov_hash_less_dashd(b, a)) << "fixture: memcmp order";

    GovernanceStore s;
    s.set_funding_threshold(1);
    s.set_vote_weight_fn(weight_all_regular);
    auto ta = mk_trig(0, TSH, "1.0"); ta.object_hash = a;
    auto tb = mk_trig(0, TSH, "2.0"); tb.object_hash = b;
    ASSERT_TRUE(s.add_trigger(ta));
    ASSERT_TRUE(s.add_trigger(tb));
    s.add_verified_funding_vote(a, "mn-1", VOTE_OUTCOME_YES, 1);
    s.add_verified_funding_vote(b, "mn-2", VOTE_OUTCOME_YES, 1);
    auto best = s.get_best_superblock(TSH);
    ASSERT_TRUE(best.has_value());
    EXPECT_EQ(best->object_hash, b)
        << "dashd keeps the first max in std::map<uint256> (memcmp) order";
    EXPECT_EQ(best->payments[0].amount, 200'000'000LL);
}

// ── T5. govobject_signature_hash — CGovernanceObject::GetSignatureHash ───────
// Governance::Object serialized WITHOUT vchSig (Dash Core v24
// governance/common.h:73-87): hashParent, revision(i32), time(i64),
// collateralHash, vchData (compactsize + RAW bytes), type(i32), outpoint.
// Assembled independently here byte by byte; also distinct from the identity
// hash of the same object.
TEST(DashSuperblockTriState, GovObjectSignatureHashPreimage) {
    const uint256 parent;                       // root object
    const uint256 collateral;                   // triggers carry no fee tx
    const uint256 op_hash = uint256_from_rpc_hex(
        "4ee3ff5074723d995f4cb957a954587c6c637a42655ada8f4054037b28d1e7a8");
    const uint32_t op_index = 95;
    const std::string json = trig_plain(TSH);
    const auto data = plain_bytes(json);
    const int64_t t = 1784232979;

    std::vector<unsigned char> pre;
    auto put = [&pre](const void* p, size_t n) {
        const auto* c = static_cast<const unsigned char*>(p);
        pre.insert(pre.end(), c, c + n);
    };
    auto le32 = [&put](uint32_t v) {
        unsigned char b[4] = {static_cast<unsigned char>(v), static_cast<unsigned char>(v >> 8),
                              static_cast<unsigned char>(v >> 16), static_cast<unsigned char>(v >> 24)};
        put(b, 4);
    };
    put(parent.data(), 32);
    le32(1);                                                       // revision
    le32(static_cast<uint32_t>(t)); le32(static_cast<uint32_t>(static_cast<uint64_t>(t) >> 32));
    put(collateral.data(), 32);
    ASSERT_LT(data.size(), 253u);
    pre.push_back(static_cast<unsigned char>(data.size()));       // compactsize
    put(data.data(), data.size());                                 // RAW, not hex
    le32(static_cast<uint32_t>(GOVERNANCE_OBJECT_TRIGGER));        // type
    put(op_hash.data(), 32);
    le32(op_index);
    const uint256 want = ::Hash(std::span<const unsigned char>(pre.data(), pre.size()));

    const uint256 got = govobject_signature_hash(parent, 1, t, collateral, data,
                                                 GOVERNANCE_OBJECT_TRIGGER, op_hash, op_index);
    EXPECT_EQ(got, want);
    EXPECT_NE(got, govobject_hash(parent, 1, t, data, op_hash, op_index, {}))
        << "the signing digest is not the identity hash";
    // Every signed field moves it.
    EXPECT_NE(got, govobject_signature_hash(parent, 2, t, collateral, data,
                                            GOVERNANCE_OBJECT_TRIGGER, op_hash, op_index));
    EXPECT_NE(got, govobject_signature_hash(parent, 1, t, collateral, data,
                                            GOVERNANCE_OBJECT_PROPOSAL, op_hash, op_index));
    EXPECT_NE(got, govobject_signature_hash(parent, 1, t, collateral, data,
                                            GOVERNANCE_OBJECT_TRIGGER, op_hash, op_index + 1));
}

// ── T6. maintainer: NotTriggered serves a normal coinbase end to end ─────────
TEST(DashSuperblockTriState, ProvenUnfundedHeightServesNormalCoinbase) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int64_t now = 1'700'000'000;
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    m.on_new_tip(SBH - 1, raw256(0xAB), 0x1e0ffff0u, 1'700'000'000u,
                 140, 19, 1'700'000'100u, 0x20000000u);
    ASSERT_TRUE(m.live());
    arm_tristate(m, now);

    st.set_is_superblock_fn([](uint32_t h) { return h == SBH; });
    st.set_superblock_resolver([&m](uint32_t h) { return m.superblock_resolution(h); });
    st.set_require_superblock_provider(true);
    st.set_superblock_sync_complete_fn([&m]() { return m.gov_sync_complete(); });

    auto e = st.make_embedded_work_inputs();
    ASSERT_TRUE(e.viable()) << "a PROVEN unfunded superblock height must serve: "
                            << st.describe_decline().value;
    EXPECT_TRUE(e.superblock_payments.empty()) << "normal coinbase, no treasury outputs";
    EXPECT_EQ(m.gov_not_triggered_served_height(), SBH);

    // A trigger for H shows up (no votes yet) => no longer provable => refuse,
    // and the decline names the gate.
    m.gov_store().add_trigger(mk_trig(80, static_cast<int32_t>(SBH)));
    auto d = st.describe_decline();
    EXPECT_FALSE(d.viable);
    EXPECT_EQ(d.cause, "superblock-refused");
    EXPECT_EQ(d.value, "trigger-ambiguous");
}

// ── T7. C2 at the maintainer: signed-but-unparseable / store-full recorded ───
TEST(DashSuperblockTriState, MaintainerRecordsUnparsedAndStoreFullC2) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int64_t now = 1'700'000'000;
    arm_tristate(m, now);
    m.set_object_verifier([](const CoinStateMaintainer::GovObjectContext&) {
        return CoinStateMaintainer::GovSigCheck::Valid;
    });
    ASSERT_EQ(m.superblock_resolution(SBH).verdict, SuperblockVerdict::NotTriggered);

    // A masternode-signed TRIGGER our parser rejects (here: the legacy nested
    // form dashd still unwraps): NotTriggered becomes impossible this cycle.
    m.on_govobject(trig_obj(81, "[[\"trigger\"," + trig_plain(static_cast<int32_t>(SBH)) + "]]"));
    now += 100;   // let R5 re-quiesce: the refusal must come from the record
    ASSERT_TRUE(m.gov_sync_complete());
    EXPECT_EQ(m.gov_store().trigger_count(), 0u);
    EXPECT_EQ(m.superblock_resolution(SBH).reason, "trigger-unparsed");
    EXPECT_EQ(m.superblock_resolution(SBH + 24).reason, "trigger-unparsed");

    // Store full: the 65th distinct trigger is recorded, not silently dropped.
    NodeCoinState st2;
    CoinStateMaintainer m2(st2);
    int64_t now2 = 1'700'000'000;
    arm_tristate(m2, now2);
    m2.set_object_verifier([](const CoinStateMaintainer::GovObjectContext&) {
        return CoinStateMaintainer::GovSigCheck::Valid;
    });
    for (size_t i = 0; i < GovernanceStore::MAX_TRIGGERS; ++i)
        ASSERT_TRUE(m2.gov_store().add_trigger(mk_trig(6000 + i, static_cast<int32_t>(SBH) + 240)));
    m2.on_govobject(trig_obj(82, trig_plain(static_cast<int32_t>(SBH))));
    now2 += 100;
    EXPECT_FALSE(m2.gov_store().has_trigger(hash_of(82)));
    EXPECT_EQ(m2.superblock_resolution(SBH).reason, "trigger-store-full");
}

// ── T8. C3: the masternode signature gates admission ────────────────────────
TEST(DashSuperblockTriState, MaintainerSignatureGateC3) {
    using Sig = CoinStateMaintainer::GovSigCheck;
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int64_t now = 1'700'000'000;
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    m.on_new_tip(SBH - 3, raw256(0xAB), 0x1e0ffff0u, 1'700'000'000u,
                 140, 19, 1'700'000'100u, 0x20000000u);
    arm_tristate(m, now);
    Sig answer = Sig::Invalid;
    m.set_object_verifier([&answer](const CoinStateMaintainer::GovObjectContext&) {
        return answer;
    });

    // A forged trigger (bad signature) is dropped exactly like dashd drops it:
    // not stored, not recorded — a forgery can neither win nor block the
    // unfunded verdict.
    for (uint64_t i = 0; i < 100; ++i)
        m.on_govobject(trig_obj(7000 + i, trig_plain(static_cast<int32_t>(SBH))));
    now += 100;
    EXPECT_EQ(m.gov_store().trigger_count(), 0u);
    EXPECT_EQ(m.gov_store().outstanding_count(), 0u);
    EXPECT_EQ(m.gov_triggers_rejected(), 100u);
    EXPECT_EQ(m.superblock_resolution(SBH).verdict, SuperblockVerdict::NotTriggered);

    // Not yet verifiable (signer outside a current DMN view): held aside,
    // never stored, and its height is Unknown.
    answer = Sig::CannotVerify;
    m.on_govobject(trig_obj(83, trig_plain(static_cast<int32_t>(SBH))));
    now += 100;
    EXPECT_EQ(m.gov_store().trigger_count(), 0u);
    EXPECT_EQ(m.gov_pending_objects(), 1u);
    EXPECT_EQ(m.superblock_resolution(SBH).reason, "trigger-unverified-pending");

    // The view catches up: the next connected block retries and admits it.
    answer = Sig::Valid;
    BlockType blk;
    blk.m_txs.push_back(make_cb(500'000'000, p2pkh_script(0x30)));
    bind_block(blk);
    m.on_block_connected(blk, SBH - 2);
    EXPECT_TRUE(m.gov_store().has_trigger(hash_of(83)));
    EXPECT_EQ(m.gov_pending_objects(), 0u);
    EXPECT_EQ(m.gov_store().outstanding_count(), 0u);
    // A stored trigger with no votes: ambiguous (C1), never "unfunded".
    EXPECT_EQ(m.superblock_resolution(SBH).reason, "trigger-ambiguous");

    // Unset verifier (production default before wiring): CannotVerify, never stored.
    NodeCoinState st2;
    CoinStateMaintainer m2(st2);
    int64_t now2 = 1'700'000'000;
    arm_tristate(m2, now2);
    m2.on_govobject(trig_obj(84, trig_plain(static_cast<int32_t>(SBH))));
    EXPECT_EQ(m2.gov_store().trigger_count(), 0u);
    EXPECT_EQ(m2.gov_store().outstanding_count(), 1u);
}

// ── T9. C4: per-trigger vote re-sync at H - window and H - 1; orphans ────────
TEST(DashSuperblockTriState, MaintainerVoteResyncAndOrphansC4) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int64_t now = 1'700'000'000;
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    m.on_new_tip(SBH - 10, raw256(0xAB), 0x1e0ffff0u, 1'700'000'000u,
                 140, 19, 1'700'000'100u, 0x20000000u);
    arm_tristate(m, now);
    m.set_superblock_maturity_window(DASH_SUPERBLOCK_MATURITY_WINDOW_TESTNET);
    std::vector<uint256> resync, fetched;
    m.set_on_trigger_vote_resync([&resync](const uint256& h) { resync.push_back(h); });
    m.set_on_gov_object_fetch([&fetched](const uint256& h) { fetched.push_back(h); });
    m.set_object_verifier([](const CoinStateMaintainer::GovObjectContext&) {
        return CoinStateMaintainer::GovSigCheck::Valid;
    });
    m.set_vote_verifier([](const CoinStateMaintainer::GovVoteContext&) { return true; });

    // ORPHAN: a funding YES arrives before its trigger. dashd keeps it; so do
    // we, and the unfunded verdict is unprovable until the parent lands.
    m.on_govvote(fund_vote(hash_of(85), VOTE_OUTCOME_YES), "mn-1");
    now += 100;
    EXPECT_EQ(m.gov_orphan_votes(), 1u);
    EXPECT_EQ(m.superblock_resolution(SBH).reason, "trigger-orphan-votes");
    ASSERT_EQ(fetched.size(), 1u);
    EXPECT_EQ(fetched[0], hash_of(85)) << "the missing parent is fetched";
    // A vote on a known PROPOSAL is never an orphan.
    m.on_govobject(hash_of(86), GOVERNANCE_OBJECT_PROPOSAL, plain_bytes("{}"));
    m.on_govvote(fund_vote(hash_of(86), VOTE_OUTCOME_YES), "mn-1");
    EXPECT_EQ(m.gov_orphan_votes(), 1u);

    // The parent arrives later: its buffered vote is tallied without any
    // re-download (the inv dedup cannot starve it).
    m.on_govobject(trig_obj(85, trig_plain(static_cast<int32_t>(SBH))));
    now += 100;
    EXPECT_EQ(m.gov_orphan_votes(), 0u);
    EXPECT_EQ(m.gov_store().absolute_yes_count(hash_of(85)), 1);
    auto r = m.superblock_resolution(SBH);
    ASSERT_EQ(r.verdict, SuperblockVerdict::Triggered) << r.reason;

    // C4 legs: tip H - window and H - 1 re-request the held trigger's votes,
    // nothing in between, never a full sync.
    auto connect = [&m](uint32_t h) {
        BlockType blk;
        blk.m_txs.push_back(make_cb(500'000'000, p2pkh_script(0x30)));
        bind_block(blk);
        m.on_block_connected(blk, h);
    };
    for (uint32_t h = SBH - 9; h <= SBH - 1; ++h) {
        connect(h);
        const size_t want =
            h < SBH - DASH_SUPERBLOCK_MATURITY_WINDOW_TESTNET ? 0u
            : h < SBH - 1                                     ? 1u
                                                              : 2u;
        ASSERT_EQ(resync.size(), want) << "after connecting h=" << h;
    }
    EXPECT_EQ(resync[0], hash_of(85));
    EXPECT_EQ(resync[1], hash_of(85));
}

// ── T10. executed triggers are history: never stored, pruned every block ─────
TEST(DashSuperblockTriState, ExecutedTriggerIsHistoryAndPruned) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int64_t now = 1'700'000'000;
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)));
    // Restart AFTER the superblock at SBH executed (mainnet tenant: the
    // executed 2558864 trigger re-synced and sat in the store).
    m.on_new_tip(SBH + 5, raw256(0xAB), 0x1e0ffff0u, 1'700'000'000u,
                 140, 19, 1'700'000'100u, 0x20000000u);
    arm_tristate(m, now);
    m.set_object_verifier([](const CoinStateMaintainer::GovObjectContext&) {
        return CoinStateMaintainer::GovSigCheck::Valid;
    });
    m.set_vote_verifier([](const CoinStateMaintainer::GovVoteContext&) { return true; });
    m.on_govobject(trig_obj(87, trig_plain(static_cast<int32_t>(SBH))));
    EXPECT_EQ(m.gov_store().trigger_count(), 0u) << "an executed trigger is not stored";
    EXPECT_TRUE(m.gov_store().is_erased(hash_of(87)));
    // Its re-synced votes are history too: no orphan, no blocker.
    m.on_govvote(fund_vote(hash_of(87), VOTE_OUTCOME_YES), "mn-1");
    EXPECT_EQ(m.gov_orphan_votes(), 0u);
    EXPECT_EQ(m.gov_store().outstanding_count(), 0u);

    // A trigger held for SBH+24 is pruned by the first block past it, even a
    // NON-superblock block (the restart case never crosses H itself).
    ASSERT_TRUE(m.gov_store().add_trigger(mk_trig(88, static_cast<int32_t>(SBH) + 24)));
    BlockType blk;
    blk.m_txs.push_back(make_cb(500'000'000, p2pkh_script(0x30)));
    bind_block(blk);
    m.on_block_connected(blk, SBH + 25);
    EXPECT_EQ(m.gov_store().trigger_count(), 0u);
    EXPECT_TRUE(m.gov_store().is_erased(hash_of(88)));
}

// ── T11. C5 reverse R6: the network paid a superblock we called absent ──────
// A not-triggered superblock height's coinbase is capped at subsidy + fees
// (dashd payments.cpp:365-373). Fee-free ceiling from the coinbase's OWN
// masternode payment: R = GetMasternodePayment(h, subsidy + fees) =
// (subsidy + fees) * 3 / 4, paid as [platform OP_RETURN P] + MN outputs
// (payments.cpp:131-199), so subsidy + fees <= (4R + 3) / 3.
namespace {
constexpr uint32_t SBH2 = 2'160'000;   // cycle-24 multiple, past mainnet MN_RR (P > 0)

struct C5Rig {
    NodeCoinState st;
    CoinStateMaintainer m{st};
    int64_t now{1'700'000'000};
    int64_t P{0};
    explicit C5Rig() {
        m.on_mn_list_update(single_mn(p2pkh_script(0x30)), /*as_of_height=*/SBH2 - 1);
        m.on_new_tip(SBH2 - 1, raw256(0xAB), 0x1e0ffff0u, 1'700'000'000u,
                     140, 19, 1'700'000'100u, 0x20000000u);
        arm_tristate(m, now);
        P = compute_dash_platform_reward_post_v20_mn_rr(SBH2, st.mn_rr_height());
    }
    // [miner, OP_RETURN P, MN (R - P)] (+ extra)
    BlockType block(int64_t miner, int64_t R,
                    const std::vector<std::pair<int64_t, std::vector<unsigned char>>>& extra = {},
                    bool with_platform = true) {
        BlockType blk;
        auto cb = make_cb(miner, p2pkh_script(0x40));
        ::bitcoin_family::coin::TxOut o;
        if (with_platform) {
            o.value = P;
            o.scriptPubKey.m_data = {0x6a};
            cb.vout.push_back(o);
        }
        o.value = R - P;
        o.scriptPubKey.m_data = p2pkh_script(0x30);
        cb.vout.push_back(o);
        for (const auto& [v, s] : extra) {
            o.value = v;
            o.scriptPubKey.m_data = s;
            cb.vout.push_back(o);
        }
        blk.m_txs.push_back(cb);
        bind_block(blk);
        return blk;
    }
};
} // namespace

TEST(DashSuperblockTriState, ReverseCheckConfirmsUnfundedCoinbaseC5) {
    C5Rig rig;
    ASSERT_GT(rig.P, 0);
    ASSERT_EQ(rig.m.superblock_resolution(SBH2).verdict, SuperblockVerdict::NotTriggered);
    // R = 3e9 => block value <= 4e9 + 1. Miner 1e9 => total 4e9: a normal block.
    rig.m.on_block_connected(rig.block(1'000'000'000, 3'000'000'000LL), SBH2);
    EXPECT_FALSE(rig.m.gov_desync_latched()) << rig.m.gov_desync_reason();
}

TEST(DashSuperblockTriState, ReverseCheckLatchesOnPaidSuperblockC5) {
    C5Rig rig;
    ASSERT_EQ(rig.m.superblock_resolution(SBH2).verdict, SuperblockVerdict::NotTriggered);
    // Same block plus a 5 DASH treasury output: total 4.5e9 > ceiling.
    rig.m.on_block_connected(
        rig.block(1'000'000'000, 3'000'000'000LL,
                  {{500'000'000, std::vector<unsigned char>(kScriptYeRZ.begin(), kScriptYeRZ.end())}}),
        SBH2);
    EXPECT_TRUE(rig.m.gov_desync_latched());
    EXPECT_NE(rig.m.gov_desync_reason().find("paid a superblock"), std::string::npos)
        << rig.m.gov_desync_reason();
    // Fail closed for every later cycle.
    EXPECT_EQ(rig.m.superblock_resolution(SBH2 + 24).reason, "trigger-latched");
}

TEST(DashSuperblockTriState, ReverseCheckLatchesWhenUnprovableC5) {
    C5Rig rig;
    // No platform OP_RETURN: the masternode payment cannot be re-derived, so
    // nothing proves the coinbase superblock-free => latch (fail closed).
    rig.m.on_block_connected(rig.block(1'000'000'000, 3'000'000'000LL, {}, false), SBH2);
    EXPECT_TRUE(rig.m.gov_desync_latched());
    EXPECT_NE(rig.m.gov_desync_reason().find("could not be proven"), std::string::npos)
        << rig.m.gov_desync_reason();
}

TEST(DashSuperblockTriState, ReverseCheckSkippedWhenNeverServableC5) {
    // R5 never completed and the unfunded verdict was never handed out: the
    // structural view is not evidence of anything we served — no latch.
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.on_mn_list_update(single_mn(p2pkh_script(0x30)), SBH2 - 1);
    m.on_new_tip(SBH2 - 1, raw256(0xAB), 0x1e0ffff0u, 1'700'000'000u,
                 140, 19, 1'700'000'100u, 0x20000000u);
    m.set_gov_params(true, DASH_GOV_MIN_QUORUM_TESTNET);
    m.set_superblock_ctx([](uint32_t h) { return h % 24 == 0; },
                         [](uint32_t h) { return superblock_budget(h, 24); });
    m.gov_store().set_funding_threshold(1);
    BlockType blk;
    auto cb = make_cb(4'500'000'000LL, p2pkh_script(0x40));
    blk.m_txs.push_back(cb);
    bind_block(blk);
    m.on_block_connected(blk, SBH2);
    EXPECT_FALSE(m.gov_desync_latched());
}
