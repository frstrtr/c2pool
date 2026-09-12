// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT-gated correctness tests for the M3-A-DASH special-tx core (design §4.1.1
// governance-collateral builder + §4.1.2 message sign/verify).
//
// Money-correctness discipline: the gobject collateral hash is asserted against
// LIVE MAINNET vectors (and, via the ctest gov_hash_python_oracle, against the
// proven Python reference). The signed collateral tx is emitted only through
// the M3-A signer's self-verify-every-input + oversize gate, so a construct→emit
// is a full interpreter re-execution. The message signature is self-verified by
// public-key recovery. Funding-address mismatch and the SPEND gate are asserted
// to hard-abort.
//
// This TU includes ONLY the std-only module headers — no dashscript / btclibs
// header leaks — so it stays clear of the two vendored crypto trees.

#include "../CollateralTx.hpp"
#include "../DashAddress.hpp"
#include "../DashError.hpp"
#include "../DashMessage.hpp"
#include "../GovCollateral.hpp"
#include "../KeyScan.hpp"

#include "gov_vectors.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace c2w::dash;
using c2w::secure::SecureBytes;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                                                    \
    do {                                                                                    \
        if (cond) { ++g_pass; }                                                             \
        else { ++g_fail; std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); }   \
    } while (0)

template <typename F>
static bool aborts(F&& fn)
{
    try { fn(); return false; }
    catch (const DashAbort&) { return true; }
    catch (...) { return false; }
}

// ── local hex helpers (independent of any vendored closure) ─────────────────
static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static std::vector<uint8_t> H(const std::string& s)
{
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back((uint8_t)((hexval(s[i]) << 4) | hexval(s[i + 1])));
    return out;
}
static std::string hexstr(const std::vector<uint8_t>& v)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    for (uint8_t b : v) { s.push_back(d[b >> 4]); s.push_back(d[b & 15]); }
    return s;
}

// The public BIP39 test mnemonic — no real key anywhere in this suite.
static const std::string DUMMY_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";

// DASH m/44'/5'/0'/0/{0,1,2} for the dummy mnemonic (from the reference suite).
static const char* DUMMY_ADDR0 = "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5";
static const char* DUMMY_ADDR1 = "XbctnEsgWTn5j1co3emZynemxSFPqkLRKZ";
static const char* DUMMY_ADDR2 = "XdD2biTJ3saZtcR6ravwJ9bvmkvmDq49Xg";
// A public third-party mainnet address NOT derivable from the dummy mnemonic.
static const char* NOT_OURS = "XtKASJb13xrNEyi35bDP4rWgD4mJb6sM2d";

// ── a tiny legacy-tx output parser, to prove out0 = 1 DASH OP_RETURN <hash> ──
struct ParsedOut { int64_t value; std::vector<uint8_t> script; };
static std::vector<ParsedOut> parse_outputs(const std::vector<uint8_t>& raw)
{
    size_t off = 0;
    auto rd = [&](int n) { uint64_t v = 0; for (int i = 0; i < n; ++i) v |= (uint64_t)raw[off++] << (8 * i); return v; };
    auto cs = [&]() -> uint64_t { uint8_t b0 = raw[off++]; if (b0 < 0xFD) return b0; if (b0 == 0xFD) return rd(2); if (b0 == 0xFE) return rd(4); return rd(8); };
    off += 4; // version
    uint64_t nin = cs();
    for (uint64_t i = 0; i < nin; ++i) { off += 36; uint64_t sl = cs(); off += sl; off += 4; }
    uint64_t nout = cs();
    std::vector<ParsedOut> outs;
    for (uint64_t i = 0; i < nout; ++i) {
        ParsedOut o;
        o.value = (int64_t)rd(8);
        uint64_t sl = cs();
        o.script.assign(raw.begin() + off, raw.begin() + off + sl);
        off += sl;
        outs.push_back(o);
    }
    return outs;
}

static void test_gov_hash()
{
    std::printf("[gov collateral hash — live mainnet KATs]\n");
    for (int i = 0; i < testvec::kNumGovVectors; ++i) {
        const auto& v = testvec::kMainnetGovVectors[i];
        auto internal = gov_object_hash(std::string(64, '0'), 1, v.time_, v.data_hex);
        CHECK(gov_hash_display(internal) == v.expected_display, "mainnet gobject hash matches");
    }
    // On-chain OP_RETURN byte-order proof for object 0.
    const auto& v0 = testvec::kMainnetGovVectors[0];
    auto internal0 = gov_object_hash(std::string(64, '0'), 1, v0.time_, v0.data_hex);
    auto script = collateral_op_return_script(internal0);
    CHECK(hexstr(script) == std::string(testvec::kVector0OpReturnScript), "OP_RETURN script == on-chain bytes");
    CHECK(script.size() == 34 && script[0] == 0x6A && script[1] == 0x20, "OP_RETURN framing 6a20 + 32");

    // sensitivity + validation
    CHECK(gov_hash_display(gov_object_hash(std::string(64, '0'), 1, v0.time_ + 1, v0.data_hex)) != v0.expected_display, "time sensitivity");
    CHECK(gov_hash_display(gov_object_hash(std::string(64, '0'), 2, v0.time_, v0.data_hex)) != v0.expected_display, "revision sensitivity");
    CHECK(aborts([&] { gov_object_hash(std::string(64, '0'), 1, v0.time_, "zz"); }), "bad data-hex aborts");
    CHECK(aborts([&] { gov_object_hash(std::string(60, '0'), 1, v0.time_, "aa"); }), "short parent aborts");
}

static void test_address()
{
    std::printf("[DASH P2PKH address plumbing]\n");
    auto h = addr_to_h160(DUMMY_ADDR0, false);
    CHECK(hexstr(std::vector<uint8_t>(h.begin(), h.end())) == "8a4f58c222cd5544c527bc66925652baa70b5e80", "addr_to_h160");
    CHECK(h160_to_addr(h, false) == DUMMY_ADDR0, "h160_to_addr roundtrip");
    auto spk = p2pkh_script(h);
    CHECK(hexstr(std::vector<uint8_t>(spk.begin(), spk.end())) == "76a9148a4f58c222cd5544c527bc66925652baa70b5e8088ac", "p2pkh scriptPubKey");
    CHECK(aborts([&] { addr_to_h160(DUMMY_ADDR0, true); }), "wrong-network aborts");
    std::string corrupt = DUMMY_ADDR0; corrupt.back() = (corrupt.back() == '5' ? '6' : '5');
    CHECK(aborts([&] { addr_to_h160(corrupt, false); }), "bad checksum aborts");
}

static void test_key_scan()
{
    std::printf("[funding-key scan m/44'/5'/0'/{0,1}/i]\n");
    FoundKey k0 = find_key_for_address(DUMMY_MNEMONIC, "", DUMMY_ADDR0, false, 0, 3, false);
    CHECK(k0.path == "m/44'/5'/0'/0/0", "found index 0 at expected path");
    CHECK(k0.address == DUMMY_ADDR0, "found address matches");
    CHECK(k0.priv.size() == 32 && k0.pub.size() == 33, "priv 32 / pub 33");

    FoundKey k2 = find_key_for_address(DUMMY_MNEMONIC, "", DUMMY_ADDR2, false, 0, 5, false);
    CHECK(k2.path == "m/44'/5'/0'/0/2", "found index 2 at expected path");

    CHECK(aborts([&] { find_key_for_address(DUMMY_MNEMONIC, "", NOT_OURS, false, 0, 50, true); }), "absent address hard-aborts");
    CHECK(aborts([&] { find_key_for_address(DUMMY_MNEMONIC, "wrong-pass", DUMMY_ADDR0, false, 0, 5, false); }), "passphrase change hard-aborts");
    std::string bad = DUMMY_MNEMONIC; // break the checksum: last word about->abandon
    bad.replace(bad.rfind("about"), 5, "abandon");
    CHECK(aborts([&] { find_key_for_address(bad, "", DUMMY_ADDR0, false, 0, 1, false); }), "bad BIP39 checksum hard-aborts");
}

static CollateralRequest make_request(const char* funding)
{
    const auto& v0 = testvec::kMainnetGovVectors[0];
    CollateralRequest req;
    req.funding_address = funding;
    req.time_ = v0.time_;
    req.data_hex = v0.data_hex;
    req.testnet = false;
    // Two mature UTXOs paying the funding P2PKH (script set so normalize checks it).
    auto h = addr_to_h160(funding, false);
    auto spk = p2pkh_script(h);
    std::string spk_hex = hexstr(std::vector<uint8_t>(spk.begin(), spk.end()));
    req.utxos.push_back({std::string(64, 'a'), 1, 70000000, 200, spk_hex});
    req.utxos.push_back({std::string(64, 'b'), 0, 40000000, 200, spk_hex});
    return req;
}

static void test_collateral_tx()
{
    std::printf("[collateral tx build + sign + self-verify]\n");
    const auto& v0 = testvec::kMainnetGovVectors[0];

    CollateralRequest req = make_request(DUMMY_ADDR0);
    CollateralPlan plan = plan_collateral(req);
    CHECK(plan.gov_hash_display == v0.expected_display, "plan collateral hash matches mainnet");
    CHECK(hexstr(plan.op_return_script) == std::string(testvec::kVector0OpReturnScript), "plan OP_RETURN == on-chain");
    CHECK(plan.total_in == 110000000, "total in = 1.1 DASH");
    CHECK(plan.change > 0 && plan.fee >= 1000, "has change + a fee");
    CHECK(!plan.summary.empty(), "dry-run summary produced");

    FoundKey key = find_key_for_address(DUMMY_MNEMONIC, "", DUMMY_ADDR0, false, 0, 3, false);

    // SPEND gate: confirm_spend=false must refuse.
    CHECK(aborts([&] { sign_collateral(plan, key, false); }), "SPEND gate: confirm_spend=false hard-aborts");

    // Funding-address mismatch: a key for a different address must hard-abort.
    FoundKey wrong = find_key_for_address(DUMMY_MNEMONIC, "", DUMMY_ADDR1, false, 0, 3, false);
    CHECK(aborts([&] { sign_collateral(plan, wrong, true); }), "funding-address mismatch hard-aborts");

    // Sign for real (dummy key): every input self-verifies through the vendored
    // interpreter, else finalize would have aborted before emit.
    SignedTx tx = sign_collateral(plan, key, true);
    CHECK(!tx.hex.empty() && tx.txid.size() == 64, "signed tx + txid emitted (self-verify passed)");

    auto raw = H(tx.hex);
    auto outs = parse_outputs(raw);
    CHECK(outs.size() == 2, "two outputs");
    CHECK(outs[0].value == 100000000, "out0 value = 1.00000000 DASH");
    CHECK(hexstr(outs[0].script) == std::string(testvec::kVector0OpReturnScript), "out0 = OP_RETURN <collateral hash>");
    CHECK(outs[1].script.size() == 25 && outs[1].script[0] == 0x76, "out1 = P2PKH change");
    CHECK(outs[0].value + outs[1].value + plan.fee == plan.total_in, "value conservation");

    // Foreign UTXO scriptPubKey must be rejected at plan time.
    CollateralRequest foreign = make_request(DUMMY_ADDR0);
    foreign.utxos[0].script_pubkey_hex = "76a914" + std::string(40, '1') + "88ac";
    CHECK(aborts([&] { plan_collateral(foreign); }), "foreign UTXO scriptPubKey hard-aborts");

    // --expected-hash cross-check mismatch aborts.
    CollateralRequest badexp = make_request(DUMMY_ADDR0);
    badexp.expected_hash_display = std::string(64, '0');
    CHECK(aborts([&] { plan_collateral(badexp); }), "expected-hash mismatch hard-aborts");
}

static void test_message()
{
    std::printf("[message sign / verify — DarkCoin magic, recover-and-check]\n");
    FoundKey key = find_key_for_address(DUMMY_MNEMONIC, "", DUMMY_ADDR0, false, 0, 3, false);
    const std::string msg = "c2wallet-qt dash proposal-ownership test";

    std::string sig = sign_message(key.priv, msg, DUMMY_ADDR0, false);
    CHECK(!sig.empty(), "signature produced");
    CHECK(verify_message(DUMMY_ADDR0, msg, sig, false), "sign->verify roundtrip (recovers to address)");

    // RFC6979 determinism.
    std::string sig2 = sign_message(key.priv, msg, DUMMY_ADDR0, false);
    CHECK(sig == sig2, "recoverable signing is deterministic");

    // Tampered message / wrong address / tampered sig all fail.
    CHECK(!verify_message(DUMMY_ADDR0, msg + "!", sig, false), "tampered message fails");
    CHECK(!verify_message(DUMMY_ADDR1, msg, sig, false), "wrong claimed address fails");
    std::string bad = sig;
    bad[0] = (bad[0] == 'A' ? 'B' : 'A'); // corrupt the leading base64 char
    CHECK(!verify_message(DUMMY_ADDR0, msg, bad, false), "tampered signature fails");

    // Self-verify gate: signing while claiming the WRONG address must hard-abort
    // (the recovered pubkey hashes to ADDR0, not ADDR1).
    CHECK(aborts([&] { sign_message(key.priv, msg, DUMMY_ADDR1, false); }), "self-verify gate: wrong address hard-aborts");
}

int main(int argc, char** argv)
{
    // Oracle hook: emit the gobject display hashes for the fixed mainnet vectors
    // so proto_hash_oracle.py can compare the C++ port to the proven Python.
    if (argc >= 2 && std::strcmp(argv[1], "--emit-gov-hashes") == 0) {
        for (int i = 0; i < testvec::kNumGovVectors; ++i) {
            const auto& v = testvec::kMainnetGovVectors[i];
            auto internal = gov_object_hash(std::string(64, '0'), 1, v.time_, v.data_hex);
            std::printf("%s\n", gov_hash_display(internal).c_str());
        }
        return 0;
    }

    std::printf("=== c2wallet-qt M3-A-DASH KATs ===\n");
    test_gov_hash();
    test_address();
    test_key_scan();
    test_collateral_tx();
    test_message();

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
