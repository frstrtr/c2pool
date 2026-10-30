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
#include "../DashInjectModel.hpp"
#include "../InjectManifest.hpp"
#include "../DashError.hpp"
#include "../DashMessage.hpp"
#include "../GovCollateral.hpp"
#include "../InjectCaps.hpp"
#include "../KeyScan.hpp"
#include "../SweepTx.hpp"
#include "../UtxoIntake.hpp"

// std-only M5-A artifact headers: the loader-file format the inject KATs check
// the emitted file against.
#include "../../artifact/Digest.hpp"
#include "../../artifact/TransferContainer.hpp"
#include "../../artifact/TxIntrospect.hpp"

// std-only hdkeys headers: the BIP38 overload, a WIF decode for the S2-K9 grep,
// and the JSON reader the S2-K7 manifest round trip uses.
#include "../../hdkeys/Bip38.hpp"
#include "../../hdkeys/KeyImport.hpp"
#include "../../hdkeys/MiniJson.hpp"

#include "gov_vectors.hpp"
#include "inject_vectors.hpp"
#include "s2_vectors.hpp"

#include <algorithm>
#include <climits>
#include <cstdint>
#include <exception>
#include <initializer_list>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
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

// ═══════════════════════════════════════════════════════════════════════════
// Zero-fee INJECT builders (FeeMode::InjectOnlyZeroFee, SweepTx, UtxoIntake,
// KeyScanRange) — KATs K1..K13 of the inject design. K11 (the node-cap
// tripwire) is a set of static_asserts in test/test_dash_tx_inject.cpp.
// ═══════════════════════════════════════════════════════════════════════════

template <typename F>
static bool aborts_with(F&& fn, const char* needle)
{
    try { fn(); return false; }
    catch (const DashAbort& e) {
        if (std::strstr(e.what(), needle)) return true;
        std::printf("    (aborted, but with: %s)\n", e.what());
        return false;
    }
    catch (...) { return false; }
}

static bool contains(const std::string& hay, const char* needle) { return hay.find(needle) != std::string::npos; }

static std::string spk_hex_of(const char* addr)
{
    auto spk = p2pkh_script(addr_to_h160(addr, false));
    return hexstr(std::vector<uint8_t>(spk.begin(), spk.end()));
}

static Utxo mk_utxo(const std::string& txid, uint32_t vout, int64_t sats, int64_t conf,
                    const std::string& spk_hex, std::optional<bool> coinbase = std::nullopt)
{
    Utxo u;
    u.txid = txid;
    u.vout = vout;
    u.satoshis = sats;
    u.confirmations = conf;
    u.script_pubkey_hex = spk_hex;
    u.coinbase = coinbase;
    return u;
}

static std::string txid_of_byte(const char* two_hex) { std::string s; for (int i = 0; i < 32; ++i) s += two_hex; return s; }

// The on-chain bytes with every scriptSig blanked (the unsigned form the
// builder must reproduce). Independent of the library's own parser.
static std::vector<uint8_t> blank_scriptsigs(const std::vector<uint8_t>& raw)
{
    std::vector<uint8_t> out(raw.begin(), raw.begin() + 5); // version + nin (< 0xfd here)
    size_t off = 5;
    for (uint8_t i = 0; i < raw[4]; ++i) {
        out.insert(out.end(), raw.begin() + off, raw.begin() + off + 36); off += 36;
        const size_t sl = raw[off]; off += 1 + sl;                    // scriptSig < 0xfd
        out.push_back(0x00);
        out.insert(out.end(), raw.begin() + off, raw.begin() + off + 4); off += 4;
    }
    out.insert(out.end(), raw.begin() + off, raw.end());              // outputs + locktime
    return out;
}

// Input outpoints of a raw tx, display txid order, for order assertions.
static std::vector<std::string> input_txids(const std::vector<uint8_t>& raw)
{
    std::vector<std::string> ids;
    size_t off = 5;
    for (uint8_t i = 0; i < raw[4]; ++i) {
        std::vector<uint8_t> t(raw.begin() + off, raw.begin() + off + 32);
        std::reverse(t.begin(), t.end());
        ids.push_back(hexstr(t));
        off += 36;
        off += 1 + raw[off] + 4;
    }
    return ids;
}

// The default request for the inject collateral path.
static CollateralRequest inject_request(const char* funding)
{
    CollateralRequest req;
    req.funding_address = funding;
    req.fee_mode = FeeMode::InjectOnlyZeroFee;
    req.fee_rate = 0;
    req.sweep_all = true;
    req.gov_hash_display = testvec::kOnchainGovHash;
    return req;
}

static CollateralRequest k1_request()
{
    CollateralRequest req = inject_request(testvec::kDonationAddress);
    req.preserve_input_order = true;
    // Legacy sighash commits no input amounts, so the unsigned skeleton does not
    // depend on them. The chain tx itself paid a 1271-duff fee (inputs 101628946,
    // Relay tool at 1000 duffs/kB). Here the amounts sum to its outputs
    // (kOnchainSumOut), so the zero-fee inject planner lands on the identical
    // skeleton: input order, OP_RETURN and change script. The per-input split
    // is illustrative: four prior-change outputs, four coinbase donation slices.
    const int64_t amounts[8] = {25000000, 25000000, 25000000, 25000000,
                                406919, 406919, 406919, 406918};
    for (int i = 0; i < 8; ++i) {
        const auto& p = testvec::kOnchainCollateralPrevouts[i];
        req.utxos.push_back(mk_utxo(p.txid, p.vout, amounts[i], 200, testvec::kDonationSpk));
    }
    return req;
}

static void test_k1_onchain_collateral()
{
    std::printf("[K1 on-chain collateral 3d8fd96e: inject planner reproduces its unsigned skeleton]\n");
    const std::vector<uint8_t> raw = H(testvec::kOnchainCollateralHex);
    CHECK(raw.size() == 1267, "pinned on-chain tx is 1267 bytes");
    CHECK(c2w::artifact::sha256d_display(raw) == testvec::kOnchainCollateralTxid,
          "pinned raw hex hashes to txid 3d8fd96e...");
    const std::vector<uint8_t> blank = blank_scriptsigs(raw);
    CHECK(blank.size() == 415, "blanked (unsigned) form is 415 bytes");

    CollateralPlan plan = plan_collateral(k1_request());
    CHECK(plan.unsigned_tx == blank, "plan.unsigned_tx == on-chain tx with scriptSigs blanked (byte-exact)");
    CHECK(hexstr(plan.op_return_script) == testvec::kOnchainOpReturn, "OP_RETURN == 6a20 + reversed(display hash)");
    CHECK(plan.gov_hash_display == testvec::kOnchainGovHash, "plan carries the direct display hash");
    CHECK(plan.fee == 0 && plan.fee_mode == FeeMode::InjectOnlyZeroFee, "fee 0, inject-only");
    CHECK(plan.total_in == testvec::kOnchainSumOut, "KAT inputs sum to the chain tx's outputs (101627675)");
    CHECK(plan.change == testvec::kOnchainChange, "change = 1627675");
    auto outs = parse_outputs(plan.unsigned_tx);
    CHECK(outs.size() == 2 && outs[0].value == kCoin && hexstr(outs[1].script) == testvec::kDonationSpk,
          "out1 = change -> XdgF P2PKH (dash::DONATION_SCRIPT)");
    CHECK(plan.est_signed_bytes == 415 + 8 * (181 - 41), "est signed = worst case (Unknown => 181 B/input)");
    CHECK(contains(plan.summary, "fee 0.00000000 (INJECT-ONLY: Dash Core peers will not relay; rides only a c2pool block)"),
          "summary states INJECT-ONLY zero fee");
    CHECK(contains(plan.summary, "est signed 1535/100000 B"), "summary states est signed N/100000 B");

    CollateralRequest comp = k1_request();
    comp.key_encoding = PubkeyEncoding::Compressed;
    CHECK(plan_collateral(comp).est_signed_bytes >= raw.size(), "compressed estimate covers the real 1267 B");

    // The switch is load-bearing: the default (txid, vout) order is not the chain's.
    CollateralRequest sorted = k1_request();
    sorted.preserve_input_order = false;
    CollateralPlan sp = plan_collateral(sorted);
    CHECK(sp.unsigned_tx != blank && sp.unsigned_tx.size() == blank.size(), "default sort reorders the on-chain inputs");

    // The mainnet signatures themselves pass our independent re-verify.
    CHECK(!aborts([&] { verify_signed_funding_tx(testvec::kOnchainCollateralHex, testvec::kDonationAddress, false); }),
          "on-chain scriptSigs verify through verify_signed_funding_tx");
}

static void test_k2_fee_flags()
{
    std::printf("[K2 fee-mode flags]\n");
    CollateralRequest relay0 = k1_request();
    relay0.fee_mode = FeeMode::Relay; // fee_rate stays 0
    CHECK(aborts_with([&] { plan_collateral(relay0); }, "zero fee is inject-only"), "Relay + fee 0 aborts (inject-only)");

    CollateralRequest inj_fee = k1_request();
    inj_fee.fee_rate = 1000;
    CHECK(aborts_with([&] { plan_collateral(inj_fee); }, "needs fee_rate 0"), "Inject + fee_rate != 0 aborts");

    CollateralRequest inj_nosweep = k1_request();
    inj_nosweep.sweep_all = false;
    CHECK(aborts_with([&] { plan_collateral(inj_nosweep); }, "needs sweep_all"), "Inject + !sweep_all aborts");

    // The same rule at sign time, for a plan edited after review.
    FoundKey key = find_key_for_address(DUMMY_MNEMONIC, "", DUMMY_ADDR0, false, 0, 3, false);
    CollateralRequest r = make_request(DUMMY_ADDR0);
    CollateralPlan relay_plan = plan_collateral(r);
    relay_plan.change += relay_plan.fee;
    relay_plan.fee = 0;
    CHECK(aborts_with([&] { sign_collateral(relay_plan, key, true); }, "zero fee is inject-only"),
          "sign: a Relay plan forged to fee 0 aborts");
    CollateralRequest ir = inject_request(DUMMY_ADDR0);
    ir.utxos = make_request(DUMMY_ADDR0).utxos;
    CollateralPlan inj_plan = plan_collateral(ir);
    CollateralPlan fee_plan = inj_plan;
    fee_plan.fee = 1000;
    CHECK(aborts_with([&] { sign_collateral(fee_plan, key, true); }, "exactly 0"), "sign: an inject plan with a fee aborts");

    // The inject collateral signs end to end: fee exactly 0, every input re-verifies.
    SignedTx tx = sign_collateral(inj_plan, key, true);
    auto outs = parse_outputs(H(tx.hex));
    CHECK(outs.size() == 2 && outs[0].value == kCoin && hexstr(outs[0].script) == testvec::kOnchainOpReturn &&
              outs[1].value == 10000000 && outs[0].value + outs[1].value == inj_plan.total_in,
          "inject collateral: 1 DASH burn + change, fee 0");
    CHECK(tx.size <= inj_plan.est_signed_bytes, "signed size within the estimate");
    CHECK(!aborts([&] { verify_signed_funding_tx(tx.hex, DUMMY_ADDR0, false); }), "inject collateral re-verifies");

    // The unsigned bytes carry no amounts, so an edited amount passes the bytes
    // check; the sign-time sum identity is what refuses it.
    CollateralPlan amt = inj_plan;
    amt.selected[0].satoshis += 1;
    CHECK(amt.unsigned_tx == inj_plan.unsigned_tx, "an amount edit leaves the unsigned bytes unchanged");
    CHECK(aborts_with([&] { sign_collateral(amt, key, true); }, "does not balance"),
          "sign: inputs != 1 DASH + change + fee aborts (inject)");
    CollateralPlan relay_fee = plan_collateral(make_request(DUMMY_ADDR0));
    relay_fee.fee += 1;
    CHECK(aborts_with([&] { sign_collateral(relay_fee, key, true); }, "does not balance"),
          "sign: inputs != 1 DASH + change + fee aborts (Relay)");

    CollateralPlan edited = inj_plan;
    edited.unsigned_tx[edited.unsigned_tx.size() - 5] ^= 0x01;
    CHECK(aborts_with([&] { sign_collateral(edited, key, true); }, "not the planned one"), "sign: edited plan bytes abort");
    FoundKey forged = find_key_for_address(DUMMY_MNEMONIC, "", DUMMY_ADDR1, false, 0, 3, false);
    forged.address = DUMMY_ADDR0; // claims the funding address, but its pubkey hashes elsewhere
    CHECK(aborts_with([&] { sign_collateral(inj_plan, forged, true); }, "does not hash"), "sign: hash160(pub) != funding aborts");
}

static void test_k3_sweep_all()
{
    std::printf("[K3 sweep-all: order, change, dust floor]\n");
    const std::string spk = spk_hex_of(DUMMY_ADDR0);
    CollateralRequest req = inject_request(DUMMY_ADDR0);
    req.utxos = {mk_utxo(txid_of_byte("22"), 0, 1, 150, spk),
                 mk_utxo(txid_of_byte("00"), 1, 100000000, 150, spk),
                 mk_utxo(txid_of_byte("11"), 2, 5000000, 150, spk)};
    CollateralPlan p = plan_collateral(req);
    auto ids = input_txids(p.unsigned_tx);
    CHECK(ids.size() == 3 && ids[0] == txid_of_byte("00") && ids[1] == txid_of_byte("11") && ids[2] == txid_of_byte("22"),
          "default order is (txid, vout): 00, 11, 22");
    CHECK(p.total_in == 105000001 && p.change == 5000001 && p.fee == 0, "total 105000001, change 5000001, fee 0");

    CollateralRequest keep = req;
    keep.preserve_input_order = true;
    auto kids = input_txids(plan_collateral(keep).unsigned_tx);
    CHECK(kids.size() == 3 && kids[0] == txid_of_byte("22") && kids[2] == txid_of_byte("11"), "preserve keeps request order");

    CollateralRequest dust = req;
    dust.dust_floor = 2;
    CollateralPlan dp = plan_collateral(dust);
    CHECK(dp.selected.size() == 2 && dp.skipped_dust == 1, "dust_floor=2: two selected, one skipped as dust");
    CHECK(dp.total_in == 105000000 && dp.change == 5000000 && dp.fee == 0, "dust left out of the sums");
    CHECK(contains(dp.summary, "skipped dust below 2 duffs (1)"), "summary lists the dust");

    // Relay mode may sweep too: every input in, a real fee.
    CollateralRequest rs = req;
    rs.fee_mode = FeeMode::Relay;
    rs.fee_rate = kDefaultFeeRate;
    CollateralPlan rp = plan_collateral(rs);
    CHECK(rp.selected.size() == 3 && rp.fee >= 1000, "Relay sweep: all inputs, fee paid");
    CHECK(kCoin + rp.change + rp.fee == rp.total_in, "Relay sweep: value conservation");
}

static void test_k4_maturity()
{
    std::printf("[K4 maturity gate]\n");
    const std::string spk = spk_hex_of(DUMMY_ADDR0);
    CollateralRequest req = inject_request(DUMMY_ADDR0);
    req.utxos = {mk_utxo(txid_of_byte("aa"), 0, 100000000, 100, spk),         // unknown: needs 101
                 mk_utxo(txid_of_byte("bb"), 0, 60000000, 101, spk),          // exactly mature
                 mk_utxo(txid_of_byte("cc"), 0, 50000000, 5, spk, false)};    // known non-coinbase
    CollateralPlan p = plan_collateral(req);
    CHECK(p.selected.size() == 2 && p.total_in == 110000000, "conf 101 and non-coinbase conf 5 included");
    CHECK(p.skipped_immature.size() == 1 && p.skipped_immature[0].txid == txid_of_byte("aa"), "conf 100 excluded");
    CHECK(contains(p.summary, "matures in 1 block"), "summary: matures in 1");
    CHECK(contains(p.summary, "no follow-up tx"), "summary carries the perpetual-tail note");

    Utxo cb = mk_utxo(txid_of_byte("dd"), 0, 1, 0, spk, true);
    Utxo unk = mk_utxo(txid_of_byte("dd"), 0, 1, 0, spk);
    Utxo nc = mk_utxo(txid_of_byte("dd"), 0, 1, 0, spk, false);
    CHECK(confirmations_needed(cb, 50) == kCoinbaseMaturity && confirmations_needed(cb, 120) == 120,
          "known coinbase: never below 100");
    CHECK(confirmations_needed(unk, 50) == kCoinbaseMaturity && confirmations_needed(unk, 120) == 120,
          "unknown (treated as coinbase): never below 100 either");
    CHECK(confirmations_needed(nc, 101) == 1, "known non-coinbase: 1");

    // A lowered min_confirmations cannot let a possibly-coinbase UTXO through.
    CollateralRequest low = inject_request(DUMMY_ADDR0);
    low.min_confirmations = 6;
    low.utxos = {mk_utxo(txid_of_byte("e1"), 0, 50000000, 99, spk),           // unknown at 99
                 mk_utxo(txid_of_byte("e2"), 0, 80000000, 100, spk),          // unknown at 100
                 mk_utxo(txid_of_byte("e3"), 0, 30000000, 1, spk, false)};    // non-coinbase at 1
    CollateralPlan lp = plan_collateral(low);
    CHECK(lp.skipped_immature.size() == 1 && lp.skipped_immature[0].txid == txid_of_byte("e1"),
          "min_conf 6: unknown at conf 99 excluded");
    CHECK(lp.selected.size() == 2 && lp.selected[0].txid == txid_of_byte("e2") &&
              lp.selected[1].txid == txid_of_byte("e3"),
          "min_conf 6: unknown at conf 100 and known non-coinbase at conf 1 included");

    CollateralRequest none = req;
    for (Utxo& u : none.utxos) { u.confirmations = 3; u.coinbase = std::nullopt; }
    CHECK(aborts_with([&] { plan_collateral(none); }, "every UTXO is immature"), "all immature aborts");
}

static SweepRequest sweep_of(size_t n, int64_t sats)
{
    SweepRequest req;
    req.funding_address = DUMMY_ADDR0;
    const std::string spk = spk_hex_of(DUMMY_ADDR0);
    for (size_t i = 0; i < n; ++i) {
        char id[65];
        std::snprintf(id, sizeof id, "%064zx", i + 1);
        req.utxos.push_back(mk_utxo(id, static_cast<uint32_t>(i % 3), sats, 150, spk));
    }
    return req;
}

static void test_k5_batch_split()
{
    std::printf("[K5 batch split under the node caps]\n");
    SweepRequest req = sweep_of(1500, 1000);
    req.key_encoding = PubkeyEncoding::Compressed;
    SweepBatchPlan plan = plan_sweep(req);
    size_t n_in = 0;
    int64_t v_out = 0;
    bool caps_ok = true, zero_fee = true;
    for (const SweepTxPlan& tx : plan.txs) {
        n_in += tx.inputs.size();
        v_out += tx.value_out;
        caps_ok = caps_ok && tx.inputs.size() <= caps::kMaxInjectInputs && tx.inputs.size() <= 670 &&
                  tx.est_signed_bytes <= caps::kMaxInjectTxBytes;
        int64_t s = 0;
        for (const Utxo& u : tx.inputs) s += u.satoshis;
        zero_fee = zero_fee && s == tx.value_out;
    }
    CHECK(plan.txs.size() == 3 && plan.txs[0].inputs.size() == 670 && plan.txs[2].inputs.size() == 160,
          "1500 compressed inputs split 670 / 670 / 160");
    CHECK(n_in == 1500 && v_out == 1500000 && plan.total_in == 1500000, "sum inputs 1500, sum value_out 1,500,000");
    CHECK(caps_ok, "every batch <= 1000 inputs and <= 100000 est. bytes");
    CHECK(zero_fee, "every batch is zero-fee");

    SweepRequest unk = sweep_of(1500, 1000);
    CHECK(plan_sweep(unk).txs[0].inputs.size() == 552, "Unknown encoding plans 181 B/input: 552 per batch");

    CollateralRequest coll = inject_request(DUMMY_ADDR0);
    coll.utxos = req.utxos;
    CHECK(aborts([&] { plan_collateral(coll); }), "the same set as a collateral aborts");
    CollateralRequest funded = inject_request(DUMMY_ADDR0);
    funded.utxos = sweep_of(1500, 100000).utxos;
    CHECK(aborts_with([&] { plan_collateral(funded); }, "never split"), "a funded 1500-input collateral aborts: never split");

    // Under the input cap but over the size cap: refused at the worst-case
    // (Unknown => 181 B) estimate, accepted once the key is known to be compressed.
    CollateralRequest big = inject_request(DUMMY_ADDR0);
    big.utxos = sweep_of(600, 200000).utxos;
    CHECK(aborts_with([&] { plan_collateral(big); }, "estimated signed size"), "600 inputs at 181 B: est > 100000 aborts");
    big.key_encoding = PubkeyEncoding::Compressed;
    CHECK(!aborts([&] { plan_collateral(big); }), "the same 600 inputs at 149 B fit");

    SweepRequest many = sweep_of(1500, 1000);
    many.max_inputs_per_tx = 300;
    SweepBatchPlan mp = plan_sweep(many);
    CHECK(mp.txs.size() == 5 && contains(mp.summary, "WARNING: 5 txs"), "more than 4 batches is a WARNING, not a refusal");
    SweepRequest wide = sweep_of(3, 1000);
    wide.max_inputs_per_tx = caps::kMaxInjectInputs + 1;
    CHECK(aborts([&] { plan_sweep(wide); }), "max_inputs_per_tx above the node cap aborts");
    wide.max_inputs_per_tx = caps::kMaxInjectInputs;
    wide.max_tx_bytes = caps::kMaxInjectTxBytes + 1;
    CHECK(aborts([&] { plan_sweep(wide); }), "max_tx_bytes above the node cap aborts");

    FoundKey key = find_key_for_address(DUMMY_MNEMONIC, "", DUMMY_ADDR0, false, KeyScanRange{});
    std::vector<SignedTx> signed_txs = sign_sweep(plan, key, true);
    bool sizes_ok = signed_txs.size() == 3;
    for (size_t i = 0; i < signed_txs.size(); ++i)
        sizes_ok = sizes_ok && signed_txs[i].size <= caps::kMaxInjectTxBytes &&
                   signed_txs[i].size <= plan.txs[i].est_signed_bytes;
    CHECK(sizes_ok, "every signed batch <= 100000 B and <= its estimate");
}

static void test_k6_sign_verify()
{
    std::printf("[K6 sweep sign + self-verify]\n");
    FoundKey key = find_key_for_address(DUMMY_MNEMONIC, "", DUMMY_ADDR0, false, KeyScanRange{});
    CHECK(key.path == "m/44'/5'/0'/0/0" && key.compressed && key.pub.size() == 33, "XoJA8q... = m/44'/5'/0'/0/0, compressed");
    SweepRequest req = sweep_of(2, 70000);
    SweepBatchPlan plan = plan_sweep(req);
    CHECK(plan.txs.size() == 1 && plan.txs[0].inputs.size() == 2, "a 2-input sweep");

    CHECK(aborts_with([&] { sign_sweep(plan, key, false); }, "not confirmed"), "confirm_spend=false aborts");
    FoundKey other = find_key_for_address(DUMMY_MNEMONIC, "", DUMMY_ADDR1, false, KeyScanRange{});
    CHECK(aborts_with([&] { sign_sweep(plan, other, true); }, "not the funding address"), "a key for another address aborts");
    other.address = DUMMY_ADDR0; // claims the funding address, but its pubkey hashes elsewhere
    CHECK(aborts_with([&] { sign_sweep(plan, other, true); }, "does not hash"), "hash160(pub) != funding aborts");

    SweepBatchPlan fee_edit = plan;
    fee_edit.txs[0].value_out -= 1;
    CHECK(aborts_with([&] { sign_sweep(fee_edit, key, true); }, "not zero-fee"), "an edited (fee-paying) plan aborts");
    SweepBatchPlan byte_edit = plan;
    byte_edit.txs[0].unsigned_tx.back() ^= 0x01;
    CHECK(aborts_with([&] { sign_sweep(byte_edit, key, true); }, "not the planned one"), "edited plan bytes abort");

    std::vector<SignedTx> st = sign_sweep(plan, key, true);
    CHECK(st.size() == 1 && st[0].txid.size() == 64 && st[0].size == st[0].hex.size() / 2, "2-input sweep finalizes");
    CHECK(!aborts([&] { verify_signed_funding_tx(st[0].hex, DUMMY_ADDR0, false); }), "re-verify passes");
    auto outs = parse_outputs(H(st[0].hex));
    CHECK(outs.size() == 1 && outs[0].value == 140000 && hexstr(outs[0].script) == spk_hex_of(DUMMY_ADDR0),
          "one output: everything back to the funding address, fee 0");

    // Flip one byte inside input 0's DER signature: version 4 + nin 1 + outpoint
    // 36 + script length 1 + push length 1, then 8 bytes into the signature.
    std::vector<uint8_t> raw = H(st[0].hex);
    raw[4 + 1 + 36 + 1 + 1 + 8] ^= 0x01;
    CHECK(aborts_with([&] { verify_signed_funding_tx(hexstr(raw), DUMMY_ADDR0, false); }, "fails verification"),
          "a flipped signature byte fails verify_input");
}

static void test_k7_python_parity()
{
    std::printf("[K7 python c2wallet.py parity (sign_external_unsigned + sign_sweep)]\n");
    FoundKey key = find_key_for_address(DUMMY_MNEMONIC, testvec::kPyParityPassphrase, testvec::kPyParityAddress,
                                        false, KeyScanRange{});
    CHECK(key.path == "m/44'/5'/0'/0/0" && key.compressed, "TREZOR key at m/44'/5'/0'/0/0");

    std::vector<SignedTx> st = sign_external_unsigned({testvec::kPyParityUnsignedHex}, testvec::kPyParityAddress,
                                                      false, key, true);
    CHECK(st.size() == 1 && st[0].hex == testvec::kPyParitySignedHex, "signed hex == c2wallet.py, byte for byte");
    CHECK(st.size() == 1 && st[0].txid == testvec::kPyParityTxid, "txid == c2wallet.py");

    // The planner reaches the very same bytes from a UTXO list.
    SweepRequest req;
    req.funding_address = testvec::kPyParityAddress;
    req.preserve_input_order = true;
    const std::string spk = spk_hex_of(testvec::kPyParityAddress);
    req.utxos = {mk_utxo(txid_of_byte("11"), 0, 60000, 150, spk), mk_utxo(txid_of_byte("22"), 1, 40000, 150, spk)};
    SweepBatchPlan plan = plan_sweep(req);
    CHECK(plan.txs.size() == 1 && hexstr(plan.txs[0].unsigned_tx) == testvec::kPyParityUnsignedHex,
          "plan_sweep unsigned bytes == the python vector");
    std::vector<SignedTx> st2 = sign_sweep(plan, key, true);
    CHECK(st2.size() == 1 && st2[0].hex == testvec::kPyParitySignedHex, "sign_sweep == c2wallet.py too");

    // External-hex refusals (rule 11) — every one before the key is touched.
    const std::string u = testvec::kPyParityUnsignedHex;
    CHECK(aborts_with([&] { sign_external_unsigned({testvec::kPyParitySignedHex}, testvec::kPyParityAddress, false, key, true); },
                      "already carries a scriptSig"), "a scriptSig present aborts");
    CHECK(aborts_with([&] { sign_external_unsigned({u + "00"}, testvec::kPyParityAddress, false, key, true); },
                      "trailing"), "trailing bytes abort");
    CHECK(aborts_with([&] { sign_external_unsigned({"020000000001" + u.substr(10)}, testvec::kPyParityAddress, false, key, true); },
                      "segwit"), "a segwit marker aborts");
    CHECK(aborts_with([&] { sign_external_unsigned({"01" + u.substr(2)}, testvec::kPyParityAddress, false, key, true); },
                      "version 1"), "version 1 aborts");
    CHECK(aborts_with([&] { sign_external_unsigned({"02000300" + u.substr(8)}, testvec::kPyParityAddress, false, key, true); },
                      "special tx"), "a special-tx type aborts");
    CHECK(aborts_with([&] { sign_external_unsigned({"zz"}, testvec::kPyParityAddress, false, key, true); }, "not hex"),
          "non-hex aborts");
    CHECK(aborts_with([&] { sign_external_unsigned({u}, testvec::kPyParityAddress, false, key, false); }, "not confirmed"),
          "confirm_spend=false aborts");
    // A wrong key AND a bad second blob: the blob is reported, so parsing ran first.
    FoundKey wrong = find_key_for_address(DUMMY_MNEMONIC, "", DUMMY_ADDR0, false, KeyScanRange{});
    CHECK(aborts_with([&] { sign_external_unsigned({u, u + "00"}, testvec::kPyParityAddress, false, wrong, true); },
                      "unsigned tx 2"), "every blob is validated before the key is used");
    CHECK(aborts_with([&] { sign_external_unsigned({u}, testvec::kPyParityAddress, false, wrong, true); },
                      "not the funding address"), "a key for another address aborts");
}

static void test_k8_uncompressed_scan()
{
    std::printf("[K8 key scan: uncompressed + accounts]\n");
    FoundKey k = find_key_for_address(DUMMY_MNEMONIC, "", testvec::kUncompressedAddr001, false, KeyScanRange{});
    CHECK(k.pub.size() == 65 && !k.compressed, "uncompressed key found (pub65)");
    CHECK(k.path == "m/44'/5'/0'/0/1 (uncompressed)", "path ends with (uncompressed)");
    KeyScanRange comp_only;
    comp_only.try_uncompressed = false;
    CHECK(aborts([&] { find_key_for_address(DUMMY_MNEMONIC, "", testvec::kUncompressedAddr001, false, comp_only); }),
          "try_uncompressed=false aborts");
    CHECK(aborts([&] { find_key_for_address(DUMMY_MNEMONIC, "", testvec::kUncompressedAddr001, false, 0, 5, true); }),
          "the original 7-arg scan stays compressed-only");

    FoundKey a1 = find_key_for_address(DUMMY_MNEMONIC, "", testvec::kAccount1Addr000, false, KeyScanRange{});
    CHECK(a1.path == "m/44'/5'/1'/0/0" && a1.compressed, "accounts=2 finds m/44'/5'/1'/0/0");
    KeyScanRange one;
    one.accounts = 1;
    CHECK(aborts([&] { find_key_for_address(DUMMY_MNEMONIC, "", testvec::kAccount1Addr000, false, one); }),
          "accounts=1 does not reach account 1");
    KeyScanRange empty;
    empty.indices = 0;
    CHECK(aborts([&] { find_key_for_address(DUMMY_MNEMONIC, "", DUMMY_ADDR0, false, empty); }), "an empty range aborts");

    // An uncompressed key signs and verifies; the estimate covers it.
    SweepRequest req;
    req.funding_address = testvec::kUncompressedAddr001;
    req.key_encoding = PubkeyEncoding::Uncompressed;
    req.utxos = {mk_utxo(txid_of_byte("33"), 0, 50000, 150, spk_hex_of(testvec::kUncompressedAddr001))};
    SweepBatchPlan plan = plan_sweep(req);
    std::vector<SignedTx> st = sign_sweep(plan, k, true);
    CHECK(st.size() == 1 && st[0].size <= plan.txs[0].est_signed_bytes, "uncompressed sweep signs within its estimate");
    CHECK(!aborts([&] { verify_signed_funding_tx(st[0].hex, testvec::kUncompressedAddr001, false); }),
          "uncompressed sweep re-verifies");

    // A plan sized for a compressed key, signed with the uncompressed one: the
    // first batch (670 inputs) signs to > 100000 B and is refused, nothing emitted.
    SweepRequest wrong_enc;
    wrong_enc.funding_address = testvec::kUncompressedAddr001;
    wrong_enc.key_encoding = PubkeyEncoding::Compressed;
    const std::string uspk = spk_hex_of(testvec::kUncompressedAddr001);
    for (const Utxo& u : sweep_of(700, 1000).utxos)
        wrong_enc.utxos.push_back(mk_utxo(u.txid, u.vout, u.satoshis, u.confirmations, uspk));
    SweepBatchPlan wp = plan_sweep(wrong_enc);
    CHECK(wp.txs.size() == 2 && wp.txs[0].inputs.size() == 670, "planned as 670 + 30 compressed inputs");
    CHECK(aborts_with([&] { sign_sweep(wp, k, true); }, "oversize"), "signed size over the cap is refused after signing");
}

static void test_k9_emit_format()
{
    std::printf("[K9 inject file format == SignedContainer]\n");
    SignedTx a, b;
    a.hex = testvec::kPyParitySignedHex;
    FoundKey key = find_key_for_address(DUMMY_MNEMONIC, "", DUMMY_ADDR0, false, KeyScanRange{});
    b = sign_sweep(plan_sweep(sweep_of(2, 70000)), key, true).at(0);
    const std::string file = emit_inject_file({a, b});
    CHECK(file == a.hex + "\n" + b.hex + "\n", "emit(2) == h1\\nh2\\n");
    c2w::artifact::SignedContainer sc;
    sc.tx_hexes = {a.hex, b.hex};
    CHECK(sc.emit() == file, "== SignedContainer::emit");
    std::string err;
    auto parsed = c2w::artifact::SignedContainer::parse(file, err);
    CHECK(parsed && parsed->tx_hexes == sc.tx_hexes, "round-trips through SignedContainer::parse");
    std::string why;
    CHECK(c2w::artifact::accept_as_signed(H(a.hex), why) && c2w::artifact::accept_as_signed(H(b.hex), why),
          "accept_as_signed true for every line");
    CHECK(!c2w::artifact::accept_as_signed(H(testvec::kPyParityUnsignedHex), why), "accept_as_signed false for unsigned bytes");
    CHECK(emit_inject_file({b}) == b.hex + "\n", "a single tx is exactly one line");
    CHECK(aborts([&] { emit_inject_file({}); }), "an empty list aborts");
    SignedTx upper = a;
    upper.hex[0] = 'A';
    upper.hex[1] = 'B';
    CHECK(aborts([&] { emit_inject_file({upper}); }), "non-lowercase hex aborts");
}

static void test_k10_bip68()
{
    std::printf("[K10 BIP68: every input needs sequence bit 31]\n");
    FoundKey key = find_key_for_address(DUMMY_MNEMONIC, testvec::kPyParityPassphrase, testvec::kPyParityAddress,
                                        false, KeyScanRange{});
    // input 0 sequence sits at 4 + 1 + 36 + 1 = byte 42 of the unsigned tx.
    std::vector<uint8_t> raw = H(testvec::kPyParityUnsignedHex);
    raw[42] = 0xff; raw[43] = 0xff; raw[44] = 0xff; raw[45] = 0x7f; // 0x7fffffff
    CHECK(aborts_with([&] { sign_external_unsigned({hexstr(raw)}, testvec::kPyParityAddress, false, key, true); },
                      "BIP68"), "sequence 0x7fffffff aborts");
    raw[42] = 0xfe; raw[45] = 0xff;                                    // 0xfffffffe: bit 31 set
    std::vector<SignedTx> st;
    CHECK(!aborts([&] { st = sign_external_unsigned({hexstr(raw)}, testvec::kPyParityAddress, false, key, true); }) &&
              st.size() == 1,
          "sequence 0xfffffffe (bit 31 set) signs");
    // Every tx this library builds uses the final sequence (the python vector's).
    SweepRequest r;
    r.funding_address = testvec::kPyParityAddress;
    r.preserve_input_order = true;
    const std::string spk = spk_hex_of(testvec::kPyParityAddress);
    r.utxos.push_back(mk_utxo(txid_of_byte("11"), 0, 1, 150, spk));
    r.utxos.push_back(mk_utxo(txid_of_byte("22"), 1, 99999, 150, spk));
    CHECK(plan_sweep(r).txs.at(0).unsigned_tx == H(testvec::kPyParityUnsignedHex), "built inputs carry sequence ffffffff");
}

static void test_k12_refusals()
{
    std::printf("[K12 scriptPubKey + hash refusals]\n");
    CollateralRequest foreign = k1_request();
    foreign.utxos[3].script_pubkey_hex = "76a914" + std::string(40, '1') + "88ac";
    CHECK(aborts_with([&] { plan_collateral(foreign); }, "does NOT pay"), "inject: foreign scriptPubKey aborts");
    CollateralRequest missing = k1_request();
    missing.utxos[5].script_pubkey_hex.clear();
    CHECK(aborts_with([&] { plan_collateral(missing); }, "has no scriptPubKey"), "inject: missing scriptPubKey aborts");
    CollateralRequest relay_missing = make_request(DUMMY_ADDR0);
    relay_missing.utxos[0].script_pubkey_hex.clear();
    CHECK(!aborts([&] { plan_collateral(relay_missing); }), "Relay keeps the optional scriptPubKey");
    relay_missing.sweep_all = true;
    CHECK(aborts_with([&] { plan_collateral(relay_missing); }, "has no scriptPubKey"),
          "Relay sweep_all: missing scriptPubKey aborts");
    CollateralRequest dup = k1_request();
    dup.utxos.push_back(dup.utxos[0]);
    CHECK(aborts_with([&] { plan_collateral(dup); }, "listed twice"), "inject: a duplicate outpoint aborts");
    CollateralRequest relay_dup = make_request(DUMMY_ADDR0);
    relay_dup.utxos.push_back(relay_dup.utxos[0]);
    CHECK(aborts_with([&] { plan_collateral(relay_dup); }, "listed twice"),
          "Relay select_coins: a duplicate outpoint aborts too");
    CollateralRequest relay_dup_case = make_request(DUMMY_ADDR0);
    relay_dup_case.utxos.push_back(relay_dup_case.utxos[0]);
    relay_dup_case.utxos.back().txid = std::string(64, 'A'); // same outpoint, other hex case
    CHECK(aborts_with([&] { plan_collateral(relay_dup_case); }, "listed twice"),
          "a duplicate outpoint differing only in hex case aborts");

    SweepRequest sw = sweep_of(3, 1000);
    sw.utxos[1].script_pubkey_hex = spk_hex_of(DUMMY_ADDR1);
    CHECK(aborts_with([&] { plan_sweep(sw); }, "does NOT pay"), "sweep: foreign scriptPubKey aborts");
    sw.utxos[1].script_pubkey_hex.clear();
    CHECK(aborts_with([&] { plan_sweep(sw); }, "has no scriptPubKey"), "sweep: missing scriptPubKey aborts");

    CollateralRequest exp = k1_request();
    exp.expected_hash_display = std::string(64, '0');
    CHECK(aborts_with([&] { plan_collateral(exp); }, "WRONG object"), "expected-hash vs direct hash mismatch aborts");
    exp.expected_hash_display = "FA758340F1BD2391D17BB43667F76C5D9070D737B68E018E42ED75B09C6BA631";
    CHECK(!aborts([&] { plan_collateral(exp); }), "expected-hash equal to the direct hash passes");

    // Direct hash + the object fields: the derived hash must equal it.
    const auto& v0 = testvec::kMainnetGovVectors[0];
    CollateralRequest both = k1_request();
    both.time_ = v0.time_;
    both.data_hex = v0.data_hex;
    CHECK(aborts_with([&] { plan_collateral(both); }, "WRONG object"), "direct hash != derived-from-data aborts");
    both.gov_hash_display = v0.expected_display;
    CollateralPlan bp = plan_collateral(both);
    CHECK(bp.gov_hash_display == v0.expected_display && hexstr(bp.op_return_script) == testvec::kVector0OpReturnScript,
          "direct hash == derived-from-data passes, OP_RETURN as on chain");

    CollateralRequest bad = k1_request();
    bad.gov_hash_display = std::string(63, 'a');
    CHECK(aborts_with([&] { plan_collateral(bad); }, "64 hex"), "a direct hash that is not 64 hex aborts");
    CollateralRequest under = inject_request(DUMMY_ADDR0);
    under.utxos = {mk_utxo(txid_of_byte("44"), 0, 99999999, 150, spk_hex_of(DUMMY_ADDR0))};
    CHECK(aborts_with([&] { plan_collateral(under); }, "short 0.00000001 DASH"), "inject: < 1 DASH aborts with the shortfall");
}

static void test_k13_display_roundtrip()
{
    std::printf("[K13 gov_hash_from_display round trip]\n");
    bool all = true;
    for (int i = 0; i < testvec::kNumGovVectors; ++i) {
        const auto& v = testvec::kMainnetGovVectors[i];
        auto internal = gov_object_hash(std::string(64, '0'), 1, v.time_, v.data_hex);
        all = all && gov_hash_from_display(gov_hash_display(internal)) == internal &&
              gov_hash_display(gov_hash_from_display(v.expected_display)) == v.expected_display;
    }
    CHECK(all, "display -> internal -> display is the identity on every mainnet vector");
    CHECK(hexstr(collateral_op_return_script(gov_hash_from_display(testvec::kOnchainGovHash))) == testvec::kOnchainOpReturn,
          "6a20 + reversed(display) == the on-chain OP_RETURN");
    CHECK(gov_hash_from_display("FA758340F1BD2391D17BB43667F76C5D9070D737B68E018E42ED75B09C6BA631") ==
              gov_hash_from_display(testvec::kOnchainGovHash),
          "upper-case display accepted");
    CHECK(aborts([&] { gov_hash_from_display(std::string(62, 'a')); }), "short hash aborts");
    CHECK(aborts([&] { gov_hash_from_display(std::string(64, 'g')); }), "non-hex hash aborts");
    CHECK(aborts([&] { gov_hash_from_display(" " + std::string(testvec::kOnchainGovHash)); }), "padded hash aborts");
}

static void test_utxo_intake()
{
    std::printf("[UtxoIntake: insight JSON]\n");
    // Three entries of the XdgF insight list (public data), plus a key order shuffle.
    const std::string json = R"([
      {"address":"XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u","txid":"8333b0ddadb460a06e0fb18977164ff17d0f0288422504b388f6770f1bd7184f",
       "vout":3,"scriptPubKey":"76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac","amount":1e-08,"satoshis":1,
       "height":2560084,"confirmations":26},
      {"txid":"665710F4833E0D3B4C2CE93B971E5FE04315FE244D3C53C926DB511A8DDE1B9B","vout":7,"amount":0.0003649,
       "satoshis":36490,"scriptPubKey":"76A91420CB5C22B1E4D5947E5C112C7696B51AD9AF3C6188AC","confirmations":32607},
      {"txid":"a43bce9f9f8c34fe30b3873322c0b7592fd329507da1642232cef14f875ce9fb","vout":7,"satoshis":2500000000,
       "scriptPubKey":"76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac"}
    ])";
    std::string err;
    std::vector<Utxo> u = parse_insight_utxos(json, err);
    CHECK(err.empty() && u.size() == 3, "three UTXOs parsed");
    CHECK(u.size() == 3 && u[0].vout == 3 && u[0].satoshis == 1 && u[0].confirmations == 26, "integer fields");
    CHECK(u.size() == 3 && u[1].txid == "665710f4833e0d3b4c2ce93b971e5fe04315fe244d3c53c926db511a8dde1b9b" &&
              u[1].script_pubkey_hex == testvec::kDonationSpk && u[1].satoshis == 36490,
          "hex lower-cased; satoshis taken, amount ignored");
    CHECK(u.size() == 3 && u[2].confirmations == 0 && u[2].satoshis == 2500000000LL, "missing confirmations reads 0");
    CHECK(u.size() == 3 && !u[0].coinbase.has_value() && !u[2].coinbase.has_value(), "no coinbase flag: unknown");

    UtxoScreen scr = screen_utxos(u, addr_to_h160(testvec::kDonationAddress, false), kDefaultMinConf, 2, true);
    CHECK(scr.spendable.size() == 1 && scr.dust.size() == 1 && scr.immature.size() == 1, "screen: 1 spendable, 1 dust, 1 immature");

    CHECK(parse_insight_utxos(R"({"txid":"x"})", err).empty() && !err.empty(), "a non-array aborts");
    CHECK(parse_insight_utxos(R"([{"txid":"8333","vout":0,"satoshis":1}])", err).empty() && !err.empty(), "a short txid aborts");
    CHECK(parse_insight_utxos(R"([{"txid":")" + txid_of_byte("ab") + R"(","vout":0,"satoshis":1.5}])", err).empty() &&
              !err.empty(), "fractional satoshis abort");
    CHECK(parse_insight_utxos(R"([{"txid":")" + txid_of_byte("ab") + R"(","vout":0,"amount":0.1}])", err).empty() &&
              !err.empty(), "amount without satoshis aborts");
    CHECK(parse_insight_utxos(R"([{"txid":")" + txid_of_byte("ab") + R"(","vout":-1,"satoshis":1}])", err).empty() &&
              !err.empty(), "a negative vout aborts");
    CHECK(parse_insight_utxos("[1,", err).empty() && !err.empty(), "broken JSON aborts");
}

// ═══════════════════════════════════════════════════════════════════════════
// Slice 2 — PageDashInject's std-only model (DashInjectModel), the intake
// formats an operator actually produces, the target-height re-screen, the
// relay fee mode and the manifest. KATs S2-K1..K12 of the slice-2 design.
// ═══════════════════════════════════════════════════════════════════════════

#ifndef C2W_DASH_FIXTURE_DIR
#error "C2W_DASH_FIXTURE_DIR must point at tests/fixtures"
#endif

// The real XdgF UTXO set (dashd getaddressutxos on the tertiary at tip 2563986;
// public data): 170 rows, 60963705 duffs, 42 of them 1-duff spam.
static const char* kFixtureName = "xdgf-getaddressutxos-tip2563986.json";
static const int64_t kFixtureTip = 2563986;

static std::string read_file(const std::string& path)
{
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return {};
    std::string out;
    char buf[4096];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) out.append(buf, n);
    std::fclose(f);
    return out;
}

static std::string read_fixture(const char* name) { return read_file(std::string(C2W_DASH_FIXTURE_DIR) + "/" + name); }

// Run `fn`, reporting a DashAbort as a failed check instead of ending the suite.
template <typename F>
static bool runs(F&& fn, const char* what)
{
    try { fn(); return true; }
    catch (const DashAbort& e) { std::printf("    (%s aborted: %s)\n", what, e.what()); return false; }
    catch (const std::exception& e) { std::printf("    (%s threw: %s)\n", what, e.what()); return false; }
}

static void test_s2_k2_getaddressutxos_fixture()
{
    std::printf("[S2-K2 dashd getaddressutxos intake on the real 170-row fixture]\n");
    const std::string json = read_fixture(kFixtureName);
    CHECK(json.size() > 40000, "fixture readable");

    UtxoImport imp;
    const bool parsed = runs([&] { imp = parse_utxo_json(json, kFixtureTip, false); }, "parse_utxo_json");
    CHECK(parsed, "the dashd getaddressutxos shape parses");
    CHECK(imp.source == UtxoSource::GetAddressUtxos, "auto-detected as getaddressutxos");
    CHECK(imp.utxos.size() == 170, "170 rows");
    CHECK(imp.total == 60963705, "sum 60963705 duffs");
    CHECK(imp.address == testvec::kDonationAddress, "funding address derived from the scripts: XdgF...");
    CHECK(imp.tip_height == kFixtureTip && !imp.coinbase_flags, "tip 2563986, no coinbase flags");
    bool unknown_cb = true, conf_ok = true, spk_ok = true;
    int64_t hmin = INT64_MAX, hmax = 0;
    for (const Utxo& u : imp.utxos) {
        unknown_cb = unknown_cb && !u.coinbase.has_value();
        conf_ok = conf_ok && u.confirmations == kFixtureTip - u.height + 1;
        spk_ok = spk_ok && u.script_pubkey_hex == testvec::kDonationSpk;
        hmin = std::min(hmin, u.height);
        hmax = std::max(hmax, u.height);
    }
    CHECK(unknown_cb, "every row: coinbase unknown (held to the coinbase rule)");
    CHECK(conf_ok, "every row: confirmations = tip - height + 1");
    CHECK(spk_ok, "every row: script = the XdgF P2PKH");
    CHECK(hmin == 2527503 && hmax == 2563881, "heights 2527503 .. 2563881");
    CHECK(!imp.utxos.empty() && imp.utxos[0].txid == "665710f4833e0d3b4c2ce93b971e5fe04315fe244d3c53c926db511a8dde1b9b" &&
              imp.utxos[0].vout == 7 && imp.utxos[0].satoshis == 36490 && imp.utxos[0].confirmations == 36484,
          "row 0: 665710f4...:7, 36490 duffs, 36484 conf (outputIndex -> vout)");

    UtxoImport direct;
    CHECK(runs([&] { direct = parse_getaddressutxos(json, kFixtureTip, false); }, "parse_getaddressutxos") &&
              direct.utxos.size() == 170 && direct.total == imp.total,
          "parse_getaddressutxos == the auto-detected import");

    // The slice-1 insight parser alone cannot read this shape (why slice 2 adds it).
    std::string err;
    CHECK(parse_insight_utxos(json, err).empty() && contains(err, "vout"),
          "parse_insight_utxos still refuses the dashd shape (no vout field)");

    if (imp.utxos.size() == 170) {
        UtxoScreen scr = screen_utxos(imp.utxos, addr_to_h160(testvec::kDonationAddress, false), kDefaultMinConf, 2, true);
        CHECK(scr.spendable.size() == 128 && scr.immature.empty() && scr.dust.size() == 42,
              "screen at the tip, dust_floor 2: 128 spendable / 0 immature / 42 dust");
        SweepRequest sw;
        sw.funding_address = testvec::kDonationAddress;
        sw.utxos = imp.utxos;
        sw.dust_floor = 2;
        sw.key_encoding = PubkeyEncoding::Compressed;
        SweepBatchPlan sp;
        CHECK(runs([&] { sp = plan_sweep(sw); }, "plan_sweep") && sp.txs.size() == 1 &&
                  sp.txs[0].inputs.size() == 128 && sp.txs[0].est_signed_bytes <= 19116 &&
                  sp.total_in == 60963663,
              "plan: one tx, 128 inputs, 60963663 duffs, est signed <= 19116 B");
    }

    // Refusals.
    CHECK(aborts([&] { parse_getaddressutxos(json, 0, false); }), "bare array without a tip aborts");
    CHECK(aborts_with([&] { parse_getaddressutxos(json, 2563880, false); }, "above the tip"),
          "a tip below the youngest row (2563881) aborts");
    CHECK(aborts([&] { parse_getaddressutxos(json, kFixtureTip, true); }), "testnet page, mainnet address aborts");
    std::string foreign = json;
    const size_t at = foreign.find(testvec::kDonationSpk, foreign.find(testvec::kDonationSpk) + 1);
    foreign.replace(at, std::strlen(testvec::kDonationSpk), spk_hex_of(DUMMY_ADDR0));
    CHECK(aborts_with([&] { parse_getaddressutxos(foreign, kFixtureTip, false); }, "pays"),
          "a row paying another script aborts");
    std::string dup = json;
    const size_t open = dup.find('{'), close = dup.find('}');
    dup.insert(dup.find('[') + 1, dup.substr(open, close - open + 1) + ",");
    CHECK(aborts_with([&] { parse_getaddressutxos(dup, kFixtureTip, false); }, "listed twice"),
          "a duplicated row aborts");

    // The chainInfo object form carries its own tip.
    const std::string chain_info = "{\"utxos\":" + json + ",\"hash\":\"" + std::string(64, 'c') +
                                   "\",\"height\":2563986}";
    UtxoImport ci;
    CHECK(runs([&] { ci = parse_utxo_json(chain_info, 0, false); }, "chainInfo") && ci.utxos.size() == 170 &&
              ci.tip_height == kFixtureTip && ci.source == UtxoSource::GetAddressUtxos,
          "chainInfo form {utxos, hash, height}: tip taken from the object");
    CHECK(aborts([&] { parse_utxo_json(chain_info, kFixtureTip + 1, false); }),
          "chainInfo form with a different typed tip aborts");
}

// ── slice-2 helpers ─────────────────────────────────────────────────────────

struct Row {
    std::string txid;
    uint32_t vout;
    int64_t sats;
    int64_t height;
    std::optional<bool> coinbase;
};

static std::vector<Row> fixture_rows()
{
    std::vector<Row> rows;
    for (const Utxo& u : parse_getaddressutxos(read_fixture(kFixtureName), kFixtureTip, false).utxos)
        rows.push_back({u.txid, u.vout, u.satoshis, u.height, std::nullopt});
    return rows;
}

// The fixture with the XdgF address and script swapped for a TEST address, so a
// test key can sign the real 170-row shape. Txids, vouts, amounts and heights
// stay the real ones.
static std::string fixture_for(const char* addr)
{
    std::string j = read_fixture(kFixtureName);
    const std::string from_a = testvec::kDonationAddress, from_s = testvec::kDonationSpk;
    const std::string to_a = addr, to_s = spk_hex_of(addr);
    for (size_t at = j.find(from_a); at != std::string::npos; at = j.find(from_a, at + to_a.size()))
        j.replace(at, from_a.size(), to_a);
    for (size_t at = j.find(from_s); at != std::string::npos; at = j.find(from_s, at + to_s.size()))
        j.replace(at, from_s.size(), to_s);
    return j;
}

static std::string gau_json(const char* addr, const std::vector<Row>& rows)
{
    std::string j = "[";
    for (size_t i = 0; i < rows.size(); ++i) {
        const Row& r = rows[i];
        j += std::string(i ? "," : "") + "{\"address\":\"" + addr + "\",\"txid\":\"" + r.txid +
             "\",\"outputIndex\":" + std::to_string(r.vout) + ",\"script\":\"" + spk_hex_of(addr) +
             "\",\"satoshis\":" + std::to_string(r.sats) + ",\"height\":" + std::to_string(r.height) + "}";
    }
    return j + "]";
}

// The export v1 shape tools/export_utxos.py writes.
static std::string export_v1_json(const char* addr, int64_t tip, const std::vector<Row>& rows,
                                  const char* schema = kUtxoExportSchema, const char* coin = "dash",
                                  const char* network = "mainnet")
{
    std::string j = std::string("{\"schema\":\"") + schema + "\",\"coin\":\"" + coin + "\",\"network\":\"" +
                    network + "\",\"address\":\"" + addr + "\",\"tip_height\":" + std::to_string(tip) +
                    ",\"tip_hash\":\"" + std::string(64, 'b') + "\",\"utxos\":[";
    for (size_t i = 0; i < rows.size(); ++i) {
        const Row& r = rows[i];
        j += std::string(i ? "," : "") + "{\"txid\":\"" + r.txid + "\",\"vout\":" + std::to_string(r.vout) +
             ",\"satoshis\":" + std::to_string(r.sats) + ",\"height\":" + std::to_string(r.height) +
             ",\"confirmations\":" + std::to_string(tip - r.height + 1) +
             (r.coinbase.has_value() ? std::string(",\"coinbase\":") + (*r.coinbase ? "true" : "false") : "") +
             ",\"scriptPubKey\":\"" + spk_hex_of(addr) + "\"}";
    }
    return j + "]}";
}

static KeyInput key_of(KeySource src, const std::string& secret, const std::string& pass = {})
{
    KeyInput k;
    k.source = src;
    k.secret = secret;
    k.passphrase = pass;
    return k;
}

// The K7 funding set through the model: two synthetic UTXOs of the TREZOR key
// (11..:0 60000, 22..:1 40000), consolidated to itself, zero fee. The plan's
// unsigned bytes are kPyParityUnsignedHex.
static std::string k7_json()
{
    return gau_json(testvec::kPyParityAddress, {{txid_of_byte("11"), 0, 60000, 100, std::nullopt},
                                                {txid_of_byte("22"), 1, 40000, 200, std::nullopt}});
}

static bool drive_planned(DashInjectModel& m, const std::string& json, int64_t tip, const ScreenParams& sp,
                          const PlanParams& pp)
{
    return runs([&] {
        m.import_utxos(json, tip);
        m.rescreen(sp);
        m.plan(pp);
    }, "drive to Planned");
}

static bool sign_with(DashInjectModel& m, const KeyInput& k, bool burn = false)
{
    return runs([&] {
        m.load_key(k);
        m.set_gate(true, burn, kSpendWord);
        m.sign();
    }, "load_key + sign");
}

static std::vector<std::string> card_texts(const DashInjectModel& m)
{
    return {m.import_card(), m.screen_card(), m.plan_summary(), m.key_card(), m.sign_card(),
            m.manifest_json(), m.inject_file()};
}

namespace mj = c2w::hdkeys::mjson;

static const mj::JVal* jpath(const mj::JVal& root, std::initializer_list<const char*> keys)
{
    const mj::JVal* v = &root;
    for (const char* k : keys) {
        if (!v) return nullptr;
        v = v->find(k);
    }
    return v;
}
static int64_t jint(const mj::JVal* v) { return v && v->t == mj::JVal::T::Num ? static_cast<int64_t>(v->num) : -1; }
static std::string jstr(const mj::JVal* v) { return v && v->is_str() ? v->str : std::string("<missing>"); }

// ── S2-K1 export v1 ─────────────────────────────────────────────────────────

static void test_s2_k1_export_v1()
{
    std::printf("[S2-K1 export v1 intake (tools/export_utxos.py shape)]\n");
    std::vector<Row> rows = fixture_rows();
    CHECK(rows.size() == 170, "fixture rows");
    size_t n_false = 0;
    for (Row& r : rows) {
        r.coinbase = r.vout != 1; // the exporter's gettxout flags; the one vout-1 row is non-coinbase here
        n_false += r.vout == 1;
    }
    const std::string good = export_v1_json(testvec::kDonationAddress, kFixtureTip, rows);
    UtxoImport imp;
    CHECK(runs([&] { imp = parse_utxo_json(good, 0, false); }, "export v1") && imp.source == UtxoSource::ExportV1,
          "auto-detected as export v1");
    CHECK(imp.utxos.size() == 170 && imp.total == 60963705 && imp.tip_height == kFixtureTip &&
              imp.tip_hash == std::string(64, 'b') && imp.address == testvec::kDonationAddress,
          "170 rows, 60963705 duffs, tip + hash, address");
    size_t got_false = 0;
    bool flags_known = true;
    for (const Utxo& u : imp.utxos) {
        flags_known = flags_known && u.coinbase.has_value();
        got_false += u.coinbase.has_value() && !*u.coinbase;
    }
    CHECK(imp.coinbase_flags && flags_known && got_false == n_false && n_false == 1, "coinbase flags taken as given");

    auto refuses = [&](const std::string& json, const char* needle, const char* what) {
        CHECK(aborts_with([&] { parse_utxo_export_v1(json, false); }, needle), what);
    };
    refuses(export_v1_json(testvec::kDonationAddress, kFixtureTip, rows, "c2wallet-utxo-export/2"), "schema",
            "another schema aborts");
    refuses(export_v1_json(testvec::kDonationAddress, kFixtureTip, rows, kUtxoExportSchema, "btc"), "coin",
            "coin != dash aborts");
    refuses(export_v1_json(testvec::kDonationAddress, kFixtureTip, rows, kUtxoExportSchema, "dash", "testnet"),
            "network", "network mismatch aborts");
    std::string stated = export_v1_json(DUMMY_ADDR0, kFixtureTip, {{txid_of_byte("aa"), 0, 5000, 100, true}});
    const std::string addr_field = std::string("\"address\":\"") + DUMMY_ADDR0 + "\"";
    stated.replace(stated.find(addr_field), addr_field.size(), std::string("\"address\":\"") + DUMMY_ADDR1 + "\"");
    refuses(stated, "not the address the scripts pay", "stated address != the scripts' address aborts");
    refuses(export_v1_json(testvec::kDonationAddress, 0, {}), "tip_height", "tip_height 0 aborts");
    std::string mixed = good;
    const std::string c36484 = "\"confirmations\":36484";
    mixed.replace(mixed.find(c36484), c36484.size(), "\"confirmations\":36485");
    refuses(mixed, "two different tips", "confirmations != tip - height + 1 aborts (two tips mixed)");
    CHECK(aborts_with([&] { parse_utxo_json(good, kFixtureTip, false); }, "own tip"),
          "a typed tip with an export v1 aborts");

    // A row without a coinbase flag is treated as coinbase, and the flags are no longer complete.
    std::vector<Row> partial = rows;
    partial[0].coinbase = std::nullopt;
    UtxoImport pi = parse_utxo_export_v1(export_v1_json(testvec::kDonationAddress, kFixtureTip, partial), false);
    CHECK(!pi.coinbase_flags && pi.utxos[0].coinbase == std::optional<bool>(true), "absent flag => coinbase");
}

// ── S2-K3 target-height re-screen ───────────────────────────────────────────

static void test_s2_k3_rescreen()
{
    std::printf("[S2-K3 maturity at a target landing height]\n");
    const auto h160 = addr_to_h160(DUMMY_ADDR0, false);
    const std::string spk = spk_hex_of(DUMMY_ADDR0);
    const int64_t tip = 2563900;
    Utxo young = mk_utxo(txid_of_byte("a1"), 0, 50000, tip - 2563881 + 1, spk);
    young.height = 2563881;

    // Consensus floor (min_conf 100): spendable from h + 100.
    TargetScreen at = rescreen_at_height({young}, h160, tip, 2563981, 100, 0, true);
    CHECK(at.screen.spendable.size() == 1 && at.screen.immature.empty(), "h=2563881 spendable at H=2563981 (min_conf 100)");
    TargetScreen before = rescreen_at_height({young}, h160, tip, 2563980, 100, 0, true);
    CHECK(before.screen.immature.size() == 1 && matures_in(young, tip, 2563980, 100) == 1,
          "H=2563980: immature, matures in 1");
    CHECK(contains(describe_skipped(before.screen, 100, 0), "matures in 1 block"), "summary: matures in 1 block");
    // The default min_conf 101 keeps one block of slack.
    CHECK(rescreen_at_height({young}, h160, tip, 2563981, kDefaultMinConf, 0, true).screen.immature.size() == 1 &&
              rescreen_at_height({young}, h160, tip, 2563982, kDefaultMinConf, 0, true).screen.spendable.size() == 1,
          "min_conf 101: immature at 2563981, spendable at 2563982");
    CHECK(at.safe_from_height == 2563981 && at.youngest_height == 2563881, "safe_from = max(h) + 100 = 2563981");

    // Height unknown but the tip known: the same projection from confirmations.
    Utxo no_h = young;
    no_h.height = 0;
    CHECK(confirmations_at(no_h, tip, 2563981) == confirmations_at(young, tip, 2563981) &&
              confirmations_at(young, tip, 2563981) == 100,
          "conf_at(H) = H - h, equal with or without the height (tip known)");
    CHECK(effective_height(no_h, tip) == 2563881, "effective height = tip - conf + 1");
    Utxo unconf = mk_utxo(txid_of_byte("a2"), 0, 50000, 0, spk);
    CHECK(confirmations_at(unconf, tip, tip + 500) == 0, "an unconfirmed row is never projected");

    // The immature list comes ordered by height.
    Utxo b = young, c = young;
    b.txid = txid_of_byte("b2"); b.height = 2563890; b.confirmations = tip - b.height + 1;
    c.txid = txid_of_byte("c3"); c.height = 2563885; c.confirmations = tip - c.height + 1;
    TargetScreen ord = rescreen_at_height({b, young, c}, h160, tip, tip + 2, kDefaultMinConf, 0, true);
    CHECK(ord.screen.immature.size() == 3 && ord.screen.immature[0].height == 2563881 &&
              ord.screen.immature[1].height == 2563885 && ord.screen.immature[2].height == 2563890,
          "immature ordered by height");

    // A known non-coinbase input needs one block.
    Utxo nc = mk_utxo(txid_of_byte("d4"), 0, 50000, 1, spk, false);
    nc.height = tip;
    TargetScreen ncs = rescreen_at_height({young, nc}, h160, tip, 2563982, kDefaultMinConf, 0, true);
    CHECK(ncs.screen.spendable.size() == 2 && ncs.safe_from_height == 2563981,
          "known non-coinbase at the tip: spendable next block; safe_from stays max(h+100, h_nc+1)");

    CHECK(aborts_with([&] { rescreen_at_height({young}, h160, tip, tip, 100, 0, true); }, "not above"),
          "target <= tip aborts");

    // The real fixture at the default target (tip + 2).
    UtxoImport imp = parse_getaddressutxos(read_fixture(kFixtureName), kFixtureTip, false);
    TargetScreen fx = rescreen_at_height(imp.utxos, addr_to_h160(testvec::kDonationAddress, false), kFixtureTip,
                                         kFixtureTip + 2, kDefaultMinConf, 2, true);
    CHECK(fx.screen.spendable.size() == 128 && fx.screen.immature.empty() && fx.screen.dust.size() == 42,
          "fixture at tip+2: 128 / 0 / 42");
    CHECK(fx.safe_from_height == 2563981 && fx.youngest_height == 2563881, "fixture: safe_from 2563981, youngest 2563881");
}

// ── S2-K4 state machine ─────────────────────────────────────────────────────

static void test_s2_k4_state_machine()
{
    std::printf("[S2-K4 model state machine: no skipped stage, invalidation, the literal gate]\n");
    DashInjectModel m;
    const KeyInput wif = key_of(KeySource::Wif, testvec::kK7Wif);
    CHECK(m.stage() == InjectStage::Empty && !m.armed(), "starts Empty, not armed");
    CHECK(aborts_with([&] { m.rescreen({}); }, "no stage can be skipped"), "screen before import aborts");
    CHECK(aborts_with([&] { m.plan({}); }, "no stage can be skipped"), "plan before screen aborts");
    CHECK(aborts_with([&] { m.load_key(wif); }, "no stage can be skipped"), "key before plan aborts");
    CHECK(aborts_with([&] { m.sign(); }, "no stage can be skipped"), "sign before key aborts");

    m.import_utxos(k7_json(), 1000);
    CHECK(m.stage() == InjectStage::Imported, "Imported");
    CHECK(aborts([&] { m.plan({}); }), "plan before screen aborts (after import)");
    m.rescreen({});
    CHECK(m.stage() == InjectStage::Screened && m.target_screen().target_height == 1002, "Screened at tip + 2");
    CHECK(aborts([&] { m.load_key(wif); }), "key before plan aborts (after screen)");
    m.plan({});
    CHECK(m.stage() == InjectStage::Planned && m.planned_tx_count() == 1, "Planned");
    m.set_gate(true, false, kSpendWord);
    CHECK(!m.armed() && aborts([&] { m.sign(); }), "no key: not armed, sign aborts");

    m.load_key(wif);
    CHECK(m.stage() == InjectStage::KeyBound && m.has_key() && m.keys_wiped() == 0, "KeyBound");
    CHECK(!m.armed(), "a fresh key is not armed (gate cleared)");
    m.set_gate(true, false, "spend");
    CHECK(!m.armed(), "\"spend\" is not the literal SPEND");
    m.set_gate(true, false, "SPEND ");
    CHECK(!m.armed(), "\"SPEND \" is not the literal SPEND");
    m.set_gate(false, false, kSpendWord);
    CHECK(!m.armed(), "SPEND without \"reviewed\" is not armed");
    CHECK(aborts_with([&] { m.sign(); }, "not armed"), "sign while not armed aborts");
    CHECK(m.has_key(), "a refused (unarmed) sign attempt touched nothing");
    m.set_gate(true, false, kSpendWord);
    CHECK(m.armed(), "reviewed + SPEND arms a consolidation");

    // A re-import after the plan invalidates the plan and wipes the key.
    m.import_utxos(k7_json(), 1000);
    CHECK(m.stage() == InjectStage::Imported && !m.has_key() && m.keys_wiped() == 1 && !m.sweep_plan() && !m.armed(),
          "re-import: plan dropped, key wiped (sentinel 1)");
    // A re-plan wipes the key too; a re-screen drops the plan.
    m.rescreen({});
    m.plan({});
    m.load_key(wif);
    m.plan({});
    CHECK(m.stage() == InjectStage::Planned && !m.has_key() && m.keys_wiped() == 2, "re-plan: key wiped (sentinel 2)");
    m.load_key(wif);
    m.rescreen({});
    CHECK(m.stage() == InjectStage::Screened && !m.has_key() && !m.sweep_plan() && m.keys_wiped() == 3,
          "re-screen: plan dropped, key wiped (sentinel 3)");
    // A refused import leaves the model empty.
    CHECK(aborts([&] { m.import_utxos("[1,", 1000); }) && m.stage() == InjectStage::Empty, "a refused import -> Empty");
    // A refused plan leaves Screened.
    m.import_utxos(k7_json(), 1000);
    m.rescreen({});
    PlanParams bad;
    bad.fee_mode = FeeMode::Relay; // rate 0
    CHECK(aborts([&] { m.plan(bad); }) && m.stage() == InjectStage::Screened, "a refused plan -> Screened");
    // A wrong expected address refuses the import.
    CHECK(aborts_with([&] { m.import_utxos(k7_json(), 1000, DUMMY_ADDR0); }, "not the expected"),
          "expected_address mismatch aborts");

    // A sign that fails AFTER the key was used still wipes it: a relay
    // collateral at 1 duff/B signed with an uncompressed key pays below the
    // minimum relay fee (the classic fee estimate is 148 B/input).
    DashInjectModel u;
    std::vector<Row> rows;
    for (int i = 0; i < 10; ++i) rows.push_back({txid_of_byte(i < 5 ? "5a" : "5b"), static_cast<uint32_t>(i), 20000000, 100, std::nullopt});
    PlanParams coll;
    coll.mode = OutputMode::Collateral;
    coll.fee_mode = FeeMode::Relay;
    coll.fee_rate_per_byte = 1;
    coll.gov_hash_display = testvec::kOnchainGovHash;
    CHECK(drive_planned(u, gau_json(testvec::kUncompressedAddr001, rows), 1000, {}, coll), "uncompressed relay collateral planned");
    u.load_key(key_of(KeySource::Wif, testvec::kUncompWif));
    u.set_gate(true, false, kSpendWord);
    CHECK(!u.armed(), "collateral: not armed without the burn box");
    u.set_gate(true, true, kSpendWord);
    CHECK(u.armed(), "collateral: reviewed + burn box + SPEND arms");
    CHECK(aborts_with([&] { u.sign(); }, "minimum relay fee"), "below-min-relay-fee signature is refused");
    CHECK(!u.has_key() && u.keys_wiped() == 1 && u.stage() == InjectStage::Planned && u.inject_file().empty(),
          "the failed sign wiped the key, emitted nothing, left the plan");
}

// ── S2-K5 key paths ─────────────────────────────────────────────────────────

static void test_s2_k5_key_paths()
{
    std::printf("[S2-K5 key paths: every format signs the K7 vector byte-exact]\n");
    DashInjectModel m;
    CHECK(drive_planned(m, k7_json(), 1000, {}, {}), "K7 set planned");
    CHECK(m.sweep_plan() && hexstr(m.sweep_plan()->txs.at(0).unsigned_tx) == testvec::kPyParityUnsignedHex,
          "model plan == the python unsigned vector");

    struct Path {
        const char* name;
        KeyInput key;
        const char* want_path;
    };
    KeyInput mn = key_of(KeySource::Mnemonic, DUMMY_MNEMONIC, testvec::kPyParityPassphrase);
    std::vector<Path> paths = {
        {"mnemonic + passphrase", mn, "m/44'/5'/0'/0/0"},
        {"WIF (compressed)", key_of(KeySource::Wif, std::string("  ") + testvec::kK7Wif + "\n"), "imported WIF key"},
        {"BIP38 (DASH address hash)", key_of(KeySource::Bip38, testvec::kK7Bip38Dash, testvec::kBip38Pass),
         "BIP38 key (address hash over the DASH address)"},
        {"BIP38 (BTC address hash)", key_of(KeySource::Bip38, testvec::kK7Bip38BtcHash, testvec::kBip38Pass),
         "BIP38 key (address hash over the BTC address)"},
        {"descriptor pkh([fp/44'/5'/0']xprv/0/*)", key_of(KeySource::Descriptor, testvec::kK7Descriptor),
         "[b4e3f5ed]m/44'/5'/0'/0/0"},
        {"JSON keystore: WIF list with a decoy first",
         key_of(KeySource::JsonKeystore, std::string("{\"keys\":[\"") + testvec::kDecoyWif + "\",\"" + testvec::kK7Wif + "\"]}"),
         "keystore item 2 (keys)"},
        {"JSON keystore: mnemonic + sibling passphrase",
         key_of(KeySource::JsonKeystore, "{\"mnemonic\":\"" + DUMMY_MNEMONIC + "\",\"passphrase\":\"TREZOR\"}"),
         "m/44'/5'/0'/0/0"},
        {"JSON keystore: account xprv",
         key_of(KeySource::JsonKeystore, std::string("{\"xprv\":\"") + testvec::kK7AccountXprv + "\"}"),
         "keystore xprv (account key)/0/0"},
    };
    for (const Path& p : paths) {
        const bool ok = sign_with(m, p.key);
        std::printf("    %-44s %s\n", p.name, ok && m.signed_txs().size() == 1 && m.signed_txs()[0].hex == testvec::kPyParitySignedHex ? "byte-exact" : "MISMATCH");
        CHECK(ok && m.signed_txs().size() == 1 && m.signed_txs()[0].hex == testvec::kPyParitySignedHex &&
                  m.signed_txs()[0].txid == testvec::kPyParityTxid,
              p.name);
        CHECK(contains(m.manifest_json(), p.want_path), "manifest names the key path");
    }

    // The uncompressed WIF signs its own python vector byte-exact.
    DashInjectModel u;
    CHECK(drive_planned(u, gau_json(testvec::kUncompressedAddr001, {{txid_of_byte("33"), 0, 50000, 100, std::nullopt},
                                                                     {txid_of_byte("44"), 2, 40000, 100, std::nullopt}}),
                        1000, {}, {}),
          "uncompressed set planned");
    CHECK(u.sweep_plan() && hexstr(u.sweep_plan()->txs.at(0).unsigned_tx) == testvec::kUncompUnsignedHex,
          "model plan == the python uncompressed unsigned vector");
    CHECK(sign_with(u, key_of(KeySource::Wif, testvec::kUncompWif)) && u.signed_txs().size() == 1 &&
              u.signed_txs()[0].hex == testvec::kUncompSignedHex && u.signed_txs()[0].txid == testvec::kUncompTxid,
          "uncompressed WIF signs the python vector byte-exact (31-byte s edge)");
    CHECK(contains(u.manifest_json(), "\"encoding\": \"uncompressed\""), "manifest: encoding uncompressed");

    // Refusals: every one leaves the model without a key.
    auto refused = [&](const KeyInput& k, const char* needle, const char* what) {
        CHECK(aborts_with([&] { m.load_key(k); }, needle) && !m.has_key() && m.stage() == InjectStage::Planned, what);
    };
    refused(key_of(KeySource::Wif, testvec::kDecoyWif), "is for", "a WIF for another address aborts");
    refused(key_of(KeySource::Wif, testvec::kK7WifBtcVersion), "version byte", "a non-DASH WIF version aborts");
    refused(key_of(KeySource::Wif, std::string(testvec::kK7Wif).substr(1)), "does not decode", "a broken WIF aborts");
    refused(key_of(KeySource::Bip38, testvec::kK7Bip38Dash, "wrong"), "wrong passphrase", "BIP38 wrong passphrase aborts");
    // A public BIP38 vector decrypts (BTC address hash) but controls another address.
    refused(key_of(KeySource::Bip38, "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo", "TestingOneTwoThree"),
            "is for", "the public BIP38 vector decrypts but binds elsewhere");
    std::string bad_cs = testvec::kK7Descriptor;
    bad_cs.back() = bad_cs.back() == 'c' ? 'd' : 'c';
    refused(key_of(KeySource::Descriptor, bad_cs), "checksum", "a descriptor with a wrong checksum aborts");
    refused(key_of(KeySource::Descriptor, "pkh([b4e3f5ed/44'/5'/0']xprv9zUwecf3TjfmaeR6LkfC8LhRUAHgddJ4UkuNDpLQyCxucM7SbvN7h6GDxkfW8Zwx6yGrvdAao4EvjJoMPM5ModJbcqR3AE5yUwEZoAZtVFd/1/*)"),
            "produces", "a descriptor whose range misses the address aborts");
    refused(key_of(KeySource::JsonKeystore, std::string("{\"keys\":[\"") + testvec::kDecoyWif + "\"]}"), "none of the",
            "a keystore without the funding key aborts");
    refused(key_of(KeySource::Mnemonic, DUMMY_MNEMONIC, "not-trezor"), "REFUSING", "a mnemonic with the wrong passphrase aborts");

    // The hdkeys BIP38 overload: the BIP38-specified BTC hash alone rejects a
    // DASH-hashed key; naming the DASH version byte accepts it.
    CHECK(!c2w::hdkeys::decode_bip38(testvec::kK7Bip38Dash, testvec::kBip38Pass).ok,
          "decode_bip38 (BTC address hash only) refuses the DASH-hashed key");
    c2w::hdkeys::Bip38Decode d38 = c2w::hdkeys::decode_bip38(testvec::kK7Bip38Dash, testvec::kBip38Pass, {0x4c});
    CHECK(d38.ok && d38.address_version == 0x4c && d38.compressed, "decode_bip38 {0x4c} accepts it");

    // bind_found_key: the address string alone is not enough.
    FoundKey k = load_funding_key(key_of(KeySource::Wif, testvec::kK7Wif), testvec::kPyParityAddress, false);
    FoundKey other = load_funding_key(key_of(KeySource::Wif, testvec::kDecoyWif), DUMMY_ADDR1, false);
    other.address = testvec::kPyParityAddress;
    CHECK(!aborts([&] { bind_found_key(k, testvec::kPyParityAddress, false); }) &&
              aborts_with([&] { bind_found_key(other, testvec::kPyParityAddress, false); }, "does not hash"),
          "bind: the pubkey must hash to the funding address");
}

// ── S2-K6 end to end on the real fixture with a TEST key ────────────────────

static void test_s2_k6_end_to_end()
{
    std::printf("[S2-K6 end to end on the 170-row fixture (XdgF swapped for the TEST key's address)]\n");
    DashInjectModel m;
    ScreenParams sp;
    sp.dust_floor = 2;
    CHECK(drive_planned(m, fixture_for(testvec::kPyParityAddress), kFixtureTip, sp, {}), "fixture planned");
    CHECK(m.target_screen().target_height == kFixtureTip + 2 && m.target_screen().screen.spendable.size() == 128 &&
              m.target_screen().screen.dust.size() == 42 && m.target_screen().screen.immature.empty(),
          "screen at tip+2: 128 / 0 / 42");
    CHECK(m.sweep_plan() && m.sweep_plan()->txs.size() == 1 && m.sweep_plan()->txs[0].inputs.size() == 128 &&
              m.sweep_plan()->txs[0].est_signed_bytes == 23212,
          "plan before the key: 1 tx, 128 inputs, worst case 23212 B (181 B/input)");
    m.load_key(key_of(KeySource::Wif, testvec::kK7Wif));
    CHECK(m.sweep_plan()->txs[0].est_signed_bytes == 19116, "re-planned for the compressed key: est 19116 B");
    m.set_gate(true, false, kSpendWord);
    CHECK(runs([&] { m.sign(); }, "sign"), "signed");
    CHECK(m.stage() == InjectStage::Signed && !m.has_key(), "Signed; key wiped");
    if (m.signed_txs().size() != 1) { CHECK(false, "one signed tx"); return; }
    const SignedTx& st = m.signed_txs()[0];
    std::printf("    e2e zero-fee: %zu inputs, %zu B signed (est 19116), value %lld duffs, txid %s\n",
                m.sweep_plan()->txs[0].inputs.size(), st.size, (long long)m.sweep_plan()->txs[0].value_out, st.txid.c_str());
    CHECK(st.size <= 18988 && st.size == st.hex.size() / 2, "actual size <= 18988 (low-S compressed) <= estimate");
    CHECK(!aborts([&] { verify_signed_funding_tx(st.hex, testvec::kPyParityAddress, false); }), "re-verifies");
    auto outs = parse_outputs(H(st.hex));
    CHECK(outs.size() == 1 && outs[0].value == 60963663 && hexstr(outs[0].script) == spk_hex_of(testvec::kPyParityAddress),
          "one output, 60963663 duffs back to the funding address, fee 0");
    std::string err;
    auto parsed = c2w::artifact::SignedContainer::parse(m.inject_file(), err);
    CHECK(m.inject_file() == st.hex + "\n" && parsed && parsed->tx_hexes.size() == 1 && parsed->tx_hexes[0] == st.hex,
          "inject file = one line, round-trips through SignedContainer::parse");
    std::string why;
    CHECK(c2w::artifact::accept_as_signed(H(st.hex), why), "accept_as_signed (the PageAirGap confusion guard)");

    // The same set through the RELAY (fee-paying) mode at 1 duff/B.
    DashInjectModel r;
    PlanParams rp;
    rp.fee_mode = FeeMode::Relay;
    rp.fee_rate_per_byte = 1;
    CHECK(drive_planned(r, fixture_for(testvec::kPyParityAddress), kFixtureTip, sp, rp), "relay planned");
    CHECK(sign_with(r, key_of(KeySource::Wif, testvec::kK7Wif)) && r.signed_txs().size() == 1, "relay signed");
    if (r.signed_txs().size() == 1) {
        const SweepTxPlan& t = r.sweep_plan()->txs[0];
        std::printf("    e2e relay 1 duff/B: %zu inputs, %zu B signed, fee %lld duffs, value %lld duffs\n",
                    t.inputs.size(), r.signed_txs()[0].size, (long long)t.fee, (long long)t.value_out);
        CHECK(t.fee == 19116 && t.value_out == 60944547 && r.planned_fee() == 19116,
              "relay fee = 1 x 19116 B = 19116 duffs; output 60944547");
        CHECK(t.fee >= static_cast<int64_t>(r.signed_txs()[0].size), "real rate >= 1 duff/B");
        auto ro = parse_outputs(H(r.signed_txs()[0].hex));
        CHECK(ro.size() == 1 && ro[0].value + t.fee == 60963663, "inputs = output + fee");
        CHECK(contains(r.manifest_json(), "\"fee_mode\": \"relay\"") &&
                  contains(r.manifest_json(), "\"total_fee\": 19116") &&
                  contains(r.manifest_json(), "sendrawtransaction"),
              "relay manifest: fee mode, total fee, submit hint");
    }
}

// ── S2-K7 manifest ──────────────────────────────────────────────────────────

static void test_s2_k7_manifest()
{
    std::printf("[S2-K7 manifest: round trip, digests, maturity, no secrets, no clock]\n");
    DashInjectModel m;
    ScreenParams sp;
    sp.dust_floor = 2;
    if (!drive_planned(m, fixture_for(testvec::kPyParityAddress), kFixtureTip, sp, {}) ||
        !sign_with(m, key_of(KeySource::Wif, testvec::kK7Wif))) {
        CHECK(false, "manifest run");
        return;
    }
    const std::string man = m.manifest_json();
    mj::ParseResult pr = mj::parse(man);
    CHECK(pr.ok && pr.root.is_obj(), "manifest parses (MiniJson)");
    const mj::JVal& r = pr.root;
    const std::string file = m.inject_file();
    const std::vector<uint8_t> fb(file.begin(), file.end());
    CHECK(jstr(r.find("schema")) == kInjectManifestSchema && jstr(r.find("coin")) == "dash" &&
              jstr(r.find("network")) == "mainnet" && jstr(r.find("mode")) == "consolidate" &&
              jstr(r.find("fee_mode")) == "inject-zero-fee",
          "schema / coin / network / mode / fee_mode");
    CHECK(jstr(r.find("hex_file_sha256d")) == c2w::artifact::sha256d_display(fb), "hex_file_sha256d == sha256d_display(file bytes)");
    const auto h1 = c2w::artifact::sha256(fb);
    CHECK(jstr(r.find("hex_file_sha256")) == hexstr(std::vector<uint8_t>(h1.begin(), h1.end())), "hex_file_sha256 == sha256sum");
    CHECK(jint(r.find("tx_count")) == 1 && r.find("txs") && r.find("txs")->arr.size() == 1, "tx_count 1");
    if (r.find("txs") && r.find("txs")->arr.size() == 1) {
        const mj::JVal& t = r.find("txs")->arr[0];
        CHECK(jstr(t.find("txid")) == m.signed_txs()[0].txid && jint(t.find("size")) == (int64_t)m.signed_txs()[0].size &&
                  jint(t.find("vin")) == 128 && jint(t.find("vout")) == 1 && jint(t.find("value_out")) == 60963663 &&
                  jint(t.find("fee")) == 0 && jint(t.find("est_signed_bytes")) == 19116,
              "tx: txid, size, vin 128, vout 1, value_out, fee 0, est");
        const mj::JVal* ins = t.find("inputs");
        CHECK(ins && ins->arr.size() == 128 && jint(ins->arr[0].find("height")) > 0 &&
                  ins->arr[0].find("coinbase") && ins->arr[0].find("coinbase")->t == mj::JVal::T::Null,
              "inputs: 128 with heights, coinbase unknown -> null");
    }
    CHECK(jint(jpath(r, {"maturity", "safe_from_height"})) == 2563881 + 100 &&
              jint(jpath(r, {"maturity", "youngest_input_height"})) == 2563881 &&
              jint(jpath(r, {"maturity", "screen_tip_height"})) == kFixtureTip &&
              jint(jpath(r, {"maturity", "target_height"})) == kFixtureTip + 2 &&
              jint(jpath(r, {"maturity", "min_confirmations"})) == kDefaultMinConf,
          "maturity: safe_from = max(h) + 100 = 2563981, youngest, tip, target, min_conf");
    CHECK(jint(jpath(r, {"skipped", "dust"})) == 42 && jint(jpath(r, {"skipped", "dust_floor"})) == 2 &&
              jpath(r, {"skipped", "immature"}) && jpath(r, {"skipped", "immature"})->arr.empty(),
          "skipped: 42 dust at floor 2, 0 immature");
    CHECK(jstr(jpath(r, {"node_requirements", "lane"})).find("pin|inject") == 0 &&
              jint(jpath(r, {"node_requirements", "max_tx_bytes"})) == 100000 &&
              jint(jpath(r, {"node_requirements", "earliest_block_height"})) == 2563981,
          "node_requirements: lane, cap, earliest height");
    CHECK(jstr(jpath(r, {"key", "path"})) == "imported WIF key" && jstr(jpath(r, {"key", "encoding"})) == "compressed",
          "key: public description only");
    // No clock: no key anywhere in the document names a time.
    bool clockless = true;
    std::vector<const mj::JVal*> stack = {&r};
    while (!stack.empty()) {
        const mj::JVal* v = stack.back();
        stack.pop_back();
        for (const auto& kv : v->obj) {
            if (contains(kv.first, "time") || contains(kv.first, "date") || contains(kv.first, "clock")) clockless = false;
            stack.push_back(&kv.second);
        }
        for (const auto& e : v->arr) stack.push_back(&e);
    }
    CHECK(clockless, "no timestamp field");

    // Deterministic: the same plan signed again gives the same bytes.
    const std::string first = man;
    CHECK(sign_with(m, key_of(KeySource::Wif, testvec::kK7Wif)) && m.manifest_json() == first, "manifest is deterministic");
}

// ── S2-K8 collateral ────────────────────────────────────────────────────────

static void test_s2_k8_collateral()
{
    std::printf("[S2-K8 direct governance collateral: shortfall, then a funded plan]\n");
    PlanParams pp;
    pp.mode = OutputMode::Collateral;
    pp.gov_hash_display = testvec::kOnchainGovHash;
    ScreenParams all;
    all.dust_floor = 0;
    DashInjectModel m;
    m.import_utxos(fixture_for(testvec::kPyParityAddress), kFixtureTip);
    m.rescreen(all);
    CHECK(aborts_with([&] { m.plan(pp); }, "short 0.39036295 DASH") && m.stage() == InjectStage::Screened,
          "fixture (all 170 inputs, 0.60963705 DASH): refused, short 0.39036295 DASH to the 1-DASH burn");
    PlanParams rp = pp;
    rp.fee_mode = FeeMode::Relay;
    rp.fee_rate_per_byte = 1;
    CHECK(aborts_with([&] { m.plan(rp); }, "short 0.39036295 DASH"), "relay mode refuses the same shortfall");
    PlanParams split = pp;
    split.max_inputs_per_tx = 85;
    CHECK(aborts_with([&] { m.plan(split); }, "never split"), "collateral + split knob aborts");

    // +0.5 DASH of a KNOWN non-coinbase output at 1 confirmation (export v1 flags).
    std::vector<Row> rows = fixture_rows();
    for (Row& r : rows) r.coinbase = true;
    rows.push_back({txid_of_byte("5e"), 0, 50000000, kFixtureTip, false});
    DashInjectModel c;
    ScreenParams sp;
    sp.dust_floor = 2;
    CHECK(drive_planned(c, export_v1_json(testvec::kPyParityAddress, kFixtureTip, rows), 0, sp, pp), "funded collateral planned");
    const CollateralPlan* cp = c.collateral_plan();
    CHECK(cp && cp->selected.size() == 129 && cp->total_in == 110963663 && cp->fee == 0 && cp->change == 10963663,
          "129 inputs (128 + the 1-conf non-coinbase), 1.10963663 DASH, fee 0, change 0.10963663");
    CHECK(cp && hexstr(cp->op_return_script) == testvec::kOnchainOpReturn, "OP_RETURN == 6a20 || reversed(display hash)");
    CHECK(c.plan_safe_from_height() == kFixtureTip + 1, "safe_from = max(2563881 + 100, 2563986 + 1) = 2563987");
    CHECK(!c.destination_is_external(), "change to the funding address (not EXTERNAL)");
    c.load_key(key_of(KeySource::Wif, testvec::kK7Wif));
    c.set_gate(true, false, kSpendWord);
    CHECK(!c.armed(), "collateral: no burn box, not armed");
    c.set_gate(true, true, kSpendWord);
    CHECK(runs([&] { c.sign(); }, "collateral sign") && c.signed_txs().size() == 1, "collateral signed");
    if (c.signed_txs().size() == 1) {
        auto outs = parse_outputs(H(c.signed_txs()[0].hex));
        CHECK(outs.size() == 2 && outs[0].value == kCoin && hexstr(outs[0].script) == testvec::kOnchainOpReturn &&
                  outs[1].value == 10963663 && hexstr(outs[1].script) == spk_hex_of(testvec::kPyParityAddress),
              "signed: 1 DASH OP_RETURN burn + change to the funding address");
        std::printf("    collateral: %zu inputs, %zu B signed\n", cp->selected.size(), c.signed_txs()[0].size);
        CHECK(contains(c.manifest_json(), "\"mode\": \"collateral\"") &&
                  contains(c.manifest_json(), (std::string("\"gov_hash\": \"") + testvec::kOnchainGovHash + "\"").c_str()),
              "manifest: mode collateral + gov hash");
    }
    PlanParams ext = pp;
    ext.change_address = DUMMY_ADDR0;
    c.rescreen(sp);
    c.plan(ext);
    CHECK(c.destination_is_external() && contains(c.plan_summary(), "EXTERNAL"), "change elsewhere: EXTERNAL");
}

// ── S2-K9 secret hygiene ────────────────────────────────────────────────────

static void test_s2_k9_secret_hygiene()
{
    std::printf("[S2-K9 secret hygiene: no output carries a secret; the key dies at sign]\n");
    c2w::hdkeys::WifDecode wd = c2w::hdkeys::decode_wif(testvec::kK7Wif);
    const std::string scalar_hex = hexstr(std::vector<uint8_t>(wd.scalar.data(), wd.scalar.data() + wd.scalar.size()));
    CHECK(wd.ok && scalar_hex.size() == 64, "test scalar decoded for the grep");
    const std::vector<std::string> secrets = {
        testvec::kK7Wif, testvec::kK7WifBtcVersion, testvec::kK7Bip38Dash, testvec::kK7Bip38BtcHash,
        testvec::kK7AccountXprv, testvec::kDecoyWif, testvec::kUncompWif, testvec::kBip38Pass,
        testvec::kPyParityPassphrase, "abandon", DUMMY_MNEMONIC, scalar_hex};
    std::vector<std::string> outputs;

    const std::vector<KeyInput> keys = {
        key_of(KeySource::Mnemonic, DUMMY_MNEMONIC, testvec::kPyParityPassphrase),
        key_of(KeySource::Wif, testvec::kK7Wif),
        key_of(KeySource::Bip38, testvec::kK7Bip38Dash, testvec::kBip38Pass),
        key_of(KeySource::Descriptor, testvec::kK7Descriptor),
        key_of(KeySource::JsonKeystore, std::string("{\"keys\":[\"") + testvec::kDecoyWif + "\",\"" + testvec::kK7Wif + "\"]}"),
    };
    for (const KeyInput& k : keys) {
        DashInjectModel m;
        ScreenParams sp;
        sp.dust_floor = 2;
        CHECK(drive_planned(m, fixture_for(testvec::kPyParityAddress), kFixtureTip, sp, {}), "planned");
        m.load_key(k);
        for (const std::string& t : card_texts(m)) outputs.push_back(t);
        const size_t before = m.keys_wiped();
        m.set_gate(true, false, kSpendWord);
        CHECK(runs([&] { m.sign(); }, "sign"), "signed");
        CHECK(!m.has_key() && m.keys_wiped() == before + 1 && contains(m.key_card(), "wiped"),
              "sentinel: the key was destroyed by sign");
        for (const std::string& t : card_texts(m)) outputs.push_back(t);
    }
    // Error messages of refused key inputs never quote them.
    DashInjectModel m;
    CHECK(drive_planned(m, k7_json(), 1000, {}, {}), "planned");
    std::string broken_desc = testvec::kK7Descriptor;
    broken_desc.replace(broken_desc.find("xprv9z") + 10, 1, "!");
    std::string broken_wif = std::string(testvec::kK7Wif).substr(0, 40) + "0";
    const std::vector<KeyInput> bad = {
        key_of(KeySource::Descriptor, broken_desc),
        key_of(KeySource::Wif, broken_wif),
        key_of(KeySource::Wif, testvec::kK7WifBtcVersion),
        key_of(KeySource::Bip38, testvec::kK7Bip38Dash, "wrong"),
        key_of(KeySource::JsonKeystore, std::string("{\"keys\":[\"") + testvec::kDecoyWif + "\"]"),
        key_of(KeySource::Mnemonic, DUMMY_MNEMONIC, "x"),
        key_of(KeySource::Mnemonic, std::string(DUMMY_MNEMONIC).replace(0, 7, "zzzzzzz"), ""),
    };
    size_t refused = 0;
    for (const KeyInput& k : bad) {
        try { m.load_key(k); }
        catch (const DashAbort& e) { ++refused; outputs.push_back(e.what()); }
    }
    CHECK(refused == bad.size(), "every bad key input is refused");
    bool clean = true;
    for (const std::string& o : outputs)
        for (const std::string& sec : secrets)
            if (!sec.empty() && o.find(sec) != std::string::npos) {
                clean = false;
                std::printf("    LEAK of a test secret in: %.80s...\n", o.c_str());
            }
    for (const std::string& o : outputs)
        if (o.find(broken_desc.substr(broken_desc.find("xprv9z"), 30)) != std::string::npos ||
            o.find(broken_wif) != std::string::npos)
            clean = false;
    CHECK(clean, "no card, summary, manifest, hex file or error message contains a test secret");
}

// ── S2-K10 split knob ───────────────────────────────────────────────────────

static void test_s2_k10_split()
{
    std::printf("[S2-K10 split knob: max_inputs_per_tx 85 on the fixture]\n");
    DashInjectModel m;
    ScreenParams sp;
    sp.dust_floor = 2;
    PlanParams pp;
    pp.max_inputs_per_tx = 85;
    CHECK(drive_planned(m, fixture_for(testvec::kPyParityAddress), kFixtureTip, sp, pp), "planned");
    const SweepBatchPlan* p = m.sweep_plan();
    CHECK(p && p->txs.size() == 2 && p->txs[0].inputs.size() == 85 && p->txs[1].inputs.size() == 43,
          "two txs: 85 + 43 inputs");
    CHECK(contains(m.plan_summary(), "SPLIT: 2 txs"), "the summary shows the split");
    CHECK(sign_with(m, key_of(KeySource::Wif, testvec::kK7Wif)) && m.signed_txs().size() == 2, "both signed");
    if (m.signed_txs().size() == 2) {
        CHECK(m.signed_txs()[0].size <= caps::kMaxInjectTxBytes && m.signed_txs()[1].size <= caps::kMaxInjectTxBytes,
              "both under the 100000 B cap");
        CHECK(m.inject_file() == m.signed_txs()[0].hex + "\n" + m.signed_txs()[1].hex + "\n", "emitted as two lines");
        CHECK(contains(m.manifest_json(), "\"tx_count\": 2"), "manifest tx_count 2");
    }
    // input_limit: the N oldest (the dry-run / tiny-landing knob of the test plan).
    PlanParams five;
    five.input_limit = 5;
    m.rescreen(sp);
    m.plan(five);
    const SweepBatchPlan* fp = m.sweep_plan();
    int64_t oldest_max = 0;
    if (fp) for (const Utxo& u : fp->txs[0].inputs) oldest_max = std::max(oldest_max, u.height);
    CHECK(fp && fp->txs.size() == 1 && fp->txs[0].inputs.size() == 5 && oldest_max < 2530000 &&
              contains(m.plan_summary(), "not selected (input limit 5): 123"),
          "input_limit 5: the five oldest, 123 left for later");
}

// ── S2-K11 node tripwires + S2-K13 relay fee mode ───────────────────────────

static_assert(kDefaultMinConf == kCoinbaseMaturity + 1, "S2-K11: the builder keeps one block of slack over consensus");
static_assert(caps::kMaxInjectTxBytes == 100000 && caps::kMaxInjectInputs == 1000, "S2-K11: node caps");
static_assert(kMinRelayFeePerByte == 1 && kMaxRelayFeePerByte * 1000 == 100000,
              "S2-K11: relay rate range == dashd min relay fee .. the collateral builder's ceiling");
static_assert(kP2pkhDustDuffs == 546, "S2-K11: Dash Core P2PKH dust threshold");

static void test_s2_k13_relay_fee_mode()
{
    std::printf("[S2-K13 relay (fee-paying) sweep: rate, money range, sign-time checks]\n");
    SweepRequest req = sweep_of(3, 70000);
    req.fee_mode = FeeMode::Relay;
    req.fee_rate_per_byte = 0;
    CHECK(aborts_with([&] { plan_sweep(req); }, "outside"), "relay rate 0 aborts");
    req.fee_rate_per_byte = kMaxRelayFeePerByte + 1;
    CHECK(aborts_with([&] { plan_sweep(req); }, "outside"), "relay rate 101 aborts");
    SweepRequest inj = sweep_of(3, 70000);
    inj.fee_rate_per_byte = 1;
    CHECK(aborts_with([&] { plan_sweep(inj); }, "needs fee rate 0"), "zero-fee mode with a rate aborts");

    req.fee_rate_per_byte = 2;
    req.key_encoding = PubkeyEncoding::Compressed;
    SweepBatchPlan p = plan_sweep(req);
    const int64_t est = 4 + 1 + 3 * 149 + 1 + 34 + 4;
    CHECK(p.txs.size() == 1 && p.txs[0].fee == 2 * est && p.txs[0].value_out == 210000 - 2 * est &&
              p.total_fee == 2 * est && p.fee_mode == FeeMode::Relay,
          "fee = rate x est signed bytes; output = inputs - fee");
    CHECK(contains(p.summary, "RELAY") && contains(p.summary, "sendrawtransaction"), "summary names the relay lane");

    FoundKey key = find_key_for_address(DUMMY_MNEMONIC, "", DUMMY_ADDR0, false, KeyScanRange{});
    std::vector<SignedTx> st = sign_sweep(p, key, true);
    CHECK(st.size() == 1 && p.txs[0].fee >= 2 * static_cast<int64_t>(st[0].size), "signed; real rate >= 2 duffs/B");
    auto outs = parse_outputs(H(st[0].hex));
    CHECK(outs.size() == 1 && outs[0].value == p.txs[0].value_out, "the signed output is the planned one");

    SweepBatchPlan unbalanced = p;
    unbalanced.txs[0].fee += 1;
    CHECK(aborts_with([&] { sign_sweep(unbalanced, key, true); }, "does not balance"), "an edited fee aborts");
    SweepBatchPlan greedy = p;
    greedy.txs[0].fee = 101 * est;
    greedy.txs[0].value_out = 210000 - 101 * est;
    CHECK(aborts_with([&] { sign_sweep(greedy, key, true); }, "above"), "a fee above 100 duffs/B aborts at sign time");
    SweepBatchPlan as_inject = p;
    as_inject.fee_mode = FeeMode::InjectOnlyZeroFee;
    CHECK(aborts_with([&] { sign_sweep(as_inject, key, true); }, "not zero-fee"), "a fee in an inject plan aborts");
    SweepBatchPlan zero = p;
    zero.txs[0].fee = 0;
    zero.txs[0].value_out = 210000;
    CHECK(aborts_with([&] { sign_sweep(zero, key, true); }, "does not balance"), "a relay plan with fee 0 aborts");

    // Money range at plan time.
    SweepRequest tiny = sweep_of(2, 300);
    tiny.fee_mode = FeeMode::Relay;
    tiny.fee_rate_per_byte = 1;
    CHECK(aborts_with([&] { plan_sweep(tiny); }, "exceed"), "a fee above what the tx moves aborts");
    SweepRequest dust_out = sweep_of(1, 500);
    CHECK(aborts_with([&] { plan_sweep(dust_out); }, "dust threshold"), "an output below 546 duffs aborts (inject too)");
    SweepRequest uneconomic = sweep_of(3, 70000);
    uneconomic.utxos.push_back(mk_utxo(txid_of_byte("ee"), 0, 100, 150, spk_hex_of(DUMMY_ADDR0)));
    uneconomic.fee_mode = FeeMode::Relay;
    uneconomic.fee_rate_per_byte = 1;
    CHECK(contains(plan_sweep(uneconomic).summary, "carry less than the fee"), "uneconomic inputs are warned about");
    CHECK(contains(plan_sweep(sweep_of(2, 70000)).summary, "pin lane EXCLUDES"), "inject NOTE names the pin-lane outcome (nit 1)");
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

    // ctest export_utxos_roundtrip hook: import a UTXO file through the model,
    // screen it at the default target and print the two public cards.
    if (argc >= 3 && std::strcmp(argv[1], "--import-file") == 0) {
        try {
            DashInjectModel m;
            m.import_utxos(read_file(argv[2]), argc >= 4 ? std::atoll(argv[3]) : 0);
            m.rescreen({});
            std::printf("%s%s", m.import_card().c_str(), m.screen_card().c_str());
            return 0;
        } catch (const std::exception& e) {
            std::printf("REFUSED: %s\n", e.what());
            return 1;
        }
    }

    // Oracle hook: the slice-2 end-to-end txs on the fixture (test key), as
    // "<label> <unsigned hex> <signed hex>" lines, so the python reference can
    // re-sign the same unsigned bytes and compare byte for byte.
    if (argc >= 2 && std::strcmp(argv[1], "--emit-s2-e2e") == 0) {
        ScreenParams sp;
        sp.dust_floor = 2;
        PlanParams relay;
        relay.fee_mode = FeeMode::Relay;
        relay.fee_rate_per_byte = 1;
        PlanParams split;
        split.max_inputs_per_tx = 85;
        const std::pair<const char*, PlanParams> runs_[] = {{"zero-fee", PlanParams{}}, {"relay-1", relay}, {"split-85", split}};
        for (const auto& [label, pp] : runs_) {
            DashInjectModel m;
            if (!drive_planned(m, fixture_for(testvec::kPyParityAddress), kFixtureTip, sp, pp) ||
                !sign_with(m, key_of(KeySource::Wif, testvec::kK7Wif)))
                return 1;
            for (size_t i = 0; i < m.signed_txs().size(); ++i)
                std::printf("%s %s %s\n", label, hexstr(m.sweep_plan()->txs[i].unsigned_tx).c_str(),
                            m.signed_txs()[i].hex.c_str());
        }
        return 0;
    }

    std::printf("=== c2wallet-qt M3-A-DASH KATs ===\n");
    test_gov_hash();
    test_address();
    test_key_scan();
    test_collateral_tx();
    test_message();

    std::printf("\n=== zero-fee inject builders ===\n");
    test_k1_onchain_collateral();
    test_k2_fee_flags();
    test_k3_sweep_all();
    test_k4_maturity();
    test_k5_batch_split();
    test_k6_sign_verify();
    test_k7_python_parity();
    test_k8_uncompressed_scan();
    test_k9_emit_format();
    test_k10_bip68();
    test_k12_refusals();
    test_k13_display_roundtrip();
    test_utxo_intake();

    std::printf("\n=== slice 2: DashInjectModel / PageDashInject ===\n");
    test_s2_k1_export_v1();
    test_s2_k2_getaddressutxos_fixture();
    test_s2_k3_rescreen();
    test_s2_k4_state_machine();
    test_s2_k5_key_paths();
    test_s2_k6_end_to_end();
    test_s2_k7_manifest();
    test_s2_k8_collateral();
    test_s2_k9_secret_hygiene();
    test_s2_k10_split();
    test_s2_k13_relay_fee_mode();
    CHECK(kDefaultMinConf == kCoinbaseMaturity + 1, "S2-K11: kDefaultMinConf == kCoinbaseMaturity + 1 (also static_assert)");

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
