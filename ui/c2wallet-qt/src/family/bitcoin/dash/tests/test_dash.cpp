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
#include "../InjectCaps.hpp"
#include "../KeyScan.hpp"
#include "../SweepTx.hpp"
#include "../UtxoIntake.hpp"

// std-only M5-A artifact headers: the loader-file format the inject KATs check
// the emitted file against.
#include "../../artifact/TransferContainer.hpp"
#include "../../artifact/TxIntrospect.hpp"

#include "gov_vectors.hpp"
#include "inject_vectors.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
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
    // Legacy sighash commits no input amounts, so the chain does not record how
    // the 101627675 duffs split across the eight inputs; only the sum is pinned
    // (out0 + out1, fee 0). The split below is illustrative: four prior-change
    // outputs and four coinbase donation slices.
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
    std::printf("[K1 on-chain collateral 3d8fd96e: inject-only, direct hash, byte-exact]\n");
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
    CHECK(plan.total_in == testvec::kOnchainTotalIn, "total in = 101627675");
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
    CHECK(confirmations_needed(unk, 50) == 50 && confirmations_needed(nc, 101) == 1, "unknown: min_conf; non-coinbase: 1");

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

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
