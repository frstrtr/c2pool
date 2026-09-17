// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KATs for the M6 slice-2a facade (GAP-1 SignSession) + the GAP-5 Amount
// helper. Money-correctness discipline (design §5.3): every case is
// CONSTRUCTED as an UnsignedContainer, driven through the std-only facade, and
// the facade's own mandatory finalize() re-verifies each input through the
// vendored interpreter / BIP143 / BIP341 verifier before it emits — so a green
// K2 is a construct→sign→self-verify→emit round-trip, not a self-assertion.
//
//   K1  parse→serialize byte-exact + refuse malformed
//   K2  container→sign→finalize→SignedContainer round-trip per SPK type
//       (P2PKH / P2WPKH / P2SH-P2WPKH / P2SH-2of3 / P2WSH-2of3 / P2TR-keypath)
//   K3  refuse unbalanced / absurd-fee (dust is a PageBuildTx gate, not here)
//   K4  refuse-on-tamper (flip SPK → binding refuses; flip amount → BIP143
//       verify fails at the Signer layer)
//   K5  refuse-on-wrong-key
//   K6  amount-helper vectors
//   K9  unsigned↔signed confusion refuse (a signed blob has non-empty scriptSigs)
//   K11 deterministic A signatures (sign twice → identical bytes)

#include "../SignSession.hpp"
#include "../Signer.hpp"
#include "../Scripts.hpp"
#include "../Crypto.hpp"
#include "../Taproot.hpp"

// UnsignedContainer is used HEADER-ONLY here (a plain data struct); we do NOT
// call its out-of-line methods, so this test links ONLY c2wallet-signer and
// never drags the btclibs include tree into this dashscript TU (the two-lib
// separation the c2wallet-dash lane proved). SignedContainer / crossgap_txid
// are exercised by the artifact library's own test_artifact.cpp.
#include "family/bitcoin/artifact/TransferContainer.hpp"
#include "family/common/Amount.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace c2w;
namespace sgn = c2w::signer;
namespace art = c2w::artifact;
using sign::SpkType;
using sign::KeyForInput;
using sign::SignOptions;
using c2w::secure::SecureBytes;

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg)                                                                \
    do {                                                                                \
        if (cond) { ++g_pass; }                                                         \
        else { ++g_fail; std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } \
    } while (0)

using Bytes = std::vector<uint8_t>;
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static Bytes H(const std::string& s) {
    Bytes o; for (size_t i = 0; i + 1 < s.size(); i += 2) o.push_back((uint8_t)((hexval(s[i]) << 4) | hexval(s[i + 1]))); return o;
}
static Bytes SB(const CScript& s) { return Bytes(s.begin(), s.end()); }
static SecureBytes SK(const std::string& hex) { Bytes b = H(hex); return SecureBytes(b.data(), b.size()); }
static Bytes PUB(const SecureBytes& sk, bool comp) { return sgn::Secp::instance().pubkey_create(sk.data(), comp); }
static uint256 mkprev(uint8_t seed) { uint256 h; for (int i = 0; i < 32; ++i) h.begin()[i] = (uint8_t)(seed + i); return h; }

static const std::string SK_A = "0000000000000000000000000000000000000000000000000000000000000001";
static const std::string SK_B = "0000000000000000000000000000000000000000000000000000000000000002";
static const std::string SK_C = "0000000000000000000000000000000000000000000000000000000000000003";

static CScript dummy_out() { return sgn::p2pkh_from_h160(H("00112233445566778899aabbccddeeff00112233")); }

// Build a single-input, single-output UnsignedContainer spending `spk` of
// `amount`, paying `outval` to a dummy output.
static art::UnsignedContainer make_container(const CScript& spk, int64_t amount, int64_t outval) {
    uint256 prev = mkprev(0x11);
    sgn::Signer sg(2, 0);
    sg.add_input(prev, 0, amount, spk, 0xffffffffu);
    sg.add_output(outval, dummy_out());

    art::UnsignedContainer c;
    c.coin = "btc";
    c.network_version = 0;
    c.algebra = art::SighashAlgebra::Legacy;
    c.unsigned_tx = sg.serialize(false);
    art::UnsignedInput in;
    std::memcpy(in.prevout_txid.data(), prev.begin(), 32);
    in.prevout_index = 0;
    in.script_pubkey = SB(spk);
    in.amount = amount;
    c.inputs.push_back(in);
    return c;
}

// ── K2: one round-trip case per SPK type ────────────────────────────────────
static void run_case(const char* name, const CScript& spk, int64_t amount, int64_t outval,
                     std::vector<KeyForInput>&& keys, SpkType want) {
    art::UnsignedContainer c = make_container(spk, amount, outval);

    // K1 parse leg: byte-exact re-serialize + cross-check.
    sign::TxView v = sign::parse_unsigned(c);
    CHECK(v.ok, (std::string(name) + ": parse_unsigned ok").c_str());
    if (!v.ok) { std::printf("    (%s)\n", v.error.c_str()); }
    CHECK(v.ok && v.inputs.size() == 1 && v.inputs[0].type == want,
          (std::string(name) + ": SPK classified correctly").c_str());
    CHECK(v.ok && v.fee == amount - outval, (std::string(name) + ": fee = in - out").c_str());

    SignOptions opt; opt.sighash = 0x01;
    sign::SignOutcome o = sign::sign_and_verify(c, std::move(keys), opt);
    CHECK(o.ok, (std::string(name) + ": sign_and_verify finalizes+emits").c_str());
    if (!o.ok) { std::printf("    (%s)\n", o.error.c_str()); return; }

    // Signed artifact is the c2pool loader format: one raw tx hex per line.
    // (SignedContainer's own emit/parse round-trip is KAT'd in test_artifact.)
    bool valid_hex = !o.signed_tx.empty() && (o.signed_tx.size() % 2 == 0);
    for (char ch : o.signed_tx)
        if (hexval(ch) < 0) valid_hex = false;
    CHECK(valid_hex, (std::string(name) + ": signed tx is valid even-length hex").c_str());
    CHECK(o.txid_display.size() == 64 && o.wtxid_display.size() == 64,
          (std::string(name) + ": txid + wtxid displays present (32-byte)").c_str());
}

static void test_types() {
    std::printf("[K2] per-type container→sign→finalize→SignedContainer round-trip\n");
    auto ska = SK(SK_A), skb = SK(SK_B), skc = SK(SK_C);
    Bytes pka = PUB(ska, true), pkb = PUB(skb, true), pkc = PUB(skc, true);

    // P2PKH
    { std::vector<KeyForInput> ks; ks.push_back({0, ska.copy(), pka, {}});
      run_case("P2PKH", sgn::p2pkh(pka), 100000, 99000, std::move(ks), SpkType::P2PKH); }
    // P2WPKH
    { std::vector<KeyForInput> ks; ks.push_back({0, ska.copy(), pka, {}});
      run_case("P2WPKH", sgn::p2wpkh(pka), 100000, 99000, std::move(ks), SpkType::P2WPKH); }
    // P2SH-P2WPKH (redeem derived by the facade)
    { std::vector<KeyForInput> ks; ks.push_back({0, ska.copy(), pka, {}});
      run_case("P2SH-P2WPKH", sgn::p2sh(sgn::p2wpkh(pka)), 100000, 99000, std::move(ks), SpkType::P2SH); }
    // P2SH-2of3 (signers A + B)
    { CScript ms = sgn::p2ms(2, {pka, pkb, pkc}); Bytes msb = SB(ms);
      std::vector<KeyForInput> ks;
      ks.push_back({0, ska.copy(), pka, msb});
      ks.push_back({0, skb.copy(), pkb, msb});
      run_case("P2SH-2of3", sgn::p2sh(ms), 100000, 99000, std::move(ks), SpkType::P2SH); }
    // P2WSH-2of3 (signers A + C)
    { CScript ms = sgn::p2ms(2, {pka, pkb, pkc}); Bytes msb = SB(ms);
      std::vector<KeyForInput> ks;
      ks.push_back({0, ska.copy(), pka, msb});
      ks.push_back({0, skc.copy(), pkc, msb});
      run_case("P2WSH-2of3", sgn::p2wsh(ms), 100000, 99000, std::move(ks), SpkType::P2WSH); }
    // P2TR key-path
    { int par = 0; uint8_t px[32];
      bool okx = sgn::Secp::instance().xonly_pubkey(ska.data(), px, &par);
      CHECK(okx, "P2TR: x-only internal key derived");
      Bytes P(px, px + 32);
      sgn::P2TROutput tr = sgn::build_p2tr(P, /*merkle*/ nullptr, "bc");
      std::vector<KeyForInput> ks; ks.push_back({0, ska.copy(), pka, {}});
      run_case("P2TR-keypath", tr.spk, 100000, 99000, std::move(ks), SpkType::P2TR); }
}

// ── K1: refuse malformed / K9: unsigned↔signed confusion ────────────────────
static void test_parse_refusals() {
    std::printf("[K1/K9] parse refuses malformed + signed-as-unsigned\n");
    auto ska = SK(SK_A); Bytes pka = PUB(ska, true);

    // Truncated bytes.
    { art::UnsignedContainer c = make_container(sgn::p2pkh(pka), 100000, 99000);
      c.unsigned_tx.resize(c.unsigned_tx.size() - 3);
      sign::TxView v = sign::parse_unsigned(c);
      CHECK(!v.ok, "truncated unsigned tx refused"); }

    // Prevout mismatch between the tx bytes and the container metadata.
    { art::UnsignedContainer c = make_container(sgn::p2pkh(pka), 100000, 99000);
      c.inputs[0].prevout_index = 7;
      sign::TxView v = sign::parse_unsigned(c);
      CHECK(!v.ok, "prevout-index mismatch refused"); }

    // K9: a SIGNED tx (non-empty scriptSig) fed as an unsigned container.
    { std::vector<KeyForInput> ks; ks.push_back({0, ska.copy(), pka, {}});
      art::UnsignedContainer c0 = make_container(sgn::p2pkh(pka), 100000, 99000);
      SignOptions opt; auto o = sign::sign_and_verify(c0, std::move(ks), opt);
      CHECK(o.ok, "K9 setup signs");
      // Build a container whose unsigned_tx is actually the signed tx.
      art::UnsignedContainer c = c0; c.unsigned_tx = H(o.signed_tx);
      sign::TxView v = sign::parse_unsigned(c);
      CHECK(!v.ok, "K9: signed tx rejected as unsigned (non-empty scriptSig / mismatch)"); }
}

// ── K3: balance + absurd-fee gates ──────────────────────────────────────────
static void test_balance_gates() {
    std::printf("[K3] unbalanced + absurd-fee refusals\n");
    auto ska = SK(SK_A); Bytes pka = PUB(ska, true);

    // Unbalanced: output > input.
    { std::vector<KeyForInput> ks; ks.push_back({0, ska.copy(), pka, {}});
      art::UnsignedContainer c = make_container(sgn::p2pkh(pka), 100000, 200000);
      SignOptions opt; auto o = sign::sign_and_verify(c, std::move(ks), opt);
      CHECK(!o.ok, "unbalanced (out>in) refused"); }

    // Absurd fee without confirmation.
    { std::vector<KeyForInput> ks; ks.push_back({0, ska.copy(), pka, {}});
      art::UnsignedContainer c = make_container(sgn::p2pkh(pka), 100000000, 1000);
      SignOptions opt; auto o = sign::sign_and_verify(c, std::move(ks), opt);
      CHECK(!o.ok, "absurd fee refused without confirmation"); }

    // Same, WITH confirmation → allowed.
    { std::vector<KeyForInput> ks; ks.push_back({0, ska.copy(), pka, {}});
      art::UnsignedContainer c = make_container(sgn::p2pkh(pka), 100000000, 1000);
      SignOptions opt; opt.absurd_fee_confirmed = true;
      auto o = sign::sign_and_verify(c, std::move(ks), opt);
      CHECK(o.ok, "absurd fee allowed with explicit confirmation");
      if (!o.ok) std::printf("    (%s)\n", o.error.c_str()); }
}

// ── K4/K5: tamper + wrong key ───────────────────────────────────────────────
static void test_tamper_and_wrongkey() {
    std::printf("[K4/K5] binding refuse on wrong key/SPK + BIP143 amount tamper\n");
    auto ska = SK(SK_A), skb = SK(SK_B);
    Bytes pka = PUB(ska, true), pkb = PUB(skb, true);

    // K5: wrong key for a P2PKH input (pk B does not hash to pk A's SPK).
    { std::vector<KeyForInput> ks; ks.push_back({0, skb.copy(), pkb, {}});
      art::UnsignedContainer c = make_container(sgn::p2pkh(pka), 100000, 99000);
      SignOptions opt; auto o = sign::sign_and_verify(c, std::move(ks), opt);
      CHECK(!o.ok, "K5: wrong key refused before signing (binding)"); }

    // K4: BIP143 amount tamper detected by the Signer's self-verify. Sign a
    // P2WPKH input for amount X, then re-verify the same witness against amount
    // X+1 → the v0 digest changes → verify_input fails.
    {
        uint256 prev = mkprev(0x22);
        sgn::Signer sg(2, 0);
        sg.add_input(prev, 0, 100000, sgn::p2wpkh(pka), 0xffffffffu);
        sg.add_output(99000, dummy_out());
        Bytes sig = sg.make_bip143_sig(0, sgn::p2wpkh_scriptcode(pka), 100000, ska, 0x01);
        sg.set_witness(0, sgn::Witness{sig, pka});
        CHECK(sg.verify_input(0).ok, "K4: correct-amount P2WPKH verifies");

        sgn::Signer bad(2, 0);
        bad.add_input(prev, 0, 100001 /*tampered*/, sgn::p2wpkh(pka), 0xffffffffu);
        bad.add_output(99000, dummy_out());
        bad.set_witness(0, sgn::Witness{sig, pka});
        CHECK(!bad.verify_input(0).ok, "K4: tampered-amount P2WPKH FAILS BIP143 verify");
    }
}

// ── K11: deterministic signatures ───────────────────────────────────────────
static void test_determinism() {
    std::printf("[K11] deterministic A signatures (RFC6979 / BIP340)\n");
    auto ska = SK(SK_A); Bytes pka = PUB(ska, true);

    auto sign_once = [&](const CScript& spk, SpkType /*t*/) {
        std::vector<KeyForInput> ks; ks.push_back({0, ska.copy(), pka, {}});
        art::UnsignedContainer c = make_container(spk, 100000, 99000);
        SignOptions opt; return sign::sign_and_verify(c, std::move(ks), opt);
    };
    auto a1 = sign_once(sgn::p2pkh(pka), SpkType::P2PKH);
    auto a2 = sign_once(sgn::p2pkh(pka), SpkType::P2PKH);
    CHECK(a1.ok && a2.ok && a1.signed_tx == a2.signed_tx, "P2PKH sign twice → identical bytes");

    int par = 0; uint8_t px[32]; sgn::Secp::instance().xonly_pubkey(ska.data(), px, &par);
    Bytes P(px, px + 32); auto tr = sgn::build_p2tr(P, nullptr, "bc");
    auto t1 = sign_once(tr.spk, SpkType::P2TR);
    auto t2 = sign_once(tr.spk, SpkType::P2TR);
    CHECK(t1.ok && t2.ok && t1.signed_tx == t2.signed_tx, "P2TR key-path sign twice → identical bytes");
}

// ── K6: amount helper ───────────────────────────────────────────────────────
static void test_amount() {
    using namespace c2w::amount;
    std::printf("[K6] amount format/parse vectors (integer-only)\n");
    CHECK(format_amount(100000000, 8) == "1.00000000", "format 1.0");
    CHECK(format_amount(1, 8) == "0.00000001", "format 1 sat");
    CHECK(format_amount(-50000000, 8) == "-0.50000000", "format negative");
    CHECK(format_amount(2100000000000000LL, 8) == "21000000.00000000", "format 21M");
    CHECK(format_amount(1234, 0) == "1234", "format 0 decimals");

    CHECK(parse_amount("1.5", 8).ok && parse_amount("1.5", 8).sats == 150000000, "parse 1.5");
    CHECK(parse_amount("21000000", 8).ok && parse_amount("21000000", 8).sats == 2100000000000000LL, "parse 21M");
    CHECK(parse_amount("0.00000001", 8).ok && parse_amount("0.00000001", 8).sats == 1, "parse 1 sat");
    CHECK(!parse_amount("1.234567890", 8).ok, "reject >decimals fraction");
    CHECK(!parse_amount("-1", 8).ok, "reject sign");
    CHECK(!parse_amount("1e3", 8).ok, "reject exponent");
    CHECK(!parse_amount(" 1", 8).ok, "reject leading whitespace");
    CHECK(!parse_amount("1 ", 8).ok, "reject trailing whitespace");
    CHECK(!parse_amount("", 8).ok, "reject empty");
    CHECK(!parse_amount(".", 8).ok, "reject bare dot");
    CHECK(!parse_amount("1.2.3", 8).ok, "reject two dots");
    CHECK(!parse_amount("0x10", 8).ok, "reject hex");
    CHECK(!parse_amount("99999999999", 8).ok, "reject int64 overflow");
}

int main() {
    std::printf("== c2wallet-qt M6 slice-2a SignSession + Amount KATs ==\n");
    test_types();
    test_parse_refusals();
    test_balance_gates();
    test_tamper_and_wrongkey();
    test_determinism();
    test_amount();
    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
