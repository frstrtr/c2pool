// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT-gated correctness tests for the M3-A Family-A signing core (design §4.1
// spend matrix + "Wrapped & nested scripts"; §5.3 self-verify-before-emit).
//
// Money-correctness discipline: every spend is CONSTRUCTED and then VERIFIED by
// the vendored in-tree interpreter — a wrong sighash fails verify. Legacy
// inputs run the full VerifyScript (which independently re-derives the legacy
// sighash via the vendored SignatureHash — an implementation the signer did
// NOT write), so a legacy construct→verify is a strong cross-check. Segwit v0
// is anchored to a PUBLISHED vector:
//
//   * BIP143 native-P2WPKH example (BIP143 "Native P2WPKH" section): the full
//     2-input tx is reconstructed and (a) its input-1 v0 sighash is asserted
//     byte-exact against the published 0xc37af311… digest, and (b) the fully
//     signed transaction is asserted byte-exact against BIP143's published
//     signed hex — proving legacy sighash + BIP143 sighash + RFC6979/low-S/DER
//     + witness serialization all at once.
//
// Parity precedents (design §1): the DASH block-2518186 P2PKH spend and the
// LTC+DOGE bare-P2MS-in-P2SH donation spend are reproduced as construct→verify
// (exact prior tx bytes are not reconstructable, so — per the brief — we assert
// the signed input PASSES the in-tree VerifyScript; the P2WPKH published vector
// carries the byte-exact leg).

#include "../Signer.hpp"
#include "../Scripts.hpp"
#include "../Bip143.hpp"
#include "../Crypto.hpp"

#include <script/interpreter.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace c2w::signer;
using c2w::secure::SecureBytes;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                                                \
    do {                                                                                \
        if (cond) { ++g_pass; }                                                         \
        else { ++g_fail; std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } \
    } while (0)

// ── local hex helpers (kept independent of the hdkeys/btclibs closure) ──────
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static Bytes H(const std::string& s) {
    Bytes out;
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back((uint8_t)((hexval(s[i]) << 4) | hexval(s[i + 1])));
    return out;
}
static std::string HEX(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 0xf]; }
    return s;
}
static std::string HEX(const Bytes& b) { return HEX(b.data(), b.size()); }
static std::string HEX(const CScript& s) { return HEX(Bytes(s.begin(), s.end())); }
static std::string HEX(const uint256& h) { return HEX(h.begin(), 32); }

static SecureBytes SK(const std::string& hex) { Bytes b = H(hex); return SecureBytes(b.data(), b.size()); }
static Bytes PUB(const SecureBytes& sk, bool comp) { return Secp::instance().pubkey_create(sk.data(), comp); }
static uint256 le_hash(const std::string& hex) {
    uint256 h; Bytes b = H(hex); std::memcpy(h.begin(), b.data(), 32); return h;
}

// ════════════════════════════════════════════════════════════════════════════
// 1. BIP143 NATIVE P2WPKH — published vector, byte-exact.
// ════════════════════════════════════════════════════════════════════════════
static void test_bip143_p2wpkh_published()
{
    std::printf("[bip143] native P2WPKH published vector\n");

    const auto pub0 = H("03c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432");
    const auto sk0  = SK("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
    const auto pub1 = H("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357");
    const auto sk1  = SK("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");

    Signer s(/*version*/1, /*locktime*/17);
    s.add_input(le_hash("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"),
                0, 625000000, p2pk(pub0), 0xffffffeeu);          // input0: P2PK
    s.add_input(le_hash("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"),
                1, 600000000, p2wpkh(pub1), 0xffffffffu);        // input1: P2WPKH
    s.add_output(112340000, p2pkh_from_h160(H("8280b37df378db99f66f85c95a783a76ac7a6d59")));
    s.add_output(223450000, p2pkh_from_h160(H("3bde42dbee7e4dbe6a21b2d50ce2f0167faa8159")));

    // (a) input-1 v0 sighash == published 0xc37af311… digest.
    uint256 sh = s.bip143_sighash_for(1, p2wpkh_scriptcode(pub1), 600000000, SIGHASH_ALL);
    CHECK(HEX(sh) == "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670",
          "BIP143 P2WPKH input-1 sighash matches published vector");

    // Sign both inputs.
    Bytes sig0 = s.make_legacy_sig(0, p2pk(pub0), sk0, SIGHASH_ALL);   // legacy P2PK
    s.set_scriptsig(0, push_data(sig0));
    Bytes sig1 = s.make_bip143_sig(1, p2wpkh_scriptcode(pub1), 600000000, sk1, SIGHASH_ALL);
    s.set_witness(1, Witness{sig1, pub1});

    // (b) full signed tx == BIP143 published signed hex (byte-exact).
    Bytes signed_tx; std::string err;
    CHECK(s.finalize(signed_tx, err), "finalize self-verifies + emits");
    if (!err.empty()) std::printf("    (%s)\n", err.c_str());
    const std::string expected =
        "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4"
        "e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3beb"
        "f337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede9"
        "44ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b"
        "309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a914"
        "8280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143b"
        "de42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7"
        "d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c45183315"
        "61406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368d"
        "a1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";
    CHECK(HEX(signed_tx) == expected, "BIP143 P2WPKH full signed tx is byte-exact");
}

// ════════════════════════════════════════════════════════════════════════════
// helpers for construct→verify KATs (own keys; the interpreter is the harness).
// ════════════════════════════════════════════════════════════════════════════
static const std::string SK_A = "0000000000000000000000000000000000000000000000000000000000000001";
static const std::string SK_B = "0000000000000000000000000000000000000000000000000000000000000002";
static const std::string SK_C = "0000000000000000000000000000000000000000000000000000000000000003";

// A generic 1-input, 1-output spend scaffold spending `spk` of `amount`.
static Signer scaffold(const CScript& spk, int64_t amount, const CScript& out_spk)
{
    Signer s(2, 0);
    s.add_input(le_hash("1111111111111111111111111111111111111111111111111111111111111111"),
                0, amount, spk, 0xffffffffu);
    s.add_output(amount - 1000, out_spk);
    return s;
}

static CScript dummy_out() { return p2pkh_from_h160(H("00112233445566778899aabbccddeeff00112233")); }

// ── legacy singles ──────────────────────────────────────────────────────────
static void test_legacy_singles()
{
    std::printf("[legacy] P2PK (both encodings), P2PKH (DASH-2518186 parity), P2SH\n");
    auto ska = SK(SK_A);

    for (bool comp : {true, false}) {
        Bytes pk = PUB(ska, comp);
        Signer s = scaffold(p2pk(pk), 100000, dummy_out());
        Bytes sig = s.make_legacy_sig(0, p2pk(pk), ska, SIGHASH_ALL);
        s.set_scriptsig(0, push_data(sig));
        CHECK(s.verify_input(0).ok, comp ? "P2PK compressed verifies" : "P2PK uncompressed verifies");
    }

    // P2PKH — the DASH block-2518186 parity path.
    {
        Bytes pk = PUB(ska, true);
        Signer s = scaffold(p2pkh(pk), 100000, dummy_out());
        Bytes sig = s.make_legacy_sig(0, p2pkh(pk), ska, SIGHASH_ALL);
        CScript ss; ss << sig << pk;
        s.set_scriptsig(0, ss);
        auto r = s.verify_input(0);
        CHECK(r.ok, "P2PKH (DASH-2518186 parity) verifies");
        if (!r.ok) std::printf("    (%s)\n", r.error.c_str());
    }

    // P2SH wrapping a P2PK redeemScript (single-party).
    {
        Bytes pk = PUB(ska, true);
        CScript redeem = p2pk(pk);
        Signer s = scaffold(p2sh(redeem), 100000, dummy_out());
        Bytes sig = s.make_legacy_sig(0, redeem, ska, SIGHASH_ALL); // scriptCode = redeemScript
        CScript ss; ss << sig << Bytes(redeem.begin(), redeem.end()); // redeemScript LAST
        s.set_scriptsig(0, ss);
        auto r = s.verify_input(0);
        CHECK(r.ok, "P2SH(P2PK) wrapped spend verifies");
        if (!r.ok) std::printf("    (%s)\n", r.error.c_str());
    }
}

// ── bare P2MS + P2SH-multisig (CHECKMULTISIG dummy + NULLDUMMY + ordering) ────
static void test_multisig_legacy()
{
    std::printf("[legacy] bare-P2MS + P2SH-multisig (NULLDUMMY, ordering, combine)\n");
    auto ska = SK(SK_A), skb = SK(SK_B), skc = SK(SK_C);
    std::vector<Bytes> pks = {PUB(ska, true), PUB(skb, true), PUB(skc, true)};
    CScript ms = p2ms(2, pks); // 2-of-3

    // bare P2MS 2-of-3, signers A and C (positions 0 and 2).
    {
        Signer s = scaffold(ms, 100000, dummy_out());
        Bytes sa = s.make_legacy_sig(0, ms, ska, SIGHASH_ALL);
        Bytes sc = s.make_legacy_sig(0, ms, skc, SIGHASH_ALL);
        auto ordered = Signer::order_multisig_sigs(pks, {{pks[2], sc}, {pks[0], sa}}); // deliberately mis-fed
        CHECK(ordered.size() == 2 && ordered[0] == sa && ordered[1] == sc,
              "combine orders sigs by pubkey position (A before C)");
        CScript ss = Signer::multisig_scriptsig(ordered, nullptr);
        CHECK(ss.size() >= 1 && ss[0] == 0x00, "bare-P2MS scriptSig leads with NULLDUMMY empty push (0x00, not OP_1)");
        s.set_scriptsig(0, ss);
        CHECK(s.verify_input(0).ok, "bare-P2MS 2-of-3 verifies");

        // Wrong sig order (C before A) must FAIL verify (CHECKMULTISIG no backtrack).
        Signer s2 = scaffold(ms, 100000, dummy_out());
        Bytes sa2 = s2.make_legacy_sig(0, ms, ska, SIGHASH_ALL);
        Bytes sc2 = s2.make_legacy_sig(0, ms, skc, SIGHASH_ALL);
        CScript bad = Signer::multisig_scriptsig({sc2, sa2}, nullptr); // reversed
        s2.set_scriptsig(0, bad);
        CHECK(!s2.verify_input(0).ok, "bare-P2MS wrong sig order is REJECTED");
    }

    // P2SH-multisig (the LTC+DOGE donation pattern) — combine A+B.
    {
        Signer s = scaffold(p2sh(ms), 100000, dummy_out());
        Bytes sa = s.make_legacy_sig(0, ms, ska, SIGHASH_ALL); // scriptCode = redeemScript
        Bytes sb = s.make_legacy_sig(0, ms, skb, SIGHASH_ALL);
        auto ordered = Signer::order_multisig_sigs(pks, {{pks[1], sb}, {pks[0], sa}});
        CScript ss = Signer::multisig_scriptsig(ordered, &ms);
        s.set_scriptsig(0, ss);
        auto r = s.verify_input(0);
        CHECK(r.ok, "P2SH-multisig (LTC+DOGE donation pattern) combine verifies");
        if (!r.ok) std::printf("    (%s)\n", r.error.c_str());
    }
}

// ── BIP143 segwit v0: P2WSH, P2SH-P2WPKH, P2SH-P2WSH + wrapped/combine ────────
static void test_segwit_v0()
{
    std::printf("[bip143] P2WSH / P2SH-P2WPKH / P2SH-P2WSH + wrapped multisig combine\n");
    auto ska = SK(SK_A), skb = SK(SK_B), skc = SK(SK_C);
    Bytes pka = PUB(ska, true), pkb = PUB(skb, true), pkc = PUB(skc, true);

    // P2WSH wrapping a P2PK.
    {
        CScript ws = p2pk(pka);
        Signer s = scaffold(p2wsh(ws), 100000, dummy_out());
        Bytes sig = s.make_bip143_sig(0, ws, 100000, ska, SIGHASH_ALL);
        s.set_witness(0, Witness{sig, Bytes(ws.begin(), ws.end())});
        auto r = s.verify_input(0);
        CHECK(r.ok, "P2WSH(P2PK) verifies");
        if (!r.ok) std::printf("    (%s)\n", r.error.c_str());
    }

    // P2SH-P2WPKH.
    {
        CScript prog = p2wpkh(pka);              // OP_0 <h160(pubkey)>
        Signer s = scaffold(p2sh(prog), 100000, dummy_out());
        Bytes sig = s.make_bip143_sig(0, p2wpkh_scriptcode(pka), 100000, ska, SIGHASH_ALL);
        s.set_scriptsig(0, push_data(Bytes(prog.begin(), prog.end()))); // scriptSig pushes the program
        s.set_witness(0, Witness{sig, pka});
        auto r = s.verify_input(0);
        CHECK(r.ok, "P2SH-P2WPKH verifies");
        if (!r.ok) std::printf("    (%s)\n", r.error.c_str());
    }

    // P2SH-P2WSH wrapping a 2-of-3 multisig — multi-party combine (B+C).
    {
        std::vector<Bytes> pks = {pka, pkb, pkc};
        CScript ws = p2ms(2, pks);
        CScript prog = p2wsh(ws);                 // OP_0 <sha256(witnessScript)>
        Signer s = scaffold(p2sh(prog), 100000, dummy_out());
        Bytes sb = s.make_bip143_sig(0, ws, 100000, skb, SIGHASH_ALL);
        Bytes sc = s.make_bip143_sig(0, ws, 100000, skc, SIGHASH_ALL);
        auto ordered = Signer::order_multisig_sigs(pks, {{pks[2], sc}, {pks[1], sb}});
        s.set_scriptsig(0, push_data(Bytes(prog.begin(), prog.end())));
        s.set_witness(0, Signer::multisig_witness(ordered, ws));
        auto r = s.verify_input(0);
        CHECK(r.ok, "P2SH-P2WSH 2-of-3 multisig combine verifies");
        if (!r.ok) std::printf("    (%s)\n", r.error.c_str());
    }

    // P2WSH wrapping a 2-of-2 multisig — NULLDUMMY leading empty element.
    {
        auto skd = SK(SK_A), ske = SK(SK_B);
        std::vector<Bytes> pks = {PUB(skd, true), PUB(ske, true)};
        CScript ws = p2ms(2, pks);
        Signer s = scaffold(p2wsh(ws), 100000, dummy_out());
        Bytes s0 = s.make_bip143_sig(0, ws, 100000, skd, SIGHASH_ALL);
        Bytes s1 = s.make_bip143_sig(0, ws, 100000, ske, SIGHASH_ALL);
        Witness w = Signer::multisig_witness({s0, s1}, ws);
        CHECK(w.front().empty(), "P2WSH-multisig witness leads with the NULLDUMMY empty element");
        s.set_witness(0, w);
        CHECK(s.verify_input(0).ok, "P2WSH 2-of-2 multisig verifies");
    }
}

// ── sighash flags: NONE / SINGLE / ANYONECANPAY + the SIGHASH_SINGLE bug ──────
static void test_sighash_flags()
{
    std::printf("[sighash] NONE / SINGLE / ANYONECANPAY + SIGHASH_SINGLE bug\n");
    auto ska = SK(SK_A);
    Bytes pk = PUB(ska, true);

    for (int base : {SIGHASH_NONE, SIGHASH_SINGLE}) {
        for (int aco : {0, (int)SIGHASH_ANYONECANPAY}) {
            int ht = base | aco;
            Signer s = scaffold(p2pkh(pk), 100000, dummy_out()); // 1-in 1-out: SINGLE valid at idx 0
            Bytes sig = s.make_legacy_sig(0, p2pkh(pk), ska, ht);
            CScript ss; ss << sig << pk;
            s.set_scriptsig(0, ss);
            char buf[64]; std::snprintf(buf, sizeof buf, "P2PKH verifies with hashtype 0x%02x", ht);
            CHECK(s.verify_input(0).ok, buf);
        }
    }

    // SIGHASH_SINGLE bug: input index >= number of outputs → warning + 0x01 digest.
    {
        Signer s(2, 0);
        s.add_input(le_hash("2222222222222222222222222222222222222222222222222222222222222222"),
                    0, 100000, p2pkh(pk), 0xffffffffu);
        s.add_input(le_hash("3333333333333333333333333333333333333333333333333333333333333333"),
                    1, 100000, p2pkh(pk), 0xffffffffu);
        s.add_output(150000, dummy_out()); // only ONE output; input index 1 >= 1
        uint256 d = s.legacy_sighash(1, p2pkh(pk), SIGHASH_SINGLE);
        CHECK(HEX(d) == "0100000000000000000000000000000000000000000000000000000000000000",
              "SIGHASH_SINGLE bug: digest is the constant uint256::ONE");
        bool warned = false;
        for (auto& w : s.warnings()) if (w.find("SIGHASH_SINGLE bug") != std::string::npos) warned = true;
        CHECK(warned, "SIGHASH_SINGLE bug raises a warning");
    }
}

// ── self-verify-before-emit refuses a bad sig; 100 kB oversize refusal ────────
static void test_refusals()
{
    std::printf("[refuse] mis-signed input rejected; 100 kB oversize rejected\n");
    auto ska = SK(SK_A), skb = SK(SK_B);
    Bytes pk = PUB(ska, true);

    // Deliberately mis-signed: sign with the WRONG key (B) for a P2PKH locked to A.
    {
        Signer s = scaffold(p2pkh(pk), 100000, dummy_out());
        Bytes badsig = s.make_legacy_sig(0, p2pkh(pk), skb, SIGHASH_ALL); // wrong key
        CScript ss; ss << badsig << pk;
        s.set_scriptsig(0, ss);
        CHECK(!s.verify_input(0).ok, "mis-signed input fails self-verify");
        Bytes out; std::string err;
        CHECK(!s.finalize(out, err) && out.empty(), "finalize REFUSES to emit a mis-signed tx");
        CHECK(err.find("REFUSED") != std::string::npos, "refusal names self-verify-before-emit");
    }

    // Oversize: pad with outputs until serialized size exceeds 100 kB.
    {
        Signer s = scaffold(p2pkh(pk), 100000000, dummy_out());
        CScript big; big << OP_RETURN;
        { Bytes pad(3000, 0x00); big.insert(big.end(), pad.begin(), pad.end()); } // ~3 kB per output
        for (int i = 0; i < 40; ++i) s.add_output(1, big); // ~120 kB — add BEFORE signing
        Bytes sig = s.make_legacy_sig(0, p2pkh(pk), ska, SIGHASH_ALL);
        CScript ss; ss << sig << pk;
        s.set_scriptsig(0, ss);
        Bytes out; std::string err;
        CHECK(!s.finalize(out, err) && err.find("oversize") != std::string::npos,
              "finalize REFUSES an oversize (>100 kB) tx");
    }
}

int main()
{
    std::printf("== c2wallet-qt M3-A signer KATs ==\n");
    test_bip143_p2wpkh_published();
    test_legacy_singles();
    test_multisig_legacy();
    test_segwit_v0();
    test_sighash_flags();
    test_refusals();
    std::printf("\n== %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
