// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT-gated correctness tests for the M4-A taproot signing core (design §4.1
// P2TR key-path + script-path rows; "Wrapped & nested scripts" multi-leaf tap
// trees + OP_CHECKSIGADD; §5.3 self-verify-before-emit).
//
// Money-correctness discipline (construct → verify):
//   * PUBLISHED BIP341 wallet test vectors (bitcoin/bips bip-0341
//     wallet-test-vectors.json, version 1). scriptPubKey vectors anchor the
//     address/tap-tree algebra (tapleaf hash, TapBranch fold, taptweak, output
//     key Q, scriptPubKey, bech32m address, control block) byte-exact.
//     keyPathSpending vectors anchor the BIP341 sighash byte-exact (committing
//     to ALL spent amounts + scriptPubKeys) and the tweaked-key math; the
//     produced key-path signature is verified under the tweaked output key Q.
//   * script-path + OP_CHECKSIGADD are exercised construct→verify against the
//     in-module BIP341/342 verifier + libsecp256k1 Schnorr verify: a k-of-n
//     CHECKSIGADD leaf verifies, a k-1 set fails, and a wrong control-block
//     parity fails. Self-verify-before-emit refuses a corrupted taproot sig.

#include "../Signer.hpp"
#include "../Scripts.hpp"
#include "../Taproot.hpp"
#include "../Crypto.hpp"

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
static uint256 U256(const std::string& hex) { uint256 h; Bytes b = H(hex); std::memcpy(h.begin(), b.data(), 32); return h; }
static CScript SCR(const std::string& hex) { Bytes b = H(hex); return CScript(b.begin(), b.end()); }
static SecureBytes SK(const std::string& hex) { Bytes b = H(hex); return SecureBytes(b.data(), b.size()); }

// ════════════════════════════════════════════════════════════════════════════
//  A tiny non-witness tx cursor to rebuild the BIP341 vector's unsigned tx.
// ════════════════════════════════════════════════════════════════════════════
struct Cursor {
    const Bytes& b; size_t i = 0;
    explicit Cursor(const Bytes& v) : b(v) {}
    uint8_t u8() { return b[i++]; }
    uint32_t u32() { uint32_t x = 0; for (int k = 0; k < 4; ++k) x |= (uint32_t)b[i++] << (8*k); return x; }
    int64_t i64() { uint64_t x = 0; for (int k = 0; k < 8; ++k) x |= (uint64_t)b[i++] << (8*k); return (int64_t)x; }
    uint64_t cs() { uint8_t t = u8(); if (t < 253) return t; if (t == 253) { uint16_t x = b[i] | (b[i+1]<<8); i+=2; return x; } if (t == 254) return u32(); return (uint64_t)i64(); }
    Bytes take(size_t n) { Bytes r(b.begin()+i, b.begin()+i+n); i += n; return r; }
};

// ════════════════════════════════════════════════════════════════════════════
//  1. scriptPubKey vectors — address / tap-tree algebra, byte-exact.
// ════════════════════════════════════════════════════════════════════════════
static void test_scriptpubkey_vectors() {
    std::printf("[1] BIP341 scriptPubKey vectors (taptweak / Q / SPK / bech32m)\n");
    struct V { const char* P; const char* mroot; const char* tweak; const char* Q; const char* spk; const char* addr; };
    // internalPubkey, merkleRoot("" = none), tweak, tweakedPubkey, scriptPubKey, bip350Address
    const V vs[] = {
      {"d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d","","b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70","53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343","512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343","bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5"},
      {"187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27","5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21","cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001","147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3","5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3","bc1pz37fc4cn9ah8anwm4xqqhvxygjf9rjf2resrw8h8w4tmvcs0863sa2e586"},
      {"93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820","c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b","6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30","e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e","5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e","bc1punvppl2stp38f7kwv2u2spltjuvuaayuqsthe34hd2dyy5w4g58qqfuag5"},
    };
    for (const auto& v : vs) {
        Bytes P = H(v.P);
        uint256 mr; bool has_mr = std::string(v.mroot).size() == 64;
        if (has_mr) mr = U256(v.mroot);
        uint256 tw = taptweak(P, has_mr ? &mr : nullptr);
        CHECK(HEX(tw) == v.tweak, "taptweak matches vector");
        P2TROutput o = build_p2tr(P, has_mr ? &mr : nullptr, "bc");
        CHECK(HEX(o.q_xonly) == v.Q, "tweaked output key Q matches vector");
        CHECK(HEX(o.spk) == v.spk, "P2TR scriptPubKey matches vector");
        CHECK(o.address == v.addr, "bech32m address matches vector");
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  2. tap-tree leaf hashes, merkle roots, and control blocks — byte-exact.
// ════════════════════════════════════════════════════════════════════════════
static void test_taptree_vectors() {
    std::printf("[2] BIP341 tap-tree leaf/branch/control-block vectors\n");

    // scriptPubKey[1]: single leaf, leafVersion 0xc0.
    {
        CScript leaf = SCR("20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac");
        uint256 lh = tapleaf_hash(0xc0, leaf);
        CHECK(HEX(lh) == "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21", "single-leaf tapleaf hash");
        TapTree t = TapTree::Leaf(leaf, 0xc0);
        CHECK(HEX(t.merkle_root()) == "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21", "single-leaf merkle root");
        Bytes P = H("187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27");
        uint256 mr = t.merkle_root(); Bytes Q; int par;
        tweak_output_key(P, &mr, Q, par);
        std::vector<uint256> path; t.merkle_path(lh, path);
        Bytes cb = control_block(P, par, 0xc0, path);
        CHECK(HEX(cb) == "c1187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27", "single-leaf control block");
    }

    // scriptPubKey[3]: two leaves, leaf0 ver 0xc0, leaf1 ver 0xfa (0xfa|parity in cb).
    {
        CScript s0 = SCR("20387671353e273264c495656e27e39ba899ea8fee3bb69fb2a680e22093447d48ac");
        CScript s1 = SCR("06424950333431");
        uint256 lh0 = tapleaf_hash(0xc0, s0), lh1 = tapleaf_hash(0xfa, s1);
        CHECK(HEX(lh0) == "8ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7", "vec3 leaf0 hash");
        CHECK(HEX(lh1) == "f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a", "vec3 leaf1 hash");
        TapTree t = TapTree::Branch(TapTree::Leaf(s0, 0xc0), TapTree::Leaf(s1, 0xfa));
        CHECK(HEX(t.merkle_root()) == "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef", "vec3 merkle root (TapBranch fold)");
        Bytes P = H("ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592");
        uint256 mr = t.merkle_root(); Bytes Q; int par; tweak_output_key(P, &mr, Q, par);
        CHECK(HEX(Q) == "712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5", "vec3 output key Q");
        std::vector<uint256> p0, p1; t.merkle_path(lh0, p0); t.merkle_path(lh1, p1);
        CHECK(HEX(control_block(P, par, 0xc0, p0)) == "c0ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a", "vec3 leaf0 control block");
        CHECK(HEX(control_block(P, par, 0xfa, p1)) == "faee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf37865928ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7", "vec3 leaf1 control block");
    }

    // scriptPubKey[5]: nested tree [leaf0, [leaf1, leaf2]].
    {
        CScript s0 = SCR("2072ea6adcf1d371dea8fba1035a09f3d24ed5a059799bae114084130ee5898e69ac");
        CScript s1 = SCR("202352d137f2f3ab38d1eaa976758873377fa5ebb817372c71e2c542313d4abda8ac");
        CScript s2 = SCR("207337c0dd4253cb86f2c43a2351aadd82cccb12a172cd120452b9bb8324f2186aac");
        TapTree t = TapTree::Branch(TapTree::Leaf(s0), TapTree::Branch(TapTree::Leaf(s1), TapTree::Leaf(s2)));
        CHECK(HEX(t.merkle_root()) == "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2", "vec5 nested merkle root");
        Bytes P = H("e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f");
        uint256 mr = t.merkle_root(); Bytes Q; int par; tweak_output_key(P, &mr, Q, par);
        CHECK(HEX(Q) == "91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605", "vec5 output key Q");
        std::vector<uint256> p0, p1, p2;
        t.merkle_path(tapleaf_hash(0xc0, s0), p0);
        t.merkle_path(tapleaf_hash(0xc0, s1), p1);
        t.merkle_path(tapleaf_hash(0xc0, s2), p2);
        CHECK(HEX(control_block(P, par, 0xc0, p0)) == "c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6fffe578e9ea769027e4f5a3de40732f75a88a6353a09d767ddeb66accef85e553", "vec5 leaf0 control block");
        CHECK(HEX(control_block(P, par, 0xc0, p1)) == "c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f9e31407bffa15fefbf5090b149d53959ecdf3f62b1246780238c24501d5ceaf62645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817", "vec5 leaf1 control block");
        CHECK(HEX(control_block(P, par, 0xc0, p2)) == "c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6fba982a91d4fc552163cb1c0da03676102d5b7a014304c01f0c77b2b8e888de1c2645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817", "vec5 leaf2 control block");
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  3. keyPathSpending vectors — BIP341 sighash byte-exact + sig verifies under Q.
// ════════════════════════════════════════════════════════════════════════════
struct KP { int idx; int ht; const char* mroot; const char* d; const char* sighash; const char* witness; };

static void test_keypath_vectors() {
    std::printf("[3] BIP341 keyPathSpending vectors (sighash byte-exact + tweaked-key sig)\n");

    const std::string rawtx =
      "02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d";

    struct UT { const char* spk; int64_t amt; };
    const UT utxos[9] = {
      {"512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343", 420000000},
      {"5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3", 462000000},
      {"76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", 294000000},
      {"5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e", 504000000},
      {"512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605", 630000000},
      {"00147dd65592d0ab2fe0d0257d571abf032cd9db93dc", 378000000},
      {"512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831", 672000000},
      {"5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5", 546000000},
      {"512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220", 588000000},
    };

    // Rebuild the exact unsigned tx into a Signer (inputs + outputs), attaching
    // all 9 spent scriptPubKeys+amounts (the BIP341 sighash commits to them).
    Bytes tb = H(rawtx);
    Cursor c(tb);
    uint32_t ver = c.u32();
    Signer s((int32_t)ver, 0);
    uint64_t nin = c.cs();
    struct In { Bytes h; uint32_t n; uint32_t seq; };
    std::vector<In> ins;
    for (uint64_t k = 0; k < nin; ++k) {
        Bytes h = c.take(32); uint32_t n = c.u32();
        uint64_t sl = c.cs(); c.take(sl); uint32_t seq = c.u32();
        ins.push_back({h, n, seq});
    }
    uint64_t nout = c.cs();
    struct Out { int64_t v; Bytes spk; };
    std::vector<Out> outs;
    for (uint64_t k = 0; k < nout; ++k) {
        int64_t v = c.i64(); uint64_t sl = c.cs(); Bytes spk = c.take(sl);
        outs.push_back({v, spk});
    }
    uint32_t locktime = c.u32();
    s.tx().nLockTime = locktime;

    for (uint64_t k = 0; k < nin; ++k) {
        uint256 ph; std::memcpy(ph.begin(), ins[k].h.data(), 32);
        s.add_input(ph, ins[k].n, utxos[k].amt, SCR(utxos[k].spk), ins[k].seq);
    }
    for (const auto& o : outs) s.add_output(o.v, CScript(o.spk.begin(), o.spk.end()));

    const KP kps[] = {
      {0,3,"","6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa","2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555","ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff14d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c03"},
      {1,131,"5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21","1e4da49f6aaf4e5cd175fe08a32bb5cb4863d963921255f33d3bc31e1343907f","325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d","052aedffc554b41f52b521071793a6b88d6dbca9dba94cf34c83696de0c1ec35ca9c5ed4ab28059bd606a4f3a657eec0bb96661d42921b5f50a95ad33675b54f83"},
      {3,1,"c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b","d3c7af07da2d54f7a7735d3d0fc4f0a73164db638b2f2f7c43f711f6d4aa7e64","bf013ea93474aa67815b1b6cc441d23b64fa310911d991e713cd34c7f5d46669","ff45f742a876139946a149ab4d9185574b98dc919d2eb6754f8abaa59d18b025637a3aa043b91817739554f4ed2026cf8022dbd83e351ce1fabc272841d2510a01"},
      {4,0,"ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2","f36bb07a11e469ce941d16b63b11b9b9120a84d9d87cff2c84a8d4affb438f4e","4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef","b4010dd48a617db09926f729e79c33ae0b4e94b79f04a1ae93ede6315eb3669de185a17d2b0ac9ee09fd4c64b678a0b61a0a86fa888a273c8511be83bfd6810f"},
      {6,2,"2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def","415cfe9c15d9cea27d8104d5517c06e9de48e2f986b695e4f5ffebf230e725d8","15f25c298eb5cdc7eb1d638dd2d45c97c4c59dcaec6679cfc16ad84f30876b85","a3785919a2ce3c4ce26f298c3d51619bc474ae24014bcdd31328cd8cfbab2eff3395fa0a16fe5f486d12f22a9cedded5ae74feb4bbe5351346508c5405bcfee002"},
      {7,130,"6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef","c7b0e81f0a9a0b0499e112279d718cca98e79a12e2f137c72ae5b213aad0d103","cd292de50313804dabe4685e83f923d2969577191a3e1d2882220dca88cbeb10","ea0c6ba90763c2d3a296ad82ba45881abb4f426b3f87af162dd24d5109edc1cdd11915095ba47c3a9963dc1e6c432939872bc49212fe34c632cd3ab9fed429c482"},
      {8,129,"ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc","77863416be0d0665e517e1c375fd6f75839544eca553675ef7fdf4949518ebaa","cccb739eca6c13a8a89e6e5cd317ffe55669bbda23f2fd37b0f18755e008edd2","bbc9584a11074e83bc8c6759ec55401f0ae7b03ef290c3139814f545b58a9f8127258000874f44bc46db7646322107d4d86aec8e73b8719a61fff761d75b5dd981"},
    };

    for (const auto& kp : kps) {
        uint256 sh = s.taproot_sighash_keypath(kp.idx, kp.ht);
        CHECK(HEX(sh) == kp.sighash, "key-path BIP341 sighash byte-exact");

        bool has_mr = std::string(kp.mroot).size() == 64;
        uint256 mr; if (has_mr) mr = U256(kp.mroot);
        SecureBytes d = SK(kp.d);
        Bytes sig = s.make_taproot_keypath_sig(kp.idx, d, has_mr ? &mr : nullptr, kp.ht);

        // Signature verifies under the tweaked output key Q (from the utxo SPK).
        Bytes uspk = H(utxos[kp.idx].spk);
        Bytes Q(uspk.begin() + 2, uspk.end());
        Bytes sig64(sig.begin(), sig.begin() + 64);
        CHECK(Secp::instance().schnorr_verify(Q.data(), sh.begin(), sig64), "key-path sig verifies under tweaked Q");

        // Byte-exact witness (BIP340 nonce with all-zero aux, as the vectors use).
        CHECK(HEX(sig) == kp.witness, "key-path witness signature byte-exact");
    }

    // Tweaked private key matches the vector's tweakedPrivkey (tweak math, input 0).
    {
        SecureBytes d = SK("6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa");
        uint8_t p_xonly[32]; int par;
        Secp::instance().xonly_pubkey(d.data(), p_xonly, &par);
        Bytes p(p_xonly, p_xonly + 32);
        uint256 tw = taptweak(p, nullptr);
        CHECK(HEX(tw) == "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70", "input0 tweak matches vector");
        uint256 msg = U256("2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555");
        const uint8_t aux[32] = {0};
        uint8_t tsk[32];
        Secp::instance().schnorr_sign_tweaked(d.data(), tw.begin(), msg.begin(), aux, tsk);
        CHECK(HEX(tsk, 32) == "2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9", "input0 tweaked privkey matches vector");
    }

    // Full self-verify of a complete key-path spend built from scratch (input 4,
    // SIGHASH_DEFAULT) through the Signer's verify_input path.
    {
        Signer s2 = Signer((int32_t)ver, locktime);
        for (uint64_t k = 0; k < nin; ++k) {
            uint256 ph; std::memcpy(ph.begin(), ins[k].h.data(), 32);
            s2.add_input(ph, ins[k].n, utxos[k].amt, SCR(utxos[k].spk), ins[k].seq);
        }
        for (const auto& o : outs) s2.add_output(o.v, CScript(o.spk.begin(), o.spk.end()));
        uint256 mr = U256("ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2");
        Bytes sig = s2.make_taproot_keypath_sig(4, SK("f36bb07a11e469ce941d16b63b11b9b9120a84d9d87cff2c84a8d4affb438f4e"), &mr, 0);
        s2.set_witness(4, Witness{sig});
        CHECK(s2.verify_input(4).ok, "self-verify accepts a valid key-path spend");

        // Corrupt the sig — self-verify must REFUSE (no bad taproot sig emitted).
        Bytes bad = sig; bad[10] ^= 0xff;
        s2.set_witness(4, Witness{bad});
        CHECK(!s2.verify_input(4).ok, "self-verify REFUSES a corrupted key-path sig");
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  4. script-path single-leaf + CHECKSIGADD multisig — construct→verify.
// ════════════════════════════════════════════════════════════════════════════
static Bytes xonly_of(const SecureBytes& d) {
    uint8_t x[32]; int par; Secp::instance().xonly_pubkey(d.data(), x, &par); return Bytes(x, x + 32);
}

static void test_scriptpath_and_checksigadd() {
    std::printf("[4] script-path + OP_CHECKSIGADD multisig (construct -> verify)\n");

    SecureBytes d_int = SK("0101010101010101010101010101010101010101010101010101010101010101");
    Bytes P = xonly_of(d_int);

    // ── 4a. single-leaf <pk> OP_CHECKSIG script path ────────────────────────
    {
        SecureBytes d_leaf = SK("0202020202020202020202020202020202020202020202020202020202020202");
        Bytes pk = xonly_of(d_leaf);
        CScript leaf; leaf << pk << OP_CHECKSIG;
        TapTree t = TapTree::Leaf(leaf);
        uint256 mr = t.merkle_root();
        P2TROutput o = build_p2tr(P, &mr);

        Signer s(2, 0);
        s.add_input(U256("00000000000000000000000000000000000000000000000000000000000000ab"), 0, 100000, o.spk);
        s.add_output(99000, p2pkh_from_h160(H("06afd46bcdfd22ef94ac122aa11f241244a37ecc")));

        Bytes sig = s.make_taproot_scriptpath_sig(0, leaf, 0xc0, d_leaf, 0);
        std::vector<uint256> path; t.merkle_path(tapleaf_hash(0xc0, leaf), path);
        Bytes cb = control_block(P, o.q_parity, 0xc0, path);
        s.set_witness(0, Witness{ sig, Bytes(leaf.begin(), leaf.end()), cb });
        CHECK(s.verify_input(0).ok, "single-leaf script-path spend self-verifies");

        // wrong control-block parity must fail.
        Bytes cb_bad = cb; cb_bad[0] ^= 0x01;
        s.set_witness(0, Witness{ sig, Bytes(leaf.begin(), leaf.end()), cb_bad });
        CHECK(!s.verify_input(0).ok, "script-path fails on wrong control-block parity");

        // wrong merkle path (corrupt internal key) must fail.
        Bytes cb_badP = cb; cb_badP[5] ^= 0xff;
        s.set_witness(0, Witness{ sig, Bytes(leaf.begin(), leaf.end()), cb_badP });
        CHECK(!s.verify_input(0).ok, "script-path fails on corrupted control block");
    }

    // ── 4b. 2-of-3 OP_CHECKSIGADD tapscript multisig ────────────────────────
    {
        SecureBytes d1 = SK("1111111111111111111111111111111111111111111111111111111111111111");
        SecureBytes d2 = SK("2222222222222222222222222222222222222222222222222222222222222222");
        SecureBytes d3 = SK("3333333333333333333333333333333333333333333333333333333333333333");
        Bytes pk1 = xonly_of(d1), pk2 = xonly_of(d2), pk3 = xonly_of(d3);
        CScript leaf = checksigadd_multisig(2, {pk1, pk2, pk3});
        TapTree t = TapTree::Leaf(leaf);
        uint256 mr = t.merkle_root();
        P2TROutput o = build_p2tr(P, &mr);
        std::vector<uint256> path; t.merkle_path(tapleaf_hash(0xc0, leaf), path);
        Bytes cb = control_block(P, o.q_parity, 0xc0, path);

        auto build = [&](const std::vector<std::pair<Bytes,Bytes>>& partials) {
            Signer s(2, 0);
            s.add_input(U256("00000000000000000000000000000000000000000000000000000000000000cd"), 0, 200000, o.spk);
            s.add_output(199000, p2pkh_from_h160(H("06afd46bcdfd22ef94ac122aa11f241244a37ecc")));
            // Each cosigner partial-signs independently over the shared leaf.
            std::vector<Bytes> slots = combine_checksigadd({pk1, pk2, pk3}, partials);
            s.set_witness(0, checksigadd_witness(slots, leaf, cb));
            return s;
        };

        // 2 of 3 (signers 1 and 2) — verifies.
        {
            Signer stmp(2,0);
            stmp.add_input(U256("00000000000000000000000000000000000000000000000000000000000000cd"), 0, 200000, o.spk);
            stmp.add_output(199000, p2pkh_from_h160(H("06afd46bcdfd22ef94ac122aa11f241244a37ecc")));
            Bytes s1sig = stmp.make_taproot_scriptpath_sig(0, leaf, 0xc0, d1, 0);
            Bytes s2sig = stmp.make_taproot_scriptpath_sig(0, leaf, 0xc0, d2, 0);
            Bytes s3sig = stmp.make_taproot_scriptpath_sig(0, leaf, 0xc0, d3, 0);

            Signer ok = build({{pk1, s1sig}, {pk2, s2sig}});
            CHECK(ok.verify_input(0).ok, "2-of-3 CHECKSIGADD self-verifies");

            // signers 2 and 3 (a different valid pair) — also verifies.
            Signer ok23 = build({{pk2, s2sig}, {pk3, s3sig}});
            CHECK(ok23.verify_input(0).ok, "2-of-3 CHECKSIGADD verifies for a different signer pair");

            // k-1 = only 1 signer — must fail (NUMEQUAL 1 != 2).
            Signer bad = build({{pk1, s1sig}});
            CHECK(!bad.verify_input(0).ok, "1-of-3 (k-1) CHECKSIGADD FAILS");

            // wrong control-block parity — must fail.
            Bytes cb_bad = cb; cb_bad[0] ^= 0x01;
            Signer wp(2,0);
            wp.add_input(U256("00000000000000000000000000000000000000000000000000000000000000cd"), 0, 200000, o.spk);
            wp.add_output(199000, p2pkh_from_h160(H("06afd46bcdfd22ef94ac122aa11f241244a37ecc")));
            wp.set_witness(0, checksigadd_witness(combine_checksigadd({pk1,pk2,pk3},{{pk1,s1sig},{pk2,s2sig}}), leaf, cb_bad));
            CHECK(!wp.verify_input(0).ok, "CHECKSIGADD fails on wrong control-block parity");

            // full finalize() emits (self-verify passes, under oversize).
            Bytes outbytes; std::string err;
            CHECK(ok.finalize(outbytes, err), "finalize emits a valid 2-of-3 taproot spend");
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  5. oversize refusal for a taproot spend.
// ════════════════════════════════════════════════════════════════════════════
static void test_oversize() {
    std::printf("[5] oversize refusal (taproot)\n");
    SecureBytes d_int = SK("0101010101010101010101010101010101010101010101010101010101010101");
    Bytes P = xonly_of(d_int);
    P2TROutput o = build_p2tr(P, nullptr);
    Signer s(2, 0);
    s.add_input(U256("00000000000000000000000000000000000000000000000000000000000000ab"), 0, 100000, o.spk);
    // A single huge OP_RETURN output pushes the tx past the 100 kB ceiling.
    CScript big; big << OP_RETURN << Bytes(110000, 0x00);
    s.add_output(0, big);
    Bytes sig = s.make_taproot_keypath_sig(0, d_int, nullptr, 0);
    s.set_witness(0, Witness{sig});
    Bytes out; std::string err;
    CHECK(!s.finalize(out, err), "finalize REFUSES an oversize taproot tx");
}

int main() {
    std::printf("== c2wallet-qt M4-A taproot KATs ==\n");
    test_scriptpubkey_vectors();
    test_taptree_vectors();
    test_keypath_vectors();
    test_scriptpath_and_checksigadd();
    test_oversize();
    std::printf("\n== %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
