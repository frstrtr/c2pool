// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT-gated tests for the M1-A import formats (design §3.1 / §3.4 money-path
// gate): BIP38, Core descriptors, generic JSON keystore, and the experimental
// split/shuffle seed backup. Published/derived vectors only (import_vectors.hpp
// + the BIP39/BIP44/49/84/86 vectors in test_vectors.hpp).

#include "../Aes256.hpp"
#include "../Address.hpp"
#include "../Bip32.hpp"
#include "../Bip38.hpp"
#include "../Bip39.hpp"
#include "../CoinParams.hpp"
#include "../Derivation.hpp"
#include "../Descriptor.hpp"
#include "../HexUtil.hpp"
#include "../KeyImport.hpp"
#include "../Keystore.hpp"
#include "../Scrypt.hpp"
#include "../SeedBackup.hpp"
#include "../wordlists.hpp"

#include "test_vectors.hpp"
#include "import_vectors.hpp"

#include <btclibs/crypto/sha256.h>

#include <cstdio>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace c2w::hdkeys;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg) \
    do { if (cond) { ++g_pass; } else { ++g_fail; std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)
#define CHECK_EQ(got, want, msg) \
    do { std::string g_ = (got), w_ = (want); \
         if (g_ == w_) { ++g_pass; } \
         else { ++g_fail; std::printf("  FAIL: %s\n    got : %s\n    want: %s\n", msg, g_.c_str(), w_.c_str()); } } while (0)

static std::string sbhex(const c2w::secure::SecureBytes& s) { return to_hex(s.data(), s.size()); }

// ── AES-256 (FIPS-197) ──────────────────────────────────────────────────────
static void test_aes256()
{
    std::printf("[AES-256] FIPS-197 C.3:\n");
    auto key = *from_hex(kat::aes256_key_hex);
    auto pt = *from_hex(kat::aes256_pt_hex);
    auto ct = *from_hex(kat::aes256_ct_hex);
    Aes256 aes(key.data());
    uint8_t out[16];
    aes.encrypt_block(pt.data(), out);
    CHECK_EQ(to_hex(out, 16), kat::aes256_ct_hex, "AES-256 encrypt");
    aes.decrypt_block(ct.data(), out);
    CHECK_EQ(to_hex(out, 16), kat::aes256_pt_hex, "AES-256 decrypt");
}

// ── scrypt (RFC 7914) ────────────────────────────────────────────────────────
static void test_scrypt()
{
    std::printf("[scrypt] RFC 7914 vectors:\n");
    for (const auto& v : kat::scrypt_vectors()) {
        auto out = scrypt_general(reinterpret_cast<const uint8_t*>(v.pass), std::string(v.pass).size(),
                                  reinterpret_cast<const uint8_t*>(v.salt), std::string(v.salt).size(),
                                  v.N, v.r, v.p, v.dk);
        CHECK_EQ(to_hex(out), v.out, "scrypt vector");
    }
}

// ── BIP38 ────────────────────────────────────────────────────────────────────
static void test_bip38()
{
    std::printf("[BIP38] spec test vectors:\n");
    for (const auto& v : kat::bip38_vectors()) {
        auto want = decode_wif(v.wif);
        CHECK(want.ok, "expected WIF decodes");
        auto got = decode_bip38(v.encrypted, v.passphrase);
        if (!got.ok) { ++g_fail; std::printf("  FAIL: BIP38 decrypt failed: %s (%s)\n", v.encrypted, got.error.c_str()); continue; }
        CHECK_EQ(sbhex(got.scalar), sbhex(want.scalar), "BIP38 -> scalar matches spec WIF");
        CHECK(got.compressed == want.compressed, "BIP38 compressed flag matches WIF");
        CHECK(got.ec_multiply == v.ec_multiply, "BIP38 mode (EC-multiply) matches vector");
    }
    // Reject: wrong passphrase must fail the address-hash checksum.
    auto bad = decode_bip38(kat::bip38_vectors()[0].encrypted, "wrong passphrase");
    CHECK(!bad.ok, "BIP38 wrong passphrase rejected");
    // Reject: malformed base58.
    auto bad2 = decode_bip38("6Pnotarealbip38key", "x");
    CHECK(!bad2.ok, "BIP38 malformed key rejected");
}

// ── descriptors ──────────────────────────────────────────────────────────────
static HDKey account_xpub_node(Purpose p)
{
    auto seed = Bip39::to_seed(kat::addr_kat_mnemonic, "");
    auto master = HDKey::from_seed(seed.data(), seed.size());
    std::vector<uint32_t> acct = {static_cast<uint32_t>(p) | kHardened, 0u | kHardened, 0u | kHardened};
    auto node = master->derive_path(acct);
    return node->neuter();
}

static std::string master_fp_hex()
{
    auto seed = Bip39::to_seed(kat::addr_kat_mnemonic, "");
    auto master = HDKey::from_seed(seed.data(), seed.size());
    auto fp = master->fingerprint();
    return to_hex(fp.data(), 4);
}

static std::string kat_addr(const char* purpose, const char* path)
{
    for (const auto& a : kat::btc_address_kats())
        if (std::string(a.purpose) == purpose && std::string(a.path) == path) return a.address;
    return "<missing>";
}

static void test_descriptors()
{
    std::printf("[Descriptor] published BIP44/49/84/86 addresses via descriptor path:\n");
    const CoinParams* btc = coin_by_ticker("BTC");
    std::string fp = master_fp_hex();

    struct Case { Purpose p; const char* fn_open; const char* fn_close; const char* purpose_s; };
    std::vector<Case> cases = {
        {Purpose::BIP44, "pkh(", ")", "BIP44"},
        {Purpose::BIP49, "sh(wpkh(", "))", "BIP49"},
        {Purpose::BIP84, "wpkh(", ")", "BIP84"},
        {Purpose::BIP86, "tr(", ")", "BIP86"},
    };
    for (auto& c : cases) {
        std::string xpub = account_xpub_node(c.p).serialize();
        int prm = static_cast<int>(c.p);
        std::string origin = "[" + fp + "/" + std::to_string(prm) + "'/0'/0']";
        // external chain /0/*
        std::string desc = std::string(c.fn_open) + origin + xpub + "/0/*" + c.fn_close;
        auto pr = parse_descriptor(desc);
        if (!pr.ok) { ++g_fail; std::printf("  FAIL: parse %s: %s\n", c.purpose_s, pr.error.c_str()); continue; }
        std::string err;
        auto addrs = derive_descriptor(pr.desc, *btc, 0, 1, err);
        if (addrs.size() < 2) { ++g_fail; std::printf("  FAIL: derive %s: %s\n", c.purpose_s, err.c_str()); continue; }
        std::string want0 = kat_addr(c.purpose_s, (std::string("m/") + std::to_string(prm) + "'/0'/0'/0/0").c_str());
        CHECK_EQ(addrs[0].address, want0, "descriptor external index 0");
        // BIP84/86 have index 1 published too
        if (c.p == Purpose::BIP84 || c.p == Purpose::BIP86) {
            std::string want1 = kat_addr(c.purpose_s, (std::string("m/") + std::to_string(prm) + "'/0'/0'/0/1").c_str());
            CHECK_EQ(addrs[1].address, want1, "descriptor external index 1");
        }
    }

    // Change chain /1/* against the published BIP84 change address.
    {
        std::string xpub = account_xpub_node(Purpose::BIP84).serialize();
        std::string desc = "wpkh([" + fp + "/84'/0'/0']" + xpub + "/1/*)";
        auto pr = parse_descriptor(desc);
        std::string err;
        auto addrs = derive_descriptor(pr.desc, *coin_by_ticker("BTC"), 0, 0, err);
        CHECK(pr.ok && !addrs.empty(), "change descriptor parses/derives");
        if (!addrs.empty()) CHECK_EQ(addrs[0].address, kat_addr("BIP84", "m/84'/0'/0'/1/0"), "descriptor change index 0");
    }

    // Checksum: compute, append, verify accepted; then corrupt -> rejected.
    {
        std::string xpub = account_xpub_node(Purpose::BIP84).serialize();
        std::string payload = "wpkh([" + fp + "/84'/0'/0']" + xpub + "/0/*)";
        std::string cs = descriptor_checksum(payload);
        CHECK(cs.size() == 8, "checksum computed");
        auto good = parse_descriptor(payload + "#" + cs);
        CHECK(good.ok && good.desc.checksum_valid, "valid checksum accepted");
        std::string bad_cs = cs; bad_cs[0] = (bad_cs[0] == 'q' ? 'p' : 'q');
        auto bad = parse_descriptor(payload + "#" + bad_cs);
        CHECK(!bad.ok, "bad checksum rejected");
    }

    // Reject: malformed (unbalanced) + unsupported function.
    CHECK(!parse_descriptor("wpkh([" + fp + "/84'/0'/0']xpub/0/*").ok, "unbalanced descriptor rejected");
    CHECK(!parse_descriptor("frobnicate(deadbeef)").ok, "unsupported function rejected");

    // Multisig: parse wsh(sortedmulti(2, k1, k2)) and cross-check the derived
    // P2WSH address against a direct construction from the same two xpubs.
    {
        std::string x1 = account_xpub_node(Purpose::BIP84).serialize();     // m/84'/0'/0'
        std::string x2 = account_xpub_node(Purpose::BIP49).serialize();     // m/49'/0'/0' (distinct key)
        std::string desc = "wsh(sortedmulti(2," + x1 + "/0/*," + x2 + "/0/*))";
        auto pr = parse_descriptor(desc);
        CHECK(pr.ok && pr.desc.type == DescType::WSH_MULTI && pr.desc.threshold == 2 &&
              pr.desc.sorted && pr.desc.keys.size() == 2, "wsh(sortedmulti) parsed");
        std::string err;
        auto addrs = derive_descriptor(pr.desc, *coin_by_ticker("BTC"), 0, 0, err);
        CHECK(!addrs.empty() && addrs[0].address.rfind("bc1q", 0) == 0, "wsh multisig -> bech32 v0 address");

        // Independent construction: derive both pubkeys at /0/0 directly.
        auto n1 = HDKey::parse(x1)->derive_child(0)->derive_child(0);
        auto n2 = HDKey::parse(x2)->derive_child(0)->derive_child(0);
        std::vector<std::vector<uint8_t>> pubs = {n1->pubkey(), n2->pubkey()};
        if (pubs[1] < pubs[0]) std::swap(pubs[0], pubs[1]);   // sortedmulti order
        std::vector<uint8_t> script;
        script.push_back(0x52);  // OP_2
        for (auto& p : pubs) { script.push_back(0x21); script.insert(script.end(), p.begin(), p.end()); }
        script.push_back(0x52);  // OP_2 (n)
        script.push_back(0xae);  // OP_CHECKMULTISIG
        uint8_t wp[32]; CSHA256().Write(script.data(), script.size()).Finalize(wp);
        std::string want = encode_segwit_v("bc", 0, std::vector<uint8_t>(wp, wp + 32), false);
        if (!addrs.empty()) CHECK_EQ(addrs[0].address, want, "wsh multisig address == independent construction");
    }
}

// ── JSON keystore ────────────────────────────────────────────────────────────
static void test_keystore()
{
    std::printf("[Keystore] generic JSON import:\n");
    // Reuse a published WIF (BIP38 vector's expected key) as the embedded secret.
    const char* wif = kat::bip38_vectors()[0].wif;   // 5KN7... uncompressed
    auto expect = decode_wif(wif);

    std::string j1 = std::string("{\"version\":1,\"wif\":\"") + wif + "\"}";
    auto k1 = import_json_keystore(j1);
    CHECK(k1.ok && k1.items.size() == 1 && k1.items[0].kind == KeystoreItem::Kind::Wif, "single wif field");
    if (!k1.items.empty()) CHECK_EQ(sbhex(k1.items[0].scalar), sbhex(expect.scalar), "keystore wif scalar matches");

    std::string j2 = std::string("{\"keys\":[\"") + wif + "\",\"" +
        "0000000000000000000000000000000000000000000000000000000000000001" + "\"]}";
    auto k2 = import_json_keystore(j2);
    CHECK(k2.ok && k2.items.size() == 2, "key array harvested (wif + raw hex)");

    std::string j3 = std::string("{\"mnemonic\":\"") + kat::addr_kat_mnemonic + "\",\"passphrase\":\"abc\"}";
    auto k3 = import_json_keystore(j3);
    CHECK(k3.ok && k3.items.size() == 1 && k3.items[0].kind == KeystoreItem::Kind::Mnemonic, "mnemonic field");
    if (!k3.items.empty()) { CHECK_EQ(k3.items[0].text, kat::addr_kat_mnemonic, "mnemonic text"); CHECK_EQ(k3.items[0].passphrase, "abc", "sibling passphrase"); }

    // Reject: malformed JSON.
    CHECK(!import_json_keystore("{ this is not json").ok, "malformed JSON rejected");
}

// ── split/shuffle seed backup (EXPERIMENTAL custom crypto) ───────────────────
static const std::unordered_map<std::string,int>& eidx_for_test()
{
    static const std::unordered_map<std::string,int> m = [] {
        std::unordered_map<std::string,int> mm; const auto& wl = wordlist_english();
        for (int i = 0; i < 2048; ++i) mm[wl[i]] = i; return mm;
    }();
    return m;
}

static void test_seed_backup()
{
    std::printf("[SeedBackup] split/shuffle gen<->ungen round-trip (EXPERIMENTAL/custom):\n");

    // KAT A — property test over several seeds (reduced iterations for speed;
    // round-trip fidelity is independent of the iteration count since gen and
    // ungen use the same value).
    SeedShuffleParams fast; fast.pbkdf2_iterations = 2048;
    const std::string pw = "correct horse battery staple";
    int roundtrips = 0;
    for (int s = 0; s < 3; ++s) {
        auto g = generate_split_backup(pw, fast, /*max_probe_iters=*/2000000);
        if (!g.ok) { ++g_fail; std::printf("  FAIL: generate_split_backup: %s\n", g.error.c_str()); continue; }
        CHECK(Bip39::validate(g.master_mnemonic) == Bip39Error::Ok, "master is valid BIP39");
        CHECK(Bip39::validate(g.share_even) == Bip39Error::Ok, "even share is valid BIP39");
        CHECK(Bip39::validate(g.share_odd) == Bip39Error::Ok, "odd share is valid BIP39");
        auto r = recover_split_backup(g.share_even, g.share_odd, g.salt_mnemonic, pw, fast);
        CHECK(r.ok, "recover ok");
        CHECK_EQ(r.master_mnemonic, g.master_mnemonic, "gen -> ungen recovers exact master");
        // Wrong password must NOT recover the same master.
        auto rw = recover_split_backup(g.share_even, g.share_odd, g.salt_mnemonic, "WRONG", fast);
        CHECK(!(rw.ok && rw.master_mnemonic == g.master_mnemonic), "wrong password does not recover master");
        if (r.ok && r.master_mnemonic == g.master_mnemonic) ++roundtrips;
    }
    CHECK(roundtrips >= 3, "all property-test seeds round-tripped");

    // KAT B — invertibility at the PRODUCTION iteration count (100000), proving
    // the real default path, using the published 24-word BIP39 vectors as the
    // master and salt (no probe needed: this checks the shuffle bijection only).
    {
        const auto& V = kat::bip39_english();
        std::string master24, salt24;
        for (const auto& v : V) { size_t w = 1; for (const char* p = v.mnemonic; *p; ++p) if (*p == ' ') ++w;
            if (w == 24 && master24.empty()) master24 = v.mnemonic;
            else if (w == 24 && salt24.empty() && v.mnemonic != master24) salt24 = v.mnemonic; }
        CHECK(!master24.empty() && !salt24.empty(), "found two 24-word vectors");
        SeedShuffleParams prod; // default 100000 iterations
        auto S = deterministic_shuffle(pw, salt24, prod);
        std::vector<int> Sinv(2048); for (int p = 0; p < 2048; ++p) Sinv[S[p]] = p;
        const auto& wl = wordlist_english(); const auto& ei = eidx_for_test();
        bool all_ok = true;
        std::istringstream is(master24); std::string word;
        while (is >> word) {
            int i = ei.at(word);
            std::string mapped = wl[S[i]];
            std::string back = wl[Sinv[ei.at(mapped)]];
            if (back != word) { all_ok = false; break; }
        }
        CHECK(all_ok, "shuffle is a bijection at 100000 iterations (map->unmap identity)");
    }
}

int main()
{
    std::printf("== c2wallet-qt import KATs (BIP38 / descriptors / keystore / split-shuffle) ==\n");
    test_aes256();
    test_scrypt();
    test_bip38();
    test_descriptors();
    test_keystore();
    test_seed_backup();
    std::printf("\n== %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
