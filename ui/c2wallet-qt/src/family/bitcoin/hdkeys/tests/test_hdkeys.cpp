// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT-gated correctness tests for the Bitcoin-script hdkeys core (design §6,
// M1-A money-path gate). Published vectors only:
//   * BIP39  — Trezor python-mnemonic english vectors (entropy/mnemonic/seed/xprv)
//   * BIP32  — BIP32 spec Test Vector 1 (hardened + normal + xpub CKD)
//   * BIP44/49/84/86 — canonical address vectors for the "abandon...about" seed
//   * WIF    — a published uncompressed vector + a reused-codec round-trip
//   * GEN    — generate -> re-derive determinism round-trip
// plus a BIP39 checksum-rejection negative test.

#include "../Bip39.hpp"
#include "../Bip32.hpp"
#include "../CoinParams.hpp"
#include "../Derivation.hpp"
#include "../Address.hpp"
#include "../KeyImport.hpp"
#include "../HexUtil.hpp"
#include "../Secp.hpp"
#include "test_vectors.hpp"

#include <btclibs/base58.h>
#include <btclibs/span.h>
// SSOT cross-check: prove the CoinParams address bytes agree with the shipped
// per-coin address_encoding.hpp (design §2.4 — that header is the SSOT).
#include <impl/btc/address_encoding.hpp>

#include <cstdio>
#include <string>
#include <vector>

using namespace c2w::hdkeys;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (cond) { ++g_pass; }                                                 \
        else { ++g_fail; std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } \
    } while (0)

#define CHECK_EQ(got, want, msg)                                                \
    do {                                                                        \
        std::string g_ = (got), w_ = (want);                                    \
        if (g_ == w_) { ++g_pass; }                                             \
        else { ++g_fail; std::printf("  FAIL: %s\n    got : %s\n    want: %s\n", msg, g_.c_str(), w_.c_str()); } \
    } while (0)

static std::string seed_hex(const c2w::secure::SecureBytes& s)
{
    return to_hex(s.data(), s.size());
}

// Build a WIF from raw parts using the reused base58check codec (for round-trip).
static std::string make_wif(uint8_t version, const uint8_t sk[32], bool compressed)
{
    std::vector<unsigned char> v;
    v.push_back(version);
    v.insert(v.end(), sk, sk + 32);
    if (compressed) v.push_back(0x01);
    return EncodeBase58Check(Span<const unsigned char>(v.data(), v.size()));
}

static void test_bip39()
{
    std::printf("[BIP39] Trezor english vectors (%zu):\n", kat::bip39_english().size());
    for (const auto& v : kat::bip39_english()) {
        auto entropy = from_hex(v.entropy).value();
        Bip39Error err = Bip39Error::Ok;
        std::string m = Bip39::encode(entropy, err);
        CHECK(err == Bip39Error::Ok, "encode ok");
        CHECK_EQ(m, v.mnemonic, "entropy->mnemonic");
        CHECK(Bip39::validate(v.mnemonic) == Bip39Error::Ok, "checksum verify");
        std::vector<uint8_t> dec;
        CHECK(Bip39::decode(v.mnemonic, dec) == Bip39Error::Ok, "decode ok");
        CHECK_EQ(to_hex(dec), v.entropy, "mnemonic->entropy");
        auto seed = Bip39::to_seed(v.mnemonic, "TREZOR");
        CHECK_EQ(seed_hex(seed), v.seed, "mnemonic->seed (PBKDF2)");
        auto master = HDKey::from_seed(seed.data(), seed.size());
        CHECK(master.has_value(), "master from seed");
        if (master) CHECK_EQ(master->serialize(), v.xprv, "seed->bip32 root xprv");
    }
    // Negative: corrupt the checksum word.
    std::string bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    CHECK(Bip39::validate(bad) == Bip39Error::BadChecksum, "bad checksum rejected");
    // Negative: word count.
    CHECK(Bip39::validate("abandon abandon") == Bip39Error::BadWordCount, "bad word count rejected");
    // Negative: unknown word.
    std::string unk = "zzzz abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    CHECK(Bip39::validate(unk) == Bip39Error::UnknownWord, "unknown word rejected");
}

static void test_bip32()
{
    std::printf("[BIP32] spec Test Vector 1:\n");
    auto seed = from_hex(kat::bip32_tv1_seed_hex).value();
    auto master = HDKey::from_seed(seed.data(), seed.size());
    CHECK(master.has_value(), "master");
    if (!master) return;

    for (const auto& v : kat::bip32_tv1()) {
        auto path = parse_path(v.path);
        CHECK(path.has_value(), "path parse");
        auto node = master->derive_path(*path);
        CHECK(node.has_value(), "derive path");
        if (!node) continue;
        CHECK_EQ(node->serialize(), v.xprv, (std::string("xprv ") + v.path).c_str());
        CHECK_EQ(node->neuter().serialize(), v.xpub, (std::string("xpub ") + v.path).c_str());
        // Round-trip parse of the xpub reproduces the same string.
        auto parsed = HDKey::parse(v.xpub);
        CHECK(parsed.has_value(), "xpub parse");
        if (parsed) CHECK_EQ(parsed->serialize(), v.xpub, "xpub reparse");
    }

    // Public CKD: derive m/0H/1 as a NORMAL child from the m/0H xpub, matching
    // the private-derived xpub. (m/0H is hardened; /1 is normal.)
    auto n0h = master->derive_child(0 | kHardened);
    CHECK(n0h.has_value(), "m/0H");
    if (n0h) {
        auto xpub0h = HDKey::parse(n0h->neuter().serialize());
        CHECK(xpub0h.has_value(), "reparse m/0H xpub");
        if (xpub0h) {
            auto pub_child = xpub0h->derive_child(1);   // public-only normal CKD
            auto prv_child = n0h->derive_child(1);
            CHECK(pub_child.has_value() && prv_child.has_value(), "CKD pub+prv");
            if (pub_child && prv_child)
                CHECK_EQ(pub_child->serialize(), prv_child->neuter().serialize(), "public CKD == private CKD xpub");
        }
    }
}

static void test_addresses()
{
    std::printf("[ADDR] BIP44/49/84/86 canonical addresses:\n");
    auto seed = Bip39::to_seed(kat::addr_kat_mnemonic, "");
    auto master = HDKey::from_seed(seed.data(), seed.size());
    CHECK(master.has_value(), "master");
    if (!master) return;
    const CoinParams* btc = coin_by_ticker("BTC");
    CHECK(btc != nullptr, "BTC params");

    for (const auto& v : kat::btc_address_kats()) {
        auto path = parse_path(v.path);
        auto node = master->derive_path(path.value());
        CHECK(node.has_value() && node->has_private(), "derive priv node");
        if (!node) continue;
        auto cands = address_candidates_from_seckey(node->privkey().data(), *btc);
        // Pick the candidate matching the purpose's script type.
        ScriptHint want = ScriptHint::Unknown;
        std::string p = v.purpose;
        if (p == "BIP44") want = ScriptHint::P2PKH;
        else if (p == "BIP49") want = ScriptHint::P2SH_P2WPKH;
        else if (p == "BIP84") want = ScriptHint::P2WPKH;
        else if (p == "BIP86") want = ScriptHint::P2TR;
        std::string got;
        for (const auto& c : cands)
            if (c.type == want && (want != ScriptHint::P2PKH || c.encoding == "compressed")) { got = c.address; break; }
        CHECK_EQ(got, v.address, (std::string(v.purpose) + " " + v.path).c_str());
    }
}

static void test_wif_and_rawhex()
{
    std::printf("[WIF/RAW] decode + round-trip:\n");
    // Published uncompressed WIF (Bitcoin wiki test vector).
    const char* wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    const char* expect_hex = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
    auto d = decode_wif(wif);
    CHECK(d.ok, "wif decode ok");
    CHECK(!d.compressed, "wif uncompressed");
    CHECK_EQ(to_hex(d.scalar.data(), d.scalar.size()), expect_hex, "wif scalar");
    CHECK(d.version == 0x80, "wif version 0x80");

    // Reused-codec round-trip (compressed): scalar -> WIF -> decode -> scalar.
    auto sk = from_hex("f8a1cd2b5e6b8f0e1122334455667788990011223344556677889900aabbccdd").value();
    CHECK(Secp::instance().seckey_verify(sk.data()), "test scalar valid");
    std::string w2 = make_wif(0x80, sk.data(), /*compressed=*/true);
    auto d2 = decode_wif(w2);
    CHECK(d2.ok && d2.compressed, "wif roundtrip decode");
    CHECK_EQ(to_hex(d2.scalar.data(), d2.scalar.size()), to_hex(sk), "wif roundtrip scalar");

    // raw hex range-check: 0 and N are rejected; a valid scalar accepted.
    CHECK(!decode_raw_hex(std::string(64, '0')).ok, "raw zero rejected");
    // N (curve order) must be rejected.
    CHECK(!decode_raw_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").ok, "raw N rejected");
    CHECK(decode_raw_hex(expect_hex).ok, "raw valid accepted");
}

static void test_generation_roundtrip()
{
    std::printf("[GEN] vetted-CSPRNG generate -> re-derive:\n");
    for (int bits : {128, 256}) {
        std::string m = Bip39::generate(bits);
        CHECK(Bip39::validate(m) == Bip39Error::Ok, "generated mnemonic checksum ok");
        size_t words = 1; for (char c : m) if (c == ' ') ++words;
        CHECK((bits == 128 && words == 12) || (bits == 256 && words == 24), "generated word count");
        // Re-derive from the SAME mnemonic string twice => identical key/address.
        auto s1 = Bip39::to_seed(m, "");
        auto s2 = Bip39::to_seed(m, "");
        CHECK_EQ(seed_hex(s1), seed_hex(s2), "seed deterministic");
        auto master = HDKey::from_seed(s1.data(), s1.size());
        auto path = build_bip_path(Purpose::BIP84, 0, 0, 0, 0);
        auto n1 = master->derive_path(path);
        auto master2 = HDKey::from_seed(s2.data(), s2.size());
        auto n2 = master2->derive_path(path);
        CHECK(n1 && n2, "re-derive");
        const CoinParams* btc = coin_by_ticker("BTC");
        auto a1 = address_candidates_from_seckey(n1->privkey().data(), *btc);
        auto a2 = address_candidates_from_seckey(n2->privkey().data(), *btc);
        CHECK(a1.size() == a2.size() && !a1.empty(), "candidate sets");
        CHECK_EQ(a1.front().script_hex, a2.front().script_hex, "re-derive same address");
    }
    // Two fresh generations must differ (entropy is live).
    CHECK(Bip39::generate(256) != Bip39::generate(256), "distinct generations");
}

static void test_ssot_crosscheck()
{
    std::printf("[SSOT] CoinParams vs address_encoding.hpp:\n");
    const CoinParams* btc = coin_by_ticker("BTC");
    auto acc = btc::address_acceptance(/*testnet=*/false, /*regtest=*/false);
    CHECK(!acc.p2pkh_versions.empty() && acc.p2pkh_versions[0] == btc->p2pkh_version, "btc p2pkh matches SSOT");
    CHECK(!acc.p2sh_versions.empty() && acc.p2sh_versions[0] == btc->p2sh_version, "btc p2sh matches SSOT");
    CHECK(!acc.bech32_hrps.empty() && acc.bech32_hrps[0] == std::string(btc->bech32_hrp), "btc hrp matches SSOT");
}

int main()
{
    std::printf("== c2wallet-qt hdkeys KATs ==\n");
    test_bip39();
    test_bip32();
    test_addresses();
    test_wif_and_rawhex();
    test_generation_roundtrip();
    test_ssot_crosscheck();
    std::printf("\n== %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
