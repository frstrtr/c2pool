// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT-gated tests for the Family-A full-file importers (design §3.1, locked
// decision 1): Electrum full-file (plaintext / pw_encoded field / BIE1 storage)
// and Bitcoin Core wallet.dat (unencrypted / encrypted BDB).
//
// Fixtures are produced by tests/gen_fixtures/gen_fixtures.cpp using libdb +
// OpenSSL + zlib (implementations independent of the parser under test). The
// expected values (fixture_expected.hpp) are the literal fixture inputs plus a
// published canonical BIP32 vector xprv — nothing is transcribed from the
// parser being validated.

#include "../Address.hpp"
#include "../Bip32.hpp"
#include "../CoinParams.hpp"
#include "../Derivation.hpp"
#include "../Electrum.hpp"
#include "../HexUtil.hpp"
#include "../WalletDat.hpp"

#include "fixtures/fixture_expected.hpp"

#include <cstdio>
#include <fstream>
#include <set>
#include <string>
#include <vector>

using namespace c2w::hdkeys;

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) \
    do { if (cond) { ++g_pass; } else { ++g_fail; std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)
#define CHECK_EQ(got, want, msg) \
    do { std::string g_ = (got), w_ = (want); \
         if (g_ == w_) { ++g_pass; } \
         else { ++g_fail; std::printf("  FAIL: %s\n    got : %s\n    want: %s\n", msg, g_.c_str(), w_.c_str()); } } while (0)

#ifndef C2W_FIXTURE_DIR
#define C2W_FIXTURE_DIR "."
#endif

static std::string read_file(const std::string& name) {
    std::ifstream f(std::string(C2W_FIXTURE_DIR) + "/" + name, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}
static std::string sbhex(const c2w::secure::SecureBytes& s) { return to_hex(s.data(), s.size()); }

// Independent sanity: an xprv parses, round-trips, and derives a usable address.
static bool xprv_derives_address(const std::string& xprv) {
    auto node = HDKey::parse(xprv);
    if (!node) return false;
    if (node->serialize() != xprv) return false;                 // round-trip
    auto child = node->derive_child(0);
    if (!child) return false;
    auto leaf = child->derive_child(0);
    if (!leaf || !leaf->has_private()) return false;
    const CoinParams* btc = coin_by_ticker("BTC");
    if (!btc) return false;
    auto cands = address_candidates_from_seckey(leaf->privkey().data(), *btc);
    for (const auto& c : cands) if (c.label == "P2WPKH" && !c.address.empty()) return true;
    return !cands.empty();
}

static void test_electrum_plaintext() {
    std::printf("[Electrum] plaintext standard bip32 wallet:\n");
    auto r = import_electrum_wallet(read_file("electrum_plain.json"), "");
    CHECK(r.ok, "plaintext wallet imports");
    CHECK(!r.was_encrypted, "not flagged storage-encrypted");
    CHECK(r.seed_version == 18, "seed_version parsed");
    CHECK_EQ(r.wallet_type, "standard", "wallet_type parsed");
    CHECK(r.items.size() == 1 && r.items[0].kind == ElectrumKeyItem::Kind::Xprv, "one xprv item");
    if (!r.items.empty()) {
        CHECK_EQ(r.items[0].text, fx::electrum_master_xprv, "recovered xprv == canonical BIP32 vector");
        CHECK(xprv_derives_address(r.items[0].text), "recovered xprv derives a valid P2WPKH address");
    }
}

static void test_electrum_field_encrypted() {
    std::printf("[Electrum] pw_encode'd xprv field (AES-256-CBC, key=SHA256d(pw)):\n");
    auto r = import_electrum_wallet(read_file("electrum_field_enc.json"), fx::password);
    CHECK(r.ok, "field-encrypted wallet imports with password");
    CHECK(r.items.size() == 1 && r.items[0].kind == ElectrumKeyItem::Kind::Xprv, "recovered one xprv");
    if (!r.items.empty()) CHECK_EQ(r.items[0].text, fx::electrum_master_xprv, "field-decrypted xprv == canonical vector");
    // Wrong password must not recover the xprv.
    auto bad = import_electrum_wallet(read_file("electrum_field_enc.json"), "wrong-pass");
    CHECK(bad.items.empty(), "wrong password recovers no xprv");
    CHECK(bad.needs_password, "wrong password flags needs_password");
}

static void test_electrum_bie1_storage() {
    std::printf("[Electrum] BIE1 storage encryption (ECIES: ECDH+SHA512+AES-128-CBC+HMAC):\n");
    std::string blob = read_file("electrum_bie1.wallet");
    auto r = import_electrum_wallet(blob, fx::password);
    CHECK(r.was_encrypted, "storage flagged encrypted");
    CHECK(r.ok, "BIE1 wallet decrypts + imports with password");
    CHECK(r.items.size() == 1 && r.items[0].kind == ElectrumKeyItem::Kind::Xprv, "recovered one xprv through both layers");
    if (!r.items.empty()) CHECK_EQ(r.items[0].text, fx::electrum_master_xprv, "storage+field decrypted xprv == canonical vector");
    // Wrong password must fail the HMAC (no decryption).
    auto bad = import_electrum_wallet(blob, "wrong-pass");
    CHECK(!bad.ok && bad.needs_password, "wrong storage password rejected via HMAC");
    // No password given => needs_password, clear error.
    auto nop = import_electrum_wallet(blob, "");
    CHECK(!nop.ok && nop.needs_password, "encrypted storage without password reports needs_password");
}

static void collect_scalars(const std::vector<WalletDatKey>& keys, std::set<std::string>& out) {
    for (const auto& k : keys) if (k.decrypted) out.insert(sbhex(k.scalar));
}

static void test_walletdat_unencrypted() {
    std::printf("[wallet.dat] unencrypted Berkeley DB (DER CPrivKey extraction):\n");
    std::string bytes = read_file("wallet_unenc.dat");
    CHECK(!bytes.empty(), "fixture wallet_unenc.dat present");
    auto r = import_wallet_dat(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size(), "");
    CHECK(r.ok, "unencrypted wallet.dat parses");
    CHECK(!r.is_encrypted, "not flagged encrypted");
    CHECK(r.key_records == 2, "two key records found");
    std::set<std::string> got; collect_scalars(r.keys, got);
    CHECK(got.count(fx::walletdat_scalar1_hex) == 1, "scalar #1 extracted from DER matches known input");
    CHECK(got.count(fx::walletdat_scalar2_hex) == 1, "scalar #2 extracted from DER matches known input");
}

static void test_walletdat_encrypted() {
    std::printf("[wallet.dat] encrypted Berkeley DB (mkey/ckey, EVP_BytesToKey-SHA512 + AES-256-CBC):\n");
    std::string bytes = read_file("wallet_enc.dat");
    CHECK(!bytes.empty(), "fixture wallet_enc.dat present");
    const uint8_t* p = reinterpret_cast<const uint8_t*>(bytes.data());
    // Correct passphrase decrypts every ckey.
    auto r = import_wallet_dat(p, bytes.size(), fx::password);
    CHECK(r.ok, "encrypted wallet.dat parses");
    CHECK(r.is_encrypted, "flagged encrypted");
    CHECK(r.master_keys == 1, "one master-key record");
    CHECK(r.key_records == 2, "two ckey records");
    std::set<std::string> got; collect_scalars(r.keys, got);
    CHECK(got.count(fx::walletdat_scalar1_hex) == 1, "ckey #1 decrypts to known scalar");
    CHECK(got.count(fx::walletdat_scalar2_hex) == 1, "ckey #2 decrypts to known scalar");
    // Wrong passphrase: parses, flags needs_password, decrypts nothing.
    auto bad = import_wallet_dat(p, bytes.size(), "wrong-pass");
    CHECK(bad.ok && bad.needs_password, "wrong passphrase flags needs_password");
    std::set<std::string> none; collect_scalars(bad.keys, none);
    CHECK(none.empty(), "wrong passphrase decrypts no scalars");
    // No passphrase: same, needs_password.
    auto nop = import_wallet_dat(p, bytes.size(), "");
    CHECK(nop.needs_password, "no passphrase flags needs_password");
}

int main() {
    std::printf("== c2wallet-qt Family-A full-file import KATs (Electrum + wallet.dat) ==\n");
    test_electrum_plaintext();
    test_electrum_field_encrypted();
    test_electrum_bie1_storage();
    test_walletdat_unencrypted();
    test_walletdat_encrypted();
    std::printf("\n== %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
