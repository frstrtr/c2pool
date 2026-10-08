// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// Known-answer tests for the Family B (Monero) seed/key/address core.
//
// Every vector is a PUBLISHED, independently-sourced value, so the tests pin our
// arithmetic to the same answers as widely-used external Monero libraries:
//
//   * VK / VM  -- monero-ecosystem/monero-python  tests/test_seed.py
//                 (mnemonic <-> spend key, view = H_s(spend), primary address).
//   * VA       -- monero-ecosystem/monero-python  tests/test_address.py
//                 (standard / integrated / subaddress base58 + keccak checksum;
//                  integrated payment id "JohnGalt").
//   * VS       -- monero-rs/monero-rs  src/cryptonote/subaddress.rs
//                 (subaddress derivation from a view pair at index major=2,minor=18).
//
// The generation and import round-trips prove the write path is the exact
// inverse of the read path.
// ---------------------------------------------------------------------------
#include <cstdio>
#include <string>
#include <vector>

#include "family/monero/MoneroCrypto.hpp"
#include "family/monero/MoneroKey.hpp"
#include "family/monero/addr/MoneroAddress.hpp"
#include "family/monero/addr/MoneroBase58.hpp"
#include "family/monero/seed/MoneroMnemonic.hpp"

using namespace c2wallet::monero;

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool cond, const std::string& what)
{
    ++g_checks;
    if (cond) {
        std::printf("  ok   : %s\n", what.c_str());
    } else {
        std::printf("  FAIL : %s\n", what.c_str());
        ++g_failures;
    }
}

void eq_str(const std::string& got, const std::string& want, const std::string& what)
{
    bool ok = (got == want);
    ++g_checks;
    if (ok) {
        std::printf("  ok   : %s\n", what.c_str());
    } else {
        std::printf("  FAIL : %s\n         got : %s\n         want: %s\n",
                    what.c_str(), got.c_str(), want.c_str());
        ++g_failures;
    }
}

// ---- published vectors ----------------------------------------------------

// VK: monero-python test_seed.py::test_keys
const char* VK_MNEMONIC =
    "adjust mugged vaults atlas nasty mews damp toenail suddenly toxic possible "
    "framed succeed fuzzy return demonstrate nucleus album noises peculiar virtual "
    "rowboat inorganic jester fuzzy";
const char* VK_SPEND_PRIV = "482700617ba810f94035d7f4d7ccc1a29878e165b4867872b705204c85406906";
const char* VK_VIEW_PRIV  = "09ed72c713d3e9e19bef2f5204cf85f6cb25de7842aa0722abeb12697f171903";
const char* VK_SPEND_PUB  = "4ee576f52b9c6a824a3d5c2832d117177d2bb9992507c2c78788bb8dbaf4b640";
const char* VK_VIEW_PUB   = "e1ef99d66312ec0b16b17c66c591ab59594e21621588b63b62fa69fe615a768e";
const char* VK_ADDRESS    =
    "44cWztNFdAqNnycvZbUoj44vsbAEmKnx9aNgkjHdjtMsBrSeKiY8J4s2raH7EMawA2Fwo9utaRTV7Aw8EcTMNMxhH4YtKdH";

// VM: monero-python test_seed.py::test_mnemonic_seed  (25-word <-> hex)
const char* VM_MNEMONIC_25 =
    "wedge going quick racetrack auburn physics lectures light waist axes whipped "
    "habitat square awkward together injury niece nugget guarded hive obnoxious "
    "waxing faked folding square";
const char* VM_MNEMONIC_24 =   // same seed, checksum word dropped
    "wedge going quick racetrack auburn physics lectures light waist axes whipped "
    "habitat square awkward together injury niece nugget guarded hive obnoxious "
    "waxing faked folding";
const char* VM_HEX = "8ffa9f586b86d294d93731765d192765311bddc76a4fa60311f8af36bbf6fb06";

// VS: monero-rs subaddress.rs  (view pair -> subaddress at index 2/18)
const char* VS_VIEW_PRIV     = "77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404";
const char* VS_SPEND_PRIV    = "8163466f1883598e6dd14027b8da727057165da91485834314f5500a65846f09";
const char* VS_SUB_VIEW_PUB  = "601782bdde614e9ba664048a27b7407df4b76ae2e50a85fcc168a4c1766b3edf";
const char* VS_SUB_SPEND_PUB = "c25179ddef2ca4728fb691dd71561dc9f2e7e6b2a14284a4fe5441d7757aea02";
const char* VS_SUBADDRESS    =
    "89pMNxzcCo5LAPZDX4qaTeanA6ZiS3VRdUbeKHzbDZkD1Q3YsDDfmXbT2zyjLeHWuuN4vxKne8kNpjH3cMk7nmhwSALCxsd";

// VA: monero-python test_address.py::AddressTestCase (mainnet)
const char* VA_STD  = "47ewoP19TN7JEEnFKUJHAYhGxkeTRH82sf36giEp9AcNfDBfkAtRLX7A6rZz18bbNHPNV7ex6WYbMN3aKisFRJZ8Ebsmgef";
const char* VA_PSK  = "9f2a76d879aaf0670039dc8dbdca01f0ca26a2f6d93268e3674666bfdc5957e4";
const char* VA_PVK  = "716cfc7da7e6ce366935c55747839a85be798037ab189c7dd0f10b7f1690cb78";
const char* VA_IADDR =
    "4HMcpBpe4ddJEEnFKUJHAYhGxkeTRH82sf36giEp9AcNfDBfkAtRLX7A6rZz18bbNHPNV7ex6WYbMN3aKisFRJZ8M7yKhzQhKW3ECCLWQw";
const char* VA_PID   = "4a6f686e47616c74";   // "JohnGalt"
const char* VA_SUB   = "84LooD7i35SFppgf4tQ453Vi3q5WexSUXaVgut69ro8MFnmHwuezAArEZTZyLr9fS6QotjqkSAxSF6d1aDgsPoX849izJ7m";

std::array<std::uint8_t, 8> pid_from_hex(const std::string& hex)
{
    std::array<std::uint8_t, 8> out{};
    for (std::size_t i = 0; i < 8; ++i)
        out[i] = static_cast<std::uint8_t>(std::stoi(hex.substr(2 * i, 2), nullptr, 16));
    return out;
}

// ---- tests -----------------------------------------------------------------

void test_mnemonic_to_keys_and_address()
{
    std::printf("[VK] 25-word mnemonic -> keys -> primary address (monero-python)\n");
    KeyImportResult ki = keys_from_mnemonic(VK_MNEMONIC);
    check(ki.ok, "mnemonic decodes (checksum word verified)");
    if (!ki.ok) { std::printf("       %s\n", ki.error.c_str()); return; }
    eq_str(bytes32_to_hex(ki.keys.spend_priv), VK_SPEND_PRIV, "secret spend key");
    eq_str(bytes32_to_hex(ki.keys.view_priv),  VK_VIEW_PRIV,  "secret view key = H_s(spend)");
    eq_str(bytes32_to_hex(ki.keys.spend_pub),  VK_SPEND_PUB,  "public spend key");
    eq_str(bytes32_to_hex(ki.keys.view_pub),   VK_VIEW_PUB,   "public view key");
    eq_str(address_encode(primary_address(ki.keys)), VK_ADDRESS, "primary address");
}

void test_mnemonic_roundtrip()
{
    std::printf("[VM] mnemonic <-> hex round-trip + checksum word (monero-python)\n");
    MnemonicDecode d25 = mnemonic_decode(VM_MNEMONIC_25);
    check(d25.ok && d25.had_checksum, "25-word phrase decodes with checksum");
    eq_str(bytes32_to_hex(d25.key), VM_HEX, "25-word decode -> hex");

    MnemonicDecode d24 = mnemonic_decode(VM_MNEMONIC_24);
    check(d24.ok && !d24.had_checksum, "24-word (checksum-less) phrase decodes");
    eq_str(bytes32_to_hex(d24.key), VM_HEX, "24-word decode -> same hex");

    Bytes32 key{};
    hex_to_bytes32(VM_HEX, key);
    eq_str(mnemonic_encode(key), VM_MNEMONIC_25, "hex -> 25-word phrase (encode incl. checksum)");

    // Reject a corrupted checksum word.
    std::string bad = std::string(VM_MNEMONIC_24) + " abbey";
    MnemonicDecode dbad = mnemonic_decode(bad);
    check(!dbad.ok, "wrong checksum word is rejected");
}

void test_subaddress_derivation()
{
    std::printf("[VS] subaddress derivation index (2,18) (monero-rs)\n");
    Bytes32 view_priv{}, spend_priv{}, spend_pub{};
    hex_to_bytes32(VS_VIEW_PRIV, view_priv);
    hex_to_bytes32(VS_SPEND_PRIV, spend_priv);
    check(mcrypto::secret_to_public(spend_priv, spend_pub), "spend pub B = b*G");

    SubaddressResult s = derive_subaddress(view_priv, spend_pub, 2, 18);
    check(s.ok, "subaddress derives");
    if (!s.ok) { std::printf("       %s\n", s.error.c_str()); return; }
    eq_str(bytes32_to_hex(s.sub_spend_pub), VS_SUB_SPEND_PUB, "sub spend pub = S + m*G");
    eq_str(bytes32_to_hex(s.sub_view_pub),  VS_SUB_VIEW_PUB,  "sub view pub  = v*(S+m*G)");
    eq_str(address_encode(s.addr), VS_SUBADDRESS, "subaddress string (netbyte 42)");
}

void test_address_base58_roundtrip()
{
    std::printf("[VA] address base58 + keccak checksum round-trips (monero-python)\n");

    // Standard.
    MoneroAddress std_a; std::string err;
    check(address_decode(VA_STD, std_a, err), "standard address decodes (checksum ok)");
    check(std_a.type == AddressType::Standard && std_a.net == Network::Mainnet, "standard tag = 18");
    eq_str(bytes32_to_hex(std_a.spend_pub), VA_PSK, "standard: public spend key");
    eq_str(bytes32_to_hex(std_a.view_pub),  VA_PVK, "standard: public view key");
    eq_str(address_encode(std_a), VA_STD, "standard: re-encode round-trips");

    // Integrated (payment id).
    MoneroAddress ia;
    check(address_decode(VA_IADDR, ia, err), "integrated address decodes");
    check(ia.type == AddressType::Integrated, "integrated tag = 19");
    {
        std::string pidhex(16, '0');
        static const char* d = "0123456789abcdef";
        for (int i = 0; i < 8; ++i) { pidhex[2*i]=d[ia.payment_id[i]>>4]; pidhex[2*i+1]=d[ia.payment_id[i]&0xf]; }
        eq_str(pidhex, VA_PID, "integrated: 8-byte payment id");
    }
    eq_str(address_encode(ia), VA_IADDR, "integrated: re-encode round-trips");
    check(ia.spend_pub == std_a.spend_pub && ia.view_pub == std_a.view_pub,
          "integrated shares the base address keys");

    // Subaddress string.
    MoneroAddress sa;
    check(address_decode(VA_SUB, sa, err), "subaddress string decodes");
    check(sa.type == AddressType::Subaddress, "subaddress tag = 42");
    eq_str(address_encode(sa), VA_SUB, "subaddress: re-encode round-trips");

    // Programmatic integrated construction from the base keys + payment id.
    MoneroAddress built = make_integrated(std_a.spend_pub, std_a.view_pub, pid_from_hex(VA_PID));
    eq_str(address_encode(built), VA_IADDR, "constructed integrated == published");

    // Raw byte-level base58 round-trip on non-block-aligned data.
    std::vector<std::uint8_t> raw;
    for (int i = 0; i < 37; ++i) raw.push_back(static_cast<std::uint8_t>(i * 7 + 1));
    std::vector<std::uint8_t> back;
    check(base58_decode(base58_encode(raw), back) && back == raw, "base58 raw round-trip (37 bytes)");
}

void test_generation_roundtrip()
{
    std::printf("[GEN] getrandom(2) generation -> re-derive round-trip\n");
    GeneratedWallet w; std::string err;
    check(generate_wallet(w, err), "generate_wallet via getrandom(2)");
    if (err.size()) { std::printf("       %s\n", err.c_str()); }
    check(w.mnemonic.find(' ') != std::string::npos, "produced a mnemonic phrase");
    check(mcrypto::is_canonical_scalar(w.keys.spend_priv), "generated spend key is a canonical scalar");

    // Re-import the generated mnemonic; keys must match bit-for-bit.
    KeyImportResult re = keys_from_mnemonic(w.mnemonic);
    check(re.ok, "generated mnemonic re-imports");
    check(re.keys.spend_priv == w.keys.spend_priv, "re-derived spend priv matches");
    check(re.keys.view_priv  == w.keys.view_priv,  "re-derived view priv matches");
    eq_str(address_encode(primary_address(re.keys)),
           address_encode(primary_address(w.keys)), "re-derived primary address matches");
}

void test_import_forms()
{
    std::printf("[IMP] dual-key + view-only import (VK keys)\n");

    KeyImportResult dual = keys_from_dual_hex(VK_SPEND_PRIV, VK_VIEW_PRIV);
    check(dual.ok && dual.keys.can_sign(), "dual import ok and can sign");
    eq_str(bytes32_to_hex(dual.keys.spend_pub), VK_SPEND_PUB, "dual: derived public spend key");
    eq_str(address_encode(primary_address(dual.keys)), VK_ADDRESS, "dual: primary address matches VK");

    KeyImportResult vo = keys_view_only(VK_SPEND_PUB, VK_VIEW_PRIV);
    check(vo.ok, "view-only import ok");
    check(!vo.keys.can_sign(), "view-only cannot sign");
    eq_str(bytes32_to_hex(vo.keys.view_pub), VK_VIEW_PUB, "view-only: derived public view key");
    eq_str(address_encode(primary_address(vo.keys)), VK_ADDRESS, "view-only: primary address matches VK");

    // A non-canonical scalar (all 0xFF) must be rejected on dual import.
    std::string ff(64, 'f');
    check(!keys_from_dual_hex(ff, VK_VIEW_PRIV).ok, "non-canonical spend scalar rejected");
}

} // namespace

int main()
{
    std::printf("=== c2wallet-qt Family B (Monero) seed/key/address KATs ===\n\n");
    test_mnemonic_to_keys_and_address();
    test_mnemonic_roundtrip();
    test_subaddress_derivation();
    test_address_base58_roundtrip();
    test_generation_roundtrip();
    test_import_forms();

    std::printf("\n=== %d checks, %d failures ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
