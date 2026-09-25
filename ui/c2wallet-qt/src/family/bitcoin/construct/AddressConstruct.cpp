// SPDX-License-Identifier: AGPL-3.0-or-later
#include "AddressConstruct.hpp"

#include "../hdkeys/Address.hpp"   // encode_p2sh, encode_segwit_v
#include "../hdkeys/Bip32.hpp"     // hash160
#include "../hdkeys/HexUtil.hpp"   // to_hex

#include <btclibs/crypto/sha256.h> // CSHA256

#include <array>

namespace c2w::construct {

using c2w::hdkeys::hash160;

static std::array<uint8_t, 32> sha256_of(const std::vector<uint8_t>& v)
{
    std::array<uint8_t, 32> out{};
    CSHA256().Write(v.data(), v.size()).Finalize(out.data());
    return out;
}

static std::vector<unsigned char> p2sh_spk(const std::array<uint8_t, 20>& h)
{
    std::vector<unsigned char> s = {0xa9, 0x14};
    s.insert(s.end(), h.begin(), h.end());
    s.push_back(0x87);
    return s;
}

BuiltAddress build_p2sh(uint8_t p2sh_version, const std::vector<uint8_t>& redeem)
{
    BuiltAddress b; b.type = "P2SH";
    if (redeem.empty()) return b;
    auto h = hash160(redeem.data(), redeem.size());
    b.address    = c2w::hdkeys::encode_p2sh(p2sh_version, h);
    b.script     = p2sh_spk(h);
    b.script_hex = c2w::hdkeys::to_hex(std::vector<uint8_t>(b.script.begin(), b.script.end()));
    return b;
}

BuiltAddress build_p2wsh(const std::string& hrp, const std::vector<uint8_t>& witness_script)
{
    BuiltAddress b; b.type = "P2WSH";
    if (hrp.empty() || witness_script.empty()) return b;
    auto sh = sha256_of(witness_script);
    std::vector<uint8_t> prog(sh.begin(), sh.end());
    b.address = c2w::hdkeys::encode_segwit_v(hrp, 0, prog, /*bech32m=*/false);
    b.script  = {0x00, 0x20};
    b.script.insert(b.script.end(), sh.begin(), sh.end());
    b.script_hex = c2w::hdkeys::to_hex(std::vector<uint8_t>(b.script.begin(), b.script.end()));
    return b;
}

BuiltAddress build_p2sh_p2wsh(uint8_t p2sh_version, const std::vector<uint8_t>& witness_script)
{
    BuiltAddress b; b.type = "P2SH-P2WSH";
    if (witness_script.empty()) return b;
    auto sh = sha256_of(witness_script);
    // The redeemScript is the witness program: OP_0 <32-byte SHA256(wScript)>.
    std::vector<uint8_t> redeem = {0x00, 0x20};
    redeem.insert(redeem.end(), sh.begin(), sh.end());
    auto h = hash160(redeem.data(), redeem.size());
    b.address    = c2w::hdkeys::encode_p2sh(p2sh_version, h);
    b.script     = p2sh_spk(h);
    b.script_hex = c2w::hdkeys::to_hex(std::vector<uint8_t>(b.script.begin(), b.script.end()));
    return b;
}

BuiltAddress build_p2sh_p2wpkh(uint8_t p2sh_version, const std::vector<uint8_t>& pubkey)
{
    BuiltAddress b; b.type = "P2SH-P2WPKH";
    if (pubkey.size() != 33) return b;   // segwit requires the compressed key
    auto hp = hash160(pubkey.data(), pubkey.size());
    std::vector<uint8_t> redeem = {0x00, 0x14};
    redeem.insert(redeem.end(), hp.begin(), hp.end());
    auto h = hash160(redeem.data(), redeem.size());
    b.address    = c2w::hdkeys::encode_p2sh(p2sh_version, h);
    b.script     = p2sh_spk(h);
    b.script_hex = c2w::hdkeys::to_hex(std::vector<uint8_t>(b.script.begin(), b.script.end()));
    return b;
}

std::vector<uint8_t> build_bare_multisig_script(int m, const std::vector<std::vector<uint8_t>>& pks)
{
    const int n = static_cast<int>(pks.size());
    if (m < 1 || n < m || n > 16) return {};
    std::vector<uint8_t> s;
    s.push_back(static_cast<uint8_t>(0x50 + m));   // OP_m (OP_1..OP_16)
    for (const auto& pk : pks) {
        if (pk.size() != 33 && pk.size() != 65) return {};
        s.push_back(static_cast<uint8_t>(pk.size()));
        s.insert(s.end(), pk.begin(), pk.end());
    }
    s.push_back(static_cast<uint8_t>(0x50 + n));   // OP_n
    s.push_back(0xae);                             // OP_CHECKMULTISIG
    return s;
}

} // namespace c2w::construct
