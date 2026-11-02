// SPDX-License-Identifier: AGPL-3.0-or-later
#include "DashAddress.hpp"

#include "DashError.hpp"

// btclibs base58check codec (reused, design §2.4), for both directions. The
// encoder is the same framing hdkeys::encode_p2pkh uses (base58check over the
// version byte + hash160), called directly so this key-free file
// (c2wallet-dash-plan) never references hdkeys Address.cpp: that object also
// derives address candidates from a secret scalar and would pull the BIP32 /
// secp256k1 key code into the online companion. NO dashscript headers here.
#include <base58.h>

#include <vector>

namespace c2w::dash {

uint8_t p2pkh_version(bool testnet)
{
    return testnet ? kTestnetP2PKHVersion : kMainnetP2PKHVersion;
}

std::array<uint8_t, 20> addr_to_h160(const std::string& addr, bool testnet)
{
    std::vector<unsigned char> raw;
    // 21 = 1 version byte + 20 payload; DecodeBase58Check strips+verifies the
    // 4-byte checksum. A bad checksum returns false -> hard abort.
    if (!DecodeBase58Check(addr, raw, 21))
        throw DashAbort("bad base58 checksum or over-long address: " + addr);
    if (raw.size() != 21)
        throw DashAbort("address " + addr + " payload is not 21 bytes (version + hash160)");
    const uint8_t version = raw[0];
    const uint8_t expected = p2pkh_version(testnet);
    if (version != expected)
        throw DashAbort("address " + addr + " has the wrong version byte for this network "
                        "(wrong network or not a P2PKH address)");
    std::array<uint8_t, 20> h160{};
    for (size_t i = 0; i < 20; ++i) h160[i] = raw[1 + i];
    return h160;
}

std::string h160_to_addr(const std::array<uint8_t, 20>& h160, bool testnet)
{
    std::vector<unsigned char> v;
    v.reserve(21);
    v.push_back(p2pkh_version(testnet));
    v.insert(v.end(), h160.begin(), h160.end());
    return EncodeBase58Check(Span<const unsigned char>(v.data(), v.size()));
}

std::array<uint8_t, 25> p2pkh_script(const std::array<uint8_t, 20>& h160)
{
    std::array<uint8_t, 25> s{};
    s[0] = 0x76; // OP_DUP
    s[1] = 0xA9; // OP_HASH160
    s[2] = 0x14; // push 20
    for (size_t i = 0; i < 20; ++i) s[3 + i] = h160[i];
    s[23] = 0x88; // OP_EQUALVERIFY
    s[24] = 0xAC; // OP_CHECKSIG
    return s;
}

} // namespace c2w::dash
