// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// The V34/V35 share address, exactly as the python DGB network reads it
// (review 713dc77a0 #7, #6).
//
// A V34/V35 share carries its payout as an address string. The python oracle
// (frstrtr/p2pool-dgb-scrypt, bitcoin/data.py address_to_script2) turns it into
// the output script as follows, and a share whose address it cannot turn into
// a script is invalid there (Share.__init__ raises):
//   - base58check of 25 bytes (version, hash160, checksum), the string
//     exactly its canonical encoding (no surrounding whitespace): the version
//     must be ADDRESS_VERSION (30) or ADDRESS_P2SH_VERSION (63); any other
//     version is an error (not a fall-through) -> P2PKH / P2SH;
//   - else BIP173 bech32 (util/segwit_addr.py: bech32 checksum only, never
//     bech32m; one case, upper or lower; hrp "dgb"; witness version <= 16;
//     program 2..40 bytes; version 0 only 20 or 32):
//       the program is read as one big integer and printed with '{:040x}'
//       (load_share sets net.PARENT.padding_bugfix for share type >= 35), so
//       it is at least 40 hex digits: a 20-byte program is exact, a 32-byte one
//       loses its leading zero bytes, and an odd digit count (a 32-byte program
//       whose first nibble is 0) is an error; the script is 0x00, the byte
//       count, the bytes -- opcode 0 whatever the witness version;
//   - anything else is an error.
// The stratum refuses P2WSH/P2TR logins anyway (a V35 share cannot pay them).
// The outputs of a V35 generation transaction are sorted by (amount, address
// string) (data.py generate_transaction); v35_script_to_address gives the
// canonical address string of a script, the sort key.
// ---------------------------------------------------------------------------

#include <btclibs/base58.h>
#include <core/hash.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dgb {

struct V35AddressNet {
    uint8_t p2pkh = 30;
    uint8_t p2sh = 63;
    std::vector<std::string> hrps{"dgb"};
};

/// Mainnet: the oracle's own network. Testnet (no python oracle): DGB testnet
/// versions, and the regtest HRP besides the testnet one.
inline V35AddressNet v35_address_net(bool testnet)
{
    if (!testnet)
        return {};
    V35AddressNet n;
    n.p2pkh = 126;
    n.p2sh = 140;
    n.hrps = {"dgbt", "dgbrt"};
    return n;
}

namespace v35_detail {

inline constexpr const char* kCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

inline uint32_t polymod(const std::vector<uint8_t>& v)
{
    static const uint32_t gen[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    for (uint8_t x : v) {
        const uint32_t b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ x;
        for (int i = 0; i < 5; ++i)
            if ((b >> i) & 1)
                chk ^= gen[i];
    }
    return chk;
}

inline std::vector<uint8_t> hrp_expand(const std::string& hrp)
{
    std::vector<uint8_t> r;
    for (char c : hrp)
        r.push_back(static_cast<uint8_t>(static_cast<unsigned char>(c) >> 5));
    r.push_back(0);
    for (char c : hrp)
        r.push_back(static_cast<uint8_t>(static_cast<unsigned char>(c) & 31));
    return r;
}

/// segwit_addr.bech32_decode: (hrp, data without checksum) or nullopt.
inline std::optional<std::pair<std::string, std::vector<uint8_t>>> bech32_decode(std::string bech)
{
    bool lower = false, upper = false;
    for (char c : bech) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u < 33 || u > 126)
            return std::nullopt;
        lower = lower || (c >= 'a' && c <= 'z');
        upper = upper || (c >= 'A' && c <= 'Z');
    }
    if (lower && upper)
        return std::nullopt;
    for (auto& c : bech)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    const auto pos = bech.rfind('1');
    if (pos == std::string::npos || pos < 1 || pos + 7 > bech.size() || bech.size() > 90)
        return std::nullopt;
    std::vector<uint8_t> data;
    for (size_t i = pos + 1; i < bech.size(); ++i) {
        const char* p = std::char_traits<char>::find(kCharset, 32, bech[i]);
        if (!p)
            return std::nullopt;
        data.push_back(static_cast<uint8_t>(p - kCharset));
    }
    const std::string hrp = bech.substr(0, pos);
    auto v = hrp_expand(hrp);
    v.insert(v.end(), data.begin(), data.end());
    if (polymod(v) != 1)   // BIP173 only: a bech32m checksum fails here
        return std::nullopt;
    data.resize(data.size() - 6);
    return std::make_pair(hrp, data);
}

/// segwit_addr.convertbits(data, 5, 8, False).
inline std::optional<std::vector<uint8_t>> from5(const std::vector<uint8_t>& d)
{
    uint32_t acc = 0;
    int bits = 0;
    std::vector<uint8_t> out;
    for (uint8_t x : d) {
        if (x >> 5)
            return std::nullopt;
        acc = ((acc << 5) | x) & 0xfff;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xff));
        }
    }
    if (bits >= 5 || ((acc << (8 - bits)) & 0xff))
        return std::nullopt;
    return out;
}

inline std::vector<uint8_t> to5(const std::vector<uint8_t>& d)
{
    uint32_t acc = 0;
    int bits = 0;
    std::vector<uint8_t> out;
    for (uint8_t x : d) {
        acc = ((acc << 8) | x) & 0xfff;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 31));
        }
    }
    if (bits)
        out.push_back(static_cast<uint8_t>((acc << (5 - bits)) & 31));
    return out;
}

} // namespace v35_detail

/// The output script the python DGB network pays a V34/V35 share address,
/// or nullopt where it raises (the share is invalid there).
inline std::optional<std::vector<unsigned char>> v35_address_to_script(const std::string& addr,
                                                                       const V35AddressNet& net)
{
    // Base58check of exactly version + 20-byte hash + checksum.
    {
        // DecodeBase58Check skips leading/trailing whitespace; python's
        // base58_decode does not (and bech32_decode then rejects it), so the
        // string must be exactly the canonical encoding of its payload.
        std::vector<unsigned char> payload;
        if (DecodeBase58Check(addr, payload, 21) && payload.size() == 21
            && EncodeBase58Check(Span<const unsigned char>(payload.data(), payload.size())) == addr) {
            std::vector<unsigned char> s;
            if (payload[0] == net.p2pkh) {
                s = {0x76, 0xa9, 0x14};
                s.insert(s.end(), payload.begin() + 1, payload.end());
                s.push_back(0x88);
                s.push_back(0xac);
                return s;
            }
            if (payload[0] == net.p2sh) {
                s = {0xa9, 0x14};
                s.insert(s.end(), payload.begin() + 1, payload.end());
                s.push_back(0x87);
                return s;
            }
            return std::nullopt;   // "address not for this net!": an error, not a fall-through
        }
    }
    const auto dec = v35_detail::bech32_decode(addr);
    if (!dec || dec->second.empty())
        return std::nullopt;
    bool hrp_ok = false;
    for (const auto& h : net.hrps)
        hrp_ok = hrp_ok || h == dec->first;
    if (!hrp_ok)
        return std::nullopt;
    const uint8_t witver = dec->second[0];
    const auto prog = v35_detail::from5(std::vector<uint8_t>(dec->second.begin() + 1, dec->second.end()));
    if (!prog || prog->size() < 2 || prog->size() > 40 || witver > 16)
        return std::nullopt;
    if (witver == 0 && prog->size() != 20 && prog->size() != 32)
        return std::nullopt;
    // '{:040x}'.format(int(program)): the significant hex digits, left-padded
    // with '0' to 40; an odd count cannot be unhexlified.
    static const char* H = "0123456789abcdef";
    std::string hex;
    for (uint8_t b : *prog) {
        hex += H[b >> 4];
        hex += H[b & 15];
    }
    const auto nz = hex.find_first_not_of('0');
    hex = nz == std::string::npos ? std::string("0") : hex.substr(nz);
    if (hex.size() < 40)
        hex.insert(0, 40 - hex.size(), '0');
    if (hex.size() % 2)
        return std::nullopt;
    std::vector<unsigned char> s{0x00, static_cast<unsigned char>(hex.size() / 2)};
    for (size_t i = 0; i < hex.size(); i += 2)
        s.push_back(static_cast<unsigned char>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    return s;
}

/// The canonical V35 address string of a payout script (base58 P2PKH/P2SH,
/// lowercase bech32 v0 for 0x00-prefixed programs), "" when it has none: the
/// key python sorts a V35 generation transaction's outputs by.
inline std::string v35_script_to_address(const std::vector<unsigned char>& s, const V35AddressNet& net)
{
    auto b58 = [](uint8_t ver, const unsigned char* h) {
        std::vector<unsigned char> p{ver};
        p.insert(p.end(), h, h + 20);
        return EncodeBase58Check(Span<const unsigned char>(p.data(), p.size()));
    };
    if (s.size() == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac)
        return b58(net.p2pkh, s.data() + 3);
    if (s.size() == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87)
        return b58(net.p2sh, s.data() + 2);
    if (s.size() >= 4 && s[0] == 0x00 && s[1] == s.size() - 2) {
        std::vector<uint8_t> d{0};
        const auto p5 = v35_detail::to5(std::vector<uint8_t>(s.begin() + 2, s.end()));
        d.insert(d.end(), p5.begin(), p5.end());
        const std::string& hrp = net.hrps.front();
        auto v = v35_detail::hrp_expand(hrp);
        v.insert(v.end(), d.begin(), d.end());
        v.insert(v.end(), 6, 0);
        const uint32_t pm = v35_detail::polymod(v) ^ 1;
        std::string out = hrp + "1";
        for (uint8_t x : d)
            out += v35_detail::kCharset[x];
        for (int i = 0; i < 6; ++i)
            out += v35_detail::kCharset[(pm >> (5 * (5 - i))) & 31];
        return out;
    }
    return {};
}

} // namespace dgb
