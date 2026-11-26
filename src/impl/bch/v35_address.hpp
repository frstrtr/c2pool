// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// v34/v35 share payout address <-> scriptPubKey, the python BCH p2pool rule.
//
// A v34/v35 share carries its payout as an address STRING (share_data.address).
// Python turns it into a script with bitcoin/data.py address_to_script2() and
// rejects the share (Share.__init__ raises) when that fails. This header is that
// rule, with nothing taken from a process-wide decoder registry, so every caller
// (verify, author, tests, other entrypoints) sees the same result.
//
// References: frstrtr/kr1z1sBCH c198121 (the public node, 5493200-dirty) and
// frstrtr/p2poolBCH 6603b79; bitcoin/data.py, util/cash_addr.py and
// util/math.py are identical in both.
//
// address_to_pubkey_hash(address, net):
//   1. Base58: '1's -> zero bytes, the rest a base-58 natural. The result must
//      be exactly 25 bytes (version, hash160, checksum) with a valid checksum,
//      else try CashAddr. With a valid checksum the version must be the net's
//      ADDRESS_VERSION or ADDRESS_P2SH_VERSION, else ValueError (no CashAddr
//      attempt).
//   2. CashAddr (cash_addr.decode(HUMAN_READABLE_PART, address)): printable
//      ASCII only, no mixed case, prefix optional (default the net's), payload
//      9..112 chars from the charset, size bits of the version byte must match
//      the payload length, PolyMod must be 0, prefix must equal the net's.
//      type = (version_byte & 0x78) >> 3. The reserved top bit is not checked
//      (valid_version tests bit 8 of a byte).
//   3. Anything else: ValueError('invalid addr').
// pubkey_hash_to_script2 (padding_bugfix=True, the v35 setting):
//   legacy:   P2SH version -> a9 14 h 87, else 76 a9 14 h 88 ac
//   CashAddr: the hash goes through int('{:040x}'): leading zero bytes are
//             dropped, then left-padded to 20 bytes; an odd hex length raises.
//             type 0 -> 76 a9 <len> h 88 ac, type 1 -> a9 <len> h 87, any other
//             type raises NotImplementedError.
//
// padding_bugfix: p2pool's load_share sets net.PARENT.padding_bugfix =
// (share type >= 35), a process-wide flag. jtoomim's p2poolBCH therefore runs
// v34 shares with it False ('{:x}', no padding to 20 bytes, so a hash with a
// leading zero byte becomes a shorter push). kr1z1sBCH, the public chain, has
// only v35 shares. This rule is the v35 (True) one for every share; the v34
// difference is unreachable on the live chain.

#include <btclibs/crypto/sha256.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace bch
{

// The python network constants (bitcoin/networks/bitcoincash[_testnet].py)
// plus donation_script_to_address(net): the legacy P2PKH form of the hash160 of
// the v35 DONATION_SCRIPT pubkey (d03da6fca390166d020be0e7c28ac8cc70f58403).
struct V35Net
{
    uint8_t p2pkh_version;
    uint8_t p2sh_version;
    std::string_view hrp;
    std::string_view donation_address;
};

inline constexpr V35Net V35_MAINNET{0x00, 0x05, "bitcoincash", "1Kz5QaUPDtKrj5SqW5tFkn7WZh8LmQaQi4"};
inline constexpr V35Net V35_TESTNET{0x6f, 0xc4, "bchtest", "mzW2hdZN2um7WBvTDerdahKqRgj3md9C29"};

inline const V35Net& v35_net(bool testnet) { return testnet ? V35_TESTNET : V35_MAINNET; }

// Thrown for every address python refuses. The share that carries it is invalid.
struct V35AddressError : std::invalid_argument
{
    using std::invalid_argument::invalid_argument;
};

namespace v35_detail
{

inline constexpr std::string_view BASE58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
inline constexpr std::string_view CASHADDR_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

inline std::array<unsigned char, 32> sha256d(const unsigned char* p, size_t n)
{
    std::array<unsigned char, 32> a{}, b{};
    CSHA256().Write(p, n).Finalize(a.data());
    CSHA256().Write(a.data(), a.size()).Finalize(b.data());
    return b;
}

// base58_decode(): '\0' per leading '1', then natural_to_string of the rest.
// nullopt where python raises (a character outside the alphabet). A string
// longer than 59 characters cannot come out at 25 bytes (at most 24 leading
// '1's plus 35 digits), so it is answered as "not 25 bytes" without the
// big-number work; the caller treats both the same way.
inline std::optional<std::vector<unsigned char>> base58_decode(std::string_view s)
{
    size_t zeros = 0;
    while (zeros < s.size() && s[zeros] == '1')
        ++zeros;
    if (s.size() > 59)
        return std::vector<unsigned char>(26, 0);   // any length != 25
    std::vector<unsigned char> num;                  // big-endian natural
    for (size_t i = zeros; i < s.size(); ++i)
    {
        auto pos = BASE58_ALPHABET.find(s[i]);
        if (pos == std::string_view::npos)
            return std::nullopt;
        unsigned carry = static_cast<unsigned>(pos);
        for (auto it = num.rbegin(); it != num.rend(); ++it)
        {
            carry += 58u * *it;
            *it = static_cast<unsigned char>(carry & 0xff);
            carry >>= 8;
        }
        while (carry)
        {
            num.insert(num.begin(), static_cast<unsigned char>(carry & 0xff));
            carry >>= 8;
        }
    }
    size_t lead = 0;
    while (lead < num.size() && num[lead] == 0)
        ++lead;
    std::vector<unsigned char> out(zeros, 0);
    out.insert(out.end(), num.begin() + static_cast<std::ptrdiff_t>(lead), num.end());
    return out;
}

// base58_encode(): one '1' per leading zero byte, then the base-58 digits.
inline std::string base58_encode(const std::vector<unsigned char>& data)
{
    size_t zeros = 0;
    while (zeros < data.size() && data[zeros] == 0)
        ++zeros;
    std::vector<unsigned char> num(data.begin() + static_cast<std::ptrdiff_t>(zeros), data.end());
    std::string digits;
    while (!num.empty())
    {
        unsigned rem = 0;
        std::vector<unsigned char> q;
        q.reserve(num.size());
        for (unsigned char byte : num)
        {
            unsigned cur = (rem << 8) | byte;
            unsigned d = cur / 58;
            rem = cur % 58;
            if (!q.empty() || d)
                q.push_back(static_cast<unsigned char>(d));
        }
        digits.push_back(BASE58_ALPHABET[rem]);
        num.swap(q);
    }
    return std::string(zeros, '1') + std::string(digits.rbegin(), digits.rend());
}

inline uint64_t cashaddr_polymod(const std::vector<uint8_t>& values)
{
    static constexpr uint64_t GEN[5] = {
        0x98f2bc8e61ULL, 0x79b76d99e2ULL, 0xf33e5fb3c4ULL, 0xae2eabe2a8ULL, 0x1e4f43e470ULL};
    uint64_t chk = 1;
    for (uint8_t v : values)
    {
        uint64_t top = chk >> 35;
        chk = ((chk & 0x07ffffffffULL) << 5) ^ v;
        for (int i = 0; i < 5; ++i)
            if ((top >> i) & 1)
                chk ^= GEN[i];
    }
    return chk ^ 1;
}

inline std::vector<uint8_t> cashaddr_expand_prefix(std::string_view prefix)
{
    std::vector<uint8_t> v;
    v.reserve(prefix.size() + 1);
    for (char c : prefix)
        v.push_back(static_cast<uint8_t>(static_cast<unsigned char>(c) & 31));
    v.push_back(0);
    return v;
}

// util/math.py convertbits(). nullopt where python returns None.
inline std::optional<std::vector<uint8_t>> convertbits(const std::vector<uint8_t>& data,
                                                       unsigned frombits, unsigned tobits, bool pad)
{
    uint32_t acc = 0;
    unsigned bits = 0;
    std::vector<uint8_t> ret;
    const uint32_t maxv = (1u << tobits) - 1;
    const uint32_t max_acc = (1u << (frombits + tobits - 1)) - 1;
    for (uint8_t value : data)
    {
        if (value >> frombits)
            return std::nullopt;
        acc = ((acc << frombits) | value) & max_acc;
        bits += frombits;
        while (bits >= tobits)
        {
            bits -= tobits;
            ret.push_back(static_cast<uint8_t>((acc >> bits) & maxv));
        }
    }
    if (pad)
    {
        if (bits)
            ret.push_back(static_cast<uint8_t>((acc << (tobits - bits)) & maxv));
    }
    else if (bits >= frombits || ((acc << (tobits - bits)) & maxv))
    {
        return std::nullopt;
    }
    return ret;
}

// cash_addr.decode(prefix, addr): (type, hash bytes), nullopt for (None, None).
inline std::optional<std::pair<unsigned, std::vector<uint8_t>>>
cashaddr_decode(std::string_view hrp, std::string_view addr)
{
    // disassemble(): printable ASCII only, and not mixed case.
    bool has_lower = false, has_upper = false;
    for (char ch : addr)
    {
        auto c = static_cast<unsigned char>(ch);
        if (c < 33 || c > 126)
            return std::nullopt;
        if (c >= 'a' && c <= 'z') has_lower = true;
        if (c >= 'A' && c <= 'Z') has_upper = true;
    }
    if (has_lower && has_upper)
        return std::nullopt;
    std::string s(addr);
    for (auto& ch : s)
        if (ch >= 'A' && ch <= 'Z')
            ch = static_cast<char>(ch - 'A' + 'a');
    auto pos = s.rfind(':');
    if (pos == std::string::npos)
    {
        std::string p(hrp);
        for (auto& ch : p)
            if (ch >= 'A' && ch <= 'Z')
                ch = static_cast<char>(ch - 'A' + 'a');
        s = p + ":" + s;
        pos = p.size();
    }
    const size_t payload_len = s.size() - pos - 1;
    if (payload_len <= 8 || payload_len > 112)
        return std::nullopt;
    std::vector<uint8_t> data;
    data.reserve(payload_len);
    for (size_t i = pos + 1; i < s.size(); ++i)
    {
        auto f = CASHADDR_CHARSET.find(s[i]);
        if (f == std::string_view::npos)
            return std::nullopt;
        data.push_back(static_cast<uint8_t>(f));
    }
    const std::string prefix = s.substr(0, pos);
    const std::vector<uint8_t> body(data.begin(), data.end() - 8);
    // valid_version(data[:-8])
    auto converted = convertbits(body, 5, 8, false);
    if (!converted || converted->empty())
        return std::nullopt;
    const uint8_t ver = (*converted)[0];
    unsigned size_bits = 160 + (ver & 3) * 32;
    if (ver & 4)
        size_bits *= 2;
    if (converted->size() - 1 != size_bits / 8)
        return std::nullopt;
    // verify_checksum(prefix, data)
    auto values = cashaddr_expand_prefix(prefix);
    values.insert(values.end(), data.begin(), data.end());
    if (cashaddr_polymod(values) != 0)
        return std::nullopt;
    // decode(): the prefix must be the net's own.
    if (prefix != hrp)
        return std::nullopt;
    const unsigned type = (static_cast<unsigned>((*converted)[0]) & 0x78) >> 3;
    return std::make_pair(type, std::vector<uint8_t>(converted->begin() + 1, converted->end()));
}

} // namespace v35_detail

// cash_addr.encode(prefix, ver, data): "<prefix>:<payload>", or "" where python
// returns None (hash length not 20/24/28/32/40/48/56/64, or a type other than
// 0, 1 or 15).
inline std::string v35_cashaddr_encode(std::string_view hrp, unsigned type,
                                       const std::vector<uint8_t>& hash)
{
    static constexpr size_t SIZES[] = {20, 24, 28, 32, 40, 48, 56, 64};
    bool size_ok = false;
    for (size_t s : SIZES)
        size_ok = size_ok || hash.size() == s;
    if (!size_ok || !(type <= 1 || type == 15))
        return {};
    unsigned ver = type << 3;
    unsigned tmp = static_cast<unsigned>(hash.size()) * 8;
    unsigned dlen = 0;
    if (tmp > 256)
    {
        dlen ^= 0x04;
        tmp /= 2;
    }
    dlen += (tmp - 160) / 32;
    ver += dlen;
    std::vector<uint8_t> raw;
    raw.push_back(static_cast<uint8_t>(ver));
    raw.insert(raw.end(), hash.begin(), hash.end());
    auto five = v35_detail::convertbits(raw, 8, 5, true);
    if (!five)
        return {};
    auto values = v35_detail::cashaddr_expand_prefix(hrp);
    values.insert(values.end(), five->begin(), five->end());
    values.insert(values.end(), 8, 0);
    const uint64_t mod = v35_detail::cashaddr_polymod(values);
    std::string out(hrp);
    out.push_back(':');
    for (uint8_t d : *five)
        out.push_back(v35_detail::CASHADDR_CHARSET[d]);
    for (int i = 0; i < 8; ++i)
        out.push_back(v35_detail::CASHADDR_CHARSET[(mod >> (5 * (7 - i))) & 31]);
    if (!v35_detail::cashaddr_decode(hrp, out))
        return {};
    return out;
}

// human_address_type packed and Base58-encoded: version || hash160 || checksum.
inline std::string v35_legacy_address(uint8_t version, const unsigned char* hash160)
{
    std::vector<unsigned char> payload;
    payload.reserve(25);
    payload.push_back(version);
    payload.insert(payload.end(), hash160, hash160 + 20);
    auto chk = v35_detail::sha256d(payload.data(), payload.size());
    payload.insert(payload.end(), chk.begin(), chk.begin() + 4);
    return v35_detail::base58_encode(payload);
}

// address_to_script2(address, net) for a v34/v35 share. Throws V35AddressError
// wherever python raises; never returns an empty or raw-string "script".
inline std::vector<unsigned char> v35_address_to_script(std::string_view address, const V35Net& net)
{
    // 1. get_legacy_pubkey_hash
    if (auto raw = v35_detail::base58_decode(address); raw && raw->size() == 25)
    {
        auto chk = v35_detail::sha256d(raw->data(), 21);
        if (std::equal(chk.begin(), chk.begin() + 4, raw->begin() + 21))
        {
            const uint8_t ver = (*raw)[0];
            if (ver != net.p2pkh_version && ver != net.p2sh_version)
                throw V35AddressError("address not for this net!");
            std::vector<unsigned char> script;
            if (ver == net.p2sh_version)
            {
                script = {0xa9, 0x14};
                script.insert(script.end(), raw->begin() + 1, raw->begin() + 21);
                script.push_back(0x87);
            }
            else
            {
                script = {0x76, 0xa9, 0x14};
                script.insert(script.end(), raw->begin() + 1, raw->begin() + 21);
                script.push_back(0x88);
                script.push_back(0xac);
            }
            return script;
        }
    }

    // 2. get_cashaddr_pubkey_hash
    auto ca = v35_detail::cashaddr_decode(net.hrp, address);
    if (!ca)
        throw V35AddressError("invalid addr");
    const unsigned type = ca->first;
    const auto& hash = ca->second;

    // pubkey_hash_to_script2(int(hash), -1, type): '{:040x}' then unhexlify.
    size_t lead = 0;
    while (lead < hash.size() && hash[lead] == 0)
        ++lead;
    std::vector<unsigned char> h(hash.begin() + static_cast<std::ptrdiff_t>(lead), hash.end());
    const size_t hex_len = h.empty() ? 1 : 2 * h.size() - (h[0] < 0x10 ? 1 : 0);
    if (hex_len <= 40)
        h.insert(h.begin(), 20 - h.size(), 0);
    else if (hex_len % 2)
        throw V35AddressError("cashaddr hash has an odd hex length");
    if (type == 0)
    {
        std::vector<unsigned char> script = {0x76, 0xa9, static_cast<unsigned char>(h.size())};
        script.insert(script.end(), h.begin(), h.end());
        script.push_back(0x88);
        script.push_back(0xac);
        return script;
    }
    if (type == 1)
    {
        std::vector<unsigned char> script = {0xa9, static_cast<unsigned char>(h.size())};
        script.insert(script.end(), h.begin(), h.end());
        script.push_back(0x87);
        return script;
    }
    throw V35AddressError("Invalid cashaddr type " + std::to_string(type));
}

// The address our own v35 share carries for `script`: what python's
// script2_to_address(script, net.ADDRESS_VERSION / ADDRESS_P2SH_VERSION, -1, net)
// writes, i.e. the legacy Base58 form. Only 20-byte P2PKH and P2SH have one;
// any other script returns "" and must not be minted into a v35 share.
inline std::string v35_script_to_address(const std::vector<unsigned char>& script, const V35Net& net)
{
    if (script.size() == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 &&
        script[23] == 0x88 && script[24] == 0xac)
        return v35_legacy_address(net.p2pkh_version, script.data() + 3);
    if (script.size() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87)
        return v35_legacy_address(net.p2sh_version, script.data() + 2);
    return {};
}

} // namespace bch
