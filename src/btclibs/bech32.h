// Copyright (c) 2017 Pieter Wuille
// Distributed under the MIT software license, see
// https://opensource.org/licenses/MIT
//
// Minimal bech32 encoder for segwit address generation (BIP 173).
// Only encoding is provided; decoding is not needed for payout address
// derivation and is deliberately omitted to keep the surface area small.

#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace bech32 {

namespace detail {

static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// BIP-173 generator polynomial coefficients
static const uint32_t GEN[5] = {
    0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u
};

inline uint32_t polymod(const std::vector<uint8_t>& v)
{
    uint32_t chk = 1;
    for (uint8_t p : v) {
        uint8_t top = static_cast<uint8_t>(chk >> 25);
        chk = ((chk & 0x1ffffffu) << 5) ^ p;
        for (int i = 0; i < 5; ++i)
            if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk;
}

inline std::vector<uint8_t> hrp_expand(const std::string& hrp)
{
    std::vector<uint8_t> ret;
    ret.reserve(hrp.size() * 2 + 1);
    for (char c : hrp) ret.push_back(static_cast<uint8_t>(c) >> 5);
    ret.push_back(0);
    for (char c : hrp) ret.push_back(static_cast<uint8_t>(c) & 0x1f);
    return ret;
}

inline std::vector<uint8_t> create_checksum(const std::string&                hrp,
                                             const std::vector<uint8_t>& data)
{
    auto values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.resize(values.size() + 6);          // 6 zero bytes for checksum
    uint32_t mod = polymod(values) ^ 1;
    std::vector<uint8_t> ret(6);
    for (int i = 0; i < 6; ++i)
        ret[i] = static_cast<uint8_t>((mod >> (5 * (5 - i))) & 31);
    return ret;
}

// Convert a byte array from `frombits`-wide values to `tobits`-wide values.
// Used to pack 8-bit bytes into 5-bit groups for bech32 encoding.
inline bool convertbits(const std::vector<uint8_t>& in,
                        int frombits, int tobits, bool pad,
                        std::vector<uint8_t>& out)
{
    int acc = 0, bits = 0;
    const int maxv = (1 << tobits) - 1;
    for (uint8_t v : in) {
        if (v >> frombits) return false;
        acc = (acc << frombits) | v;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            out.push_back(static_cast<uint8_t>((acc >> bits) & maxv));
        }
    }
    if (pad) {
        if (bits) out.push_back(static_cast<uint8_t>((acc << (tobits - bits)) & maxv));
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return false;
    }
    return true;
}

} // namespace detail

/// Encode a segwit native address.
/// @param hrp    Human-readable part (e.g. "ltc1", "bc1", "tb1", "tltc1")
/// @param witver Witness version (0 for P2WPKH / P2WSH)
/// @param prog   Witness program bytes (20 bytes for P2WPKH, 32 for P2WSH)
/// @returns      Bech32-encoded address, or empty string on error.
inline std::string encode_segwit(const std::string&          hrp,
                                  int                         witver,
                                  const std::vector<uint8_t>& prog)
{
    // Prepend witness version as a 5-bit value
    std::vector<uint8_t> data;
    data.reserve(1 + (prog.size() * 8 + 4) / 5);
    data.push_back(static_cast<uint8_t>(witver));
    if (!detail::convertbits(prog, 8, 5, /*pad=*/true, data))
        return {};

    auto checksum = detail::create_checksum(hrp, data);
    data.insert(data.end(), checksum.begin(), checksum.end());

    std::string result = hrp + '1';
    result.reserve(result.size() + data.size());
    for (uint8_t d : data) result += detail::CHARSET[d];
    return result;
}

/// Decode a segwit native address.
/// @param hrp    Expected human-readable part (e.g. "ltc", "tltc", "bc", "tb")
/// @param addr   Bech32-encoded address
/// @param witver [out] Witness version (0 for P2WPKH / P2WSH)
/// @param prog   [out] Witness program bytes
/// @returns      true on success
inline bool decode_segwit(const std::string& hrp,
                          const std::string& addr,
                          int& witver,
                          std::vector<uint8_t>& prog)
{
    // Lowercase the address for decoding
    std::string lower;
    lower.reserve(addr.size());
    for (char c : addr) {
        if (c >= 'A' && c <= 'Z')
            lower += static_cast<char>(c - 'A' + 'a');
        else
            lower += c;
    }

    // Find the separator '1' (last occurrence)
    auto sep = lower.rfind('1');
    if (sep == std::string::npos || sep < 1 || sep + 7 > lower.size())
        return false;

    std::string got_hrp = lower.substr(0, sep);
    if (got_hrp != hrp) return false;

    // Decode data characters to 5-bit values
    std::vector<uint8_t> data;
    data.reserve(lower.size() - sep - 1);
    for (size_t i = sep + 1; i < lower.size(); ++i) {
        const char* p = std::strchr(detail::CHARSET, lower[i]);
        if (!p) return false;
        data.push_back(static_cast<uint8_t>(p - detail::CHARSET));
    }

    // Verify checksum: bech32 (polymod == 1) or bech32m (polymod == 0x2bc830a3)
    // BIP-350: witness v0 uses bech32, witness v1+ uses bech32m
    auto values = detail::hrp_expand(got_hrp);
    values.insert(values.end(), data.begin(), data.end());
    uint32_t pm = detail::polymod(values);
    if (pm != 1 && pm != 0x2bc830a3) return false;

    // Strip 6-byte checksum
    if (data.size() < 7) return false;  // witness version + at least 1 data char + 6 checksum
    data.resize(data.size() - 6);

    // First 5-bit value is witness version
    witver = data[0];
    if (witver > 16) return false;

    // Convert remaining 5-bit values to 8-bit witness program
    std::vector<uint8_t> dp(data.begin() + 1, data.end());
    prog.clear();
    if (!detail::convertbits(dp, 5, 8, /*pad=*/false, prog))
        return false;

    // BIP-141: witness program must be 2-40 bytes
    if (prog.size() < 2 || prog.size() > 40) return false;
    // For v0: must be exactly 20 (P2WPKH) or 32 (P2WSH)
    if (witver == 0 && prog.size() != 20 && prog.size() != 32) return false;

    return true;
}

} // namespace bech32
