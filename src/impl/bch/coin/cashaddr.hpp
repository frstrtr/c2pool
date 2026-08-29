// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// bch::coin::cashaddr -- BCH CashAddr address codec (M4 TODO from config_coin.hpp).
//
// Faithful header-only port of Bitcoin Cash Node's src/cashaddr.cpp +
// src/cashaddrenc.cpp (Pieter Wuille / The Bitcoin developers, MIT). BCH
// addresses diverge from BTC base58/bech32: a base32 charset with a BCH-code
// 40-bit PolyMod checksum and a "bitcoincash:" / "bchtest:" / "bchreg:" prefix.
//
// Self-contained vs the BCHN original: the BCHN code threads CTxDestination /
// CChainParams / pubkey / script types through Encode/DecodeCashAddr. None of
// that graph is needed at the codec layer -- the codec maps {type, hash-bytes}
// <-> string. This header exposes exactly that seam (CashAddrContent) so it is
// build-inert and unit-testable out of tree with the BCHN KAT vectors, with no
// boost / chainparams dependency. Callers (config/payout-address layer) map a
// CashAddrType + 20/32-byte hash to/from CTxDestination themselves.
//
// >>> BCH DIVERGENCES carried here (M1 4.x) <<<
//   - CashTokens token-aware address types (CHIP-2022-02, May 2023): the 'z'/'r'
//     token-aware variants (TOKEN_PUBKEY_TYPE / TOKEN_SCRIPT_TYPE) are BCH
//     consensus and are encoded faithfully -- transparent to the template layer,
//     they only widen the operator-facing address surface.
//   - P2SH32 (CHIP, May 2023): 32-byte hashes are accepted via the version
//     size bits (hash_size doubling), alongside the legacy 20-byte P2PKH/P2SH.
//
// p2pool-merged-v36 SURFACE: NONE. CashAddr is the operator-facing config /
// payout-address encoding; the share, sharechain, coinbase-commitment and PPLNS
// layers serialize SCRIPTS, not address strings (those paths are already pinned
// conformant). This adds an input/display codec only -- no share-format change.
// PER-COIN ISOLATION: src/impl/bch/coin/ only; every symbol is bch-owned.
// Build-INERT / source-only: header-only, no impl_bch CMake registration
// (bch stays skip-green; don't race ci-steward).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <core/address_utils.hpp>   // register_address_decoder (payout hook)

namespace bch {
namespace coin {
namespace cashaddr {

// Address types -- 1:1 with BCHN cashaddrenc.h CashAddrType.
enum CashAddrType : uint8_t {
    PUBKEY_TYPE       = 0,
    SCRIPT_TYPE       = 1,
    TOKEN_PUBKEY_TYPE = 2, //< Token-Aware P2PKH (CashTokens)
    TOKEN_SCRIPT_TYPE = 3, //< Token-Aware P2SH  (CashTokens)
};

struct CashAddrContent {
    CashAddrType type{};
    std::vector<uint8_t> hash;

    bool IsNull() const { return hash.empty(); }
    bool IsTokenAwareType() const {
        return type == TOKEN_PUBKEY_TYPE || type == TOKEN_SCRIPT_TYPE;
    }
};

// Network prefixes (BCHN chainparams.cpp cashaddrPrefix).
inline constexpr const char* MAINNET_PREFIX = "bitcoincash";
inline constexpr const char* TESTNET_PREFIX = "bchtest";
inline constexpr const char* REGTEST_PREFIX = "bchreg";
inline std::string prefix_for(bool testnet) {
    return testnet ? TESTNET_PREFIX : MAINNET_PREFIX;
}

namespace detail {

using data = std::vector<uint8_t>;

// The cashaddr base32 charset for encoding.
inline constexpr char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
inline constexpr uint8_t PACKED_VAL_LIMIT = 32u;

// Reverse charset for decoding (index by ASCII; -1 = invalid).
inline constexpr int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, 10, 17, 21, 20, 26, 30, 7,
    5,  -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22,
    31, 27, 19, -1, 1,  0,  3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1,
    -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22, 31, 27, 19, -1, 1,  0,
    3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1, -1};

inline data Cat(data a, const data& b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

// BCH 40-bit BCH-code PolyMod (cashaddr.cpp). Returns the value to XOR into the
// 8 trailing 5-bit groups to make the checksum 1.
inline uint64_t PolyMod(const data& v) {
    uint64_t c = 1;
    for (uint8_t d : v) {
        uint8_t c0 = c >> 35;
        c = ((c & 0x07ffffffff) << 5) ^ d;
        if (c0 & 0x01) c ^= 0x98f2bc8e61;
        if (c0 & 0x02) c ^= 0x79b76d99e2;
        if (c0 & 0x04) c ^= 0xf33e5fb3c4;
        if (c0 & 0x08) c ^= 0xae2eabe2a8;
        if (c0 & 0x10) c ^= 0x1e4f43e470;
    }
    return c ^ 1;
}

inline uint8_t LowerCase(uint8_t c) { return c | 0x20; }

inline data ExpandPrefix(const std::string& prefix) {
    data ret;
    ret.resize(prefix.size() + 1);
    for (size_t i = 0; i < prefix.size(); ++i) ret[i] = uint8_t(prefix[i]) & 0x1f;
    ret[prefix.size()] = 0;
    return ret;
}

inline bool VerifyChecksum(const std::string& prefix, const data& payload) {
    return PolyMod(Cat(ExpandPrefix(prefix), payload)) == 0;
}

inline data CreateChecksum(const std::string& prefix, const data& payload) {
    data enc = Cat(ExpandPrefix(prefix), payload);
    enc.resize(enc.size() + 8);
    uint64_t mod = PolyMod(enc);
    data ret(8);
    for (size_t i = 0; i < 8; ++i) ret[i] = (mod >> (5 * (7 - i))) & 0x1f;
    return ret;
}

// Standard Bitcoin ConvertBits (util/strencodings.h). frombits->tobits with
// optional padding; returns false on invalid padding when pad=false.
template <int frombits, int tobits, bool pad, typename O>
inline bool ConvertBits(const O& outfn, data::const_iterator it,
                        data::const_iterator end) {
    size_t acc = 0;
    int bits = 0;
    constexpr size_t maxv = (1 << tobits) - 1;
    constexpr size_t max_acc = (1 << (frombits + tobits - 1)) - 1;
    while (it != end) {
        acc = ((acc << frombits) | *it) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            outfn((acc >> bits) & maxv);
        }
        ++it;
    }
    if (pad) {
        if (bits) outfn((acc << (tobits - bits)) & maxv);
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return false;
    }
    return true;
}

// Pack {type, hash} into 5-bit payload with version byte (cashaddrenc.cpp).
inline data PackAddrData(const data& id, uint8_t type) {
    uint8_t version_byte(type << 3);
    size_t size = id.size();
    uint8_t encoded_size = 0;
    switch (size * 8) {
        case 160: encoded_size = 0; break;
        case 192: encoded_size = 1; break;
        case 224: encoded_size = 2; break;
        case 256: encoded_size = 3; break;
        case 320: encoded_size = 4; break;
        case 384: encoded_size = 5; break;
        case 448: encoded_size = 6; break;
        case 512: encoded_size = 7; break;
        default:
            // Invalid hash length -> empty payload (caller treats as failure).
            return {};
    }
    version_byte |= encoded_size;
    data buf = {version_byte};
    buf.insert(buf.end(), id.begin(), id.end());

    data converted;
    converted.reserve(((size + 1) * 8 + 4) / 5);
    ConvertBits<8, 5, true>([&](uint8_t c) { converted.push_back(c); },
                            buf.begin(), buf.end());
    return converted;
}

} // namespace detail

// Encode a cashaddr string from a 5-bit payload (cashaddr.cpp Encode).
inline std::string Encode(const std::string& prefix, const detail::data& payload) {
    detail::data checksum = detail::CreateChecksum(prefix, payload);
    detail::data combined = detail::Cat(payload, checksum);
    std::string ret = prefix + ':';
    ret.reserve(ret.size() + combined.size());
    for (const uint8_t c : combined) ret += detail::CHARSET[c % detail::PACKED_VAL_LIMIT];
    return ret;
}

// Decode a cashaddr string to {prefix, 5-bit payload} (cashaddr.cpp Decode).
// Returns {"", {}} on any structural / checksum failure.
inline std::pair<std::string, detail::data> Decode(const std::string& str,
                                                   const std::string& default_prefix) {
    bool lower = false, upper = false, hasNumber = false;
    size_t prefixSize = 0;
    for (size_t i = 0; i < str.size(); ++i) {
        uint8_t c = str[i];
        if (c >= 'a' && c <= 'z') { lower = true; continue; }
        if (c >= 'A' && c <= 'Z') { upper = true; continue; }
        if (c >= '0' && c <= '9') { hasNumber = true; continue; }
        if (c == ':') {
            if (hasNumber || i == 0 || prefixSize != 0) return {};
            prefixSize = i;
            continue;
        }
        return {};
    }
    if (upper && lower) return {};

    std::string prefix;
    if (prefixSize == 0) {
        prefix = default_prefix;
    } else {
        prefix.reserve(prefixSize);
        for (size_t i = 0; i < prefixSize; ++i) prefix += char(detail::LowerCase(str[i]));
        prefixSize++;
    }

    const size_t valuesSize = str.size() - prefixSize;
    detail::data values(valuesSize);
    for (size_t i = 0; i < valuesSize; ++i) {
        uint8_t c = str[i + prefixSize];
        if (c > 127 || detail::CHARSET_REV[c] == -1) return {};
        values[i] = detail::CHARSET_REV[c];
    }
    if (!detail::VerifyChecksum(prefix, values)) return {};
    return {std::move(prefix), detail::data(values.begin(), values.end() - 8)};
}

// {type, hash} -> address string (cashaddrenc.cpp EncodeCashAddr).
inline std::string EncodeCashAddr(const std::string& prefix, const CashAddrContent& content) {
    detail::data payload = detail::PackAddrData(content.hash, content.type);
    if (payload.empty()) return {};
    return Encode(prefix, payload);
}

// address string -> {type, hash} (cashaddrenc.cpp DecodeCashAddrContent).
// Returns a null CashAddrContent on prefix mismatch / bad version / bad size.
inline CashAddrContent DecodeCashAddrContent(const std::string& addr,
                                             const std::string& expectedPrefix) {
    auto [prefix, payload] = Decode(addr, expectedPrefix);
    if (prefix != expectedPrefix) return {};
    if (payload.empty()) return {};

    detail::data out;
    out.reserve(payload.size() * 5 / 8);
    if (!detail::ConvertBits<5, 8, false>([&](uint8_t c) { out.push_back(c); },
                                          payload.begin(), payload.end())) {
        return {};
    }

    uint8_t version = out[0];
    if (version & 0x80) return {}; // reserved bit
    auto type = CashAddrType((version >> 3) & 0x1f);
    uint32_t hash_size = 20 + 4 * (version & 0x03);
    if (version & 0x04) hash_size *= 2;
    if (out.size() != hash_size + 1) return {};

    out.erase(out.begin()); // pop version
    return {type, std::move(out)};
}

// -- {type,hash} -> BCH scriptPubKey (locking script) -------------------------
// P2PKH (20B): OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
// P2SH  (20B): OP_HASH160 <20> OP_EQUAL
// P2SH32(32B): OP_HASH256 <32> OP_EQUAL   (CHIP-2022-02, May 2023)
// Token-aware variants lock identically -- token-awareness is a wallet display
// capability, not a script-level distinction. Returns {} on unsupported size.
inline std::vector<unsigned char> content_to_script(const CashAddrContent& c) {
    const auto& h = c.hash;
    std::vector<unsigned char> s;
    switch (c.type) {
        case PUBKEY_TYPE:
        case TOKEN_PUBKEY_TYPE:
            if (h.size() != 20) return {};
            s = {0x76, 0xa9, 0x14};
            s.insert(s.end(), h.begin(), h.end());
            s.push_back(0x88); s.push_back(0xac);
            return s;
        case SCRIPT_TYPE:
        case TOKEN_SCRIPT_TYPE:
            if (h.size() == 20) {            // P2SH20
                s = {0xa9, 0x14};
                s.insert(s.end(), h.begin(), h.end());
                s.push_back(0x87);
                return s;
            }
            if (h.size() == 32) {            // P2SH32 (OP_HASH256)
                s = {0xaa, 0x20};
                s.insert(s.end(), h.begin(), h.end());
                s.push_back(0x87);
                return s;
            }
            return {};
    }
    return {};
}

// Decode a CashAddr string to its scriptPubKey under a specific network prefix.
// Returns {} if the string is not a valid CashAddr for that prefix.
inline std::vector<unsigned char> cashaddr_to_script(const std::string& addr,
                                                     const std::string& prefix) {
    auto content = DecodeCashAddrContent(addr, prefix);
    if (content.IsNull()) return {};
    return content_to_script(content);
}

// Convenience: resolve under the active network prefix (mainnet/testnet/regtest).
inline std::vector<unsigned char> cashaddr_to_script_for_net(const std::string& addr,
                                                             bool testnet, bool regtest) {
    const std::string prefix = regtest ? std::string(REGTEST_PREFIX)
                                        : prefix_for(testnet);
    return cashaddr_to_script(addr, prefix);
}

// Register the BCH CashAddr decoder into the generic core address hook so
// core::address_to_script (the stratum payout path) resolves a miner CashAddr
// username to a real payout scriptPubKey. Without this the BCH payout script is
// empty -> degenerate value-0 OP_RETURN coinbase -> BCHN bad-txns/BIP30 reject.
// Idempotent (once per process). Core stays CashAddr-agnostic.
inline void register_cashaddr_decoder(bool testnet, bool regtest) {
    static std::once_flag once;
    std::call_once(once, [testnet, regtest]() {
        core::register_address_decoder(
            [testnet, regtest](const std::string& a) -> std::vector<unsigned char> {
                return cashaddr_to_script_for_net(a, testnet, regtest);
            });
    });
}

} // namespace cashaddr
} // namespace coin
} // namespace bch