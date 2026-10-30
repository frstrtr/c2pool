#pragma once

/// UTXOViewDB 'A' record: the set was imported from a pinned snapshot
/// (assumeutxo) and has not been rebuilt from genesis by this node.
///
/// It sits beside the sync state ('S', utxo_view_db.hpp), written in the same
/// final batch as 'B' and 'S' by the snapshot import, and leaves the 'S'
/// format alone: a reader that does not know 'A' sees an ordinary tracked set
/// (anchor 0, strict). 'A' says where the set's history starts being this
/// node's own work, and what the snapshot was checked against.
///
/// Value: u8 version (1) | u32 LE base_height | 32 base_hash | 32 muhash |
///        32 hash_serialized_2 (all zero = the pin carried none) |
///        u64 LE coins | u8 validated | u8 len + coin | u8 len + network |
///        u8 len + pin digest (lowercase hex, empty = explicit expectations)
///
/// Hashes are stored in internal byte order (uint256::data()).

#include <core/uint256.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace core {
namespace coin {

struct AssumedBase {
    static constexpr uint8_t VERSION = 1;

    uint32_t    base_height{0};
    uint256     base_hash;
    uint256     muhash;
    uint256     hash_serialized_2;
    uint64_t    coins{0};
    uint8_t     validated{0};   // 1 = a background rebuild matched (not before S4)
    std::string coin;           // "dash"
    std::string network;        // "mainnet" / "testnet" / ...
    std::string pin_digest;

    static std::string key() { return std::string(1, 'A'); }

    std::vector<uint8_t> serialize() const
    {
        std::vector<uint8_t> v;
        v.push_back(VERSION);
        for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>(base_height >> (8 * i)));
        v.insert(v.end(), base_hash.data(), base_hash.data() + 32);
        v.insert(v.end(), muhash.data(), muhash.data() + 32);
        v.insert(v.end(), hash_serialized_2.data(), hash_serialized_2.data() + 32);
        for (int i = 0; i < 8; ++i) v.push_back(static_cast<uint8_t>(coins >> (8 * i)));
        v.push_back(validated);
        for (const std::string* s : {&coin, &network, &pin_digest}) {
            const size_t n = std::min<size_t>(s->size(), 255);
            v.push_back(static_cast<uint8_t>(n));
            v.insert(v.end(), s->begin(), s->begin() + static_cast<std::ptrdiff_t>(n));
        }
        return v;
    }

    /// False (this left unchanged) for another version, a short record or
    /// trailing bytes.
    bool deserialize(const std::vector<uint8_t>& v)
    {
        constexpr size_t FIXED = 1 + 4 + 32 + 32 + 32 + 8 + 1;
        if (v.size() < FIXED || v[0] != VERSION)
            return false;
        AssumedBase a;
        size_t p = 1;
        for (int i = 0; i < 4; ++i) a.base_height |= uint32_t(v[p + i]) << (8 * i);
        p += 4;
        std::memcpy(a.base_hash.data(), v.data() + p, 32);
        p += 32;
        std::memcpy(a.muhash.data(), v.data() + p, 32);
        p += 32;
        std::memcpy(a.hash_serialized_2.data(), v.data() + p, 32);
        p += 32;
        for (int i = 0; i < 8; ++i) a.coins |= uint64_t(v[p + i]) << (8 * i);
        p += 8;
        a.validated = v[p++];
        for (std::string* s : {&a.coin, &a.network, &a.pin_digest}) {
            if (p >= v.size()) return false;
            const size_t n = v[p++];
            if (n > v.size() - p) return false;
            s->assign(reinterpret_cast<const char*>(v.data() + p), n);
            p += n;
        }
        if (p != v.size())
            return false;
        *this = a;
        return true;
    }
};

} // namespace coin
} // namespace core
