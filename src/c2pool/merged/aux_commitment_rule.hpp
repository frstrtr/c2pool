// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The V36 share check of a merged-mining commitment over several chains.
///
/// A share's parent coinbase commits (fabe6d6d | root | size | nonce) to the
/// AuxPoW chain merkle tree, and its merged_coinbase_info carries the header
/// of each merged block it claims. With one chain and size 1 the root is that
/// block's hash (checked per chain by the caller, as before). Otherwise:
///
///   - each chain is listed once;
///   - the size is p2pool's make_auxpow_tree over the carried chain ids: the
///     smallest power of two (2^0 .. 2^30), not below their number, at which
///     their slots (1103515245 * id + 1103515245 * 12345 + 12345) % size —
///     CAuxPow::getExpectedIndex with nonce 0 — are distinct; a tree above
///     kMaxCheckedAuxTree slots is refused (no producer builds one);
///   - every carried header is 80 bytes;
///   - the root is the merkle root (double SHA-256 of each pair) over the
///     carried blocks' hashes at their slots, empty slots zero.
///
/// The same rule is p2pool data.py check_merged_aux_commitment; a share one
/// side accepts the other accepts (cross-implementation KATs:
/// merged_aux_hardening_test.cpp, p2pool test_v36_merged_multi_aux_tree.py).

#include <core/hash.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <map>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace c2pool {
namespace merged {

inline constexpr uint32_t kMaxCheckedAuxTree = 4096;

/// p2pool make_auxpow_tree: the tree size (0 when none up to 2^30) and the
/// slot of each chain id.
inline uint32_t p2pool_aux_tree(const std::vector<uint32_t>& ids, std::map<uint32_t, uint32_t>* slots = nullptr)
{
    const std::set<uint32_t> distinct(ids.begin(), ids.end());
    for (unsigned i = 0; i <= 30; ++i) {
        const uint64_t size = uint64_t(1) << i;
        if (size < distinct.size())
            continue;
        std::map<uint32_t, uint32_t> s;
        std::set<uint64_t> used;
        bool ok = true;
        for (uint32_t id : distinct) {
            const uint64_t pos = (1103515245ull * id + 1103515245ull * 12345ull + 12345ull) % size;
            ok = ok && used.insert(pos).second;
            s[id] = static_cast<uint32_t>(pos);
        }
        if (ok) {
            if (slots)
                *slots = std::move(s);
            return static_cast<uint32_t>(size);
        }
    }
    return 0;
}

/// "" when the commitment (aux_root, aux_size) is the tree over the carried
/// blocks (chain id, header bytes), as above; else why not. One chain at
/// size 1 is left to the caller's per-chain check ("").
inline std::string check_merged_aux_commitment(
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& carried,
    const uint256& aux_root, uint32_t aux_size)
{
    std::vector<uint32_t> ids;
    std::set<uint32_t> seen;
    for (const auto& [id, header] : carried) {
        if (!seen.insert(id).second)
            return "merged_coinbase_info lists chain " + std::to_string(id) + " twice";
        ids.push_back(id);
    }
    if (ids.size() <= 1 && aux_size == 1)
        return {};
    std::map<uint32_t, uint32_t> slots;
    const uint32_t size = p2pool_aux_tree(ids, &slots);
    std::string list;
    for (uint32_t id : seen)
        list += (list.empty() ? "" : ",") + std::to_string(id);
    if (size == 0 || size > kMaxCheckedAuxTree)
        return "merged aux tree for chains [" + list + "] is larger than " + std::to_string(kMaxCheckedAuxTree);
    if (aux_size != size)
        return "merged aux tree size mismatch: expected " + std::to_string(size) + " for chains [" + list
               + "], got " + std::to_string(aux_size);
    std::vector<uint256> layer(size);
    for (const auto& [id, header] : carried) {
        if (header.size() != 80)
            return "merged block header for chain " + std::to_string(id) + " is not 80 bytes";
        layer[slots.at(id)] = Hash(std::span<const unsigned char>(header.data(), header.size()));
    }
    while (layer.size() > 1) {
        std::vector<uint256> next(layer.size() / 2);
        for (size_t k = 0; k < next.size(); ++k)
            next[k] = Hash(layer[2 * k], layer[2 * k + 1]);
        layer = std::move(next);
    }
    if (layer[0] != aux_root)
        return "merged aux root " + aux_root.GetHex() + " is not the tree over the carried blocks of chains ["
               + list + "]";
    return {};
}

} // namespace merged
} // namespace c2pool
