// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
#include <cstdint>

// ---------------------------------------------------------------------------
// Dependency-free home of the aux-chain merkle slot (CAuxPow::getExpectedIndex).
//
// The merged-mining manager needs only this function to lay out the aux chain
// merkle tree. It must not include header_chain.hpp for it: that header pulls
// core/leveldb_store.hpp (<leveldb/db.h>), and the c2pool_merged_mining OBJECT
// library does not carry the leveldb usage requirement, so MSVC/Conan fails
// with C1083 on leveldb/db.h. header_chain.hpp includes this file, so its
// users see the same function as before.
// ---------------------------------------------------------------------------
namespace nmc {
namespace coin {

/// Deterministic chain-merkle slot for a (nonce, chain_id, height) triple.
/// Byte-faithful port of Namecoin/Bitcoin CAuxPow::getExpectedIndex: pins each
/// aux chain to a pseudo-random-but-fixed slot so the same parent work cannot be
/// replayed for two chains and inter-chain slot clashes are minimised. The
/// arithmetic is intentionally wrap-around uint32 (LCG constants 1103515245 /
/// 12345) to match the reference bit-for-bit.
inline uint32_t aux_expected_index(uint32_t nonce, int32_t chain_id, unsigned height) {
    uint32_t rnd = nonce;
    rnd = rnd * 1103515245u + 12345u;
    rnd += static_cast<uint32_t>(chain_id);
    rnd = rnd * 1103515245u + 12345u;
    return rnd % (1u << height);
}

} // namespace coin
} // namespace nmc
