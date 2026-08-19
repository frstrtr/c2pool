// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dash::coin::GentxCoinbase -- the regenerated DASH coinbase (gentx) as both
// its non-witness serialization AND its txid, mirroring dgb::coin::GentxCoinbase
// (src/impl/dgb/coin/gentx_coinbase.hpp).
//
// It is the SSOT hand-off between the accept-path coinbase recompute
// (share_check.hpp generate_share_transaction, which already builds the exact
// DIP3/DIP4 CbTx bytes the share committed to) and the won-block reconstructor
// (reconstruct_won_block.hpp): generate_share_transaction fills this out-param
// with the coinbase BYTES + its txid, so the reconstructor never re-implements
// the coinbase assembly -- it reuses the one, KAT-proven, byte path.
//
// Reward/consensus-NEUTRAL: a plain data record. No PoW hash, share format,
// coinbase commitment, or PPLNS math lives here. Per-coin isolation:
// src/impl/dash/ only.
// ---------------------------------------------------------------------------

#include <vector>

#include <core/uint256.hpp>

namespace dash
{
namespace coin
{

// The regenerated coinbase transaction:
//   bytes : non-witness serialization (block tx 0)
//   txid  : SHA256d(bytes) == the gentx_hash the share's hash_link committed to
struct GentxCoinbase
{
    std::vector<unsigned char> bytes;
    uint256                    txid;
};

} // namespace coin
} // namespace dash
