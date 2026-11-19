// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// found_block_record_map.hpp -- a ledger row (core::MiningInterface::
// FoundBlock) to its stored record (FoundBlockRecord, fblk:) and back: every
// persisted field, in one place, so the LTC node's persistence callbacks and
// the KATs that pin them map the same fields. Only the INPUTS are stored;
// every derived luck field is recomputed on load.

#include <c2pool/storage/found_block_store.hpp>
#include <core/web_server.hpp>

#include <cstdint>

namespace c2pool {
namespace storage {

/// The record of a ledger row, `last_checked` = when it is written.
inline FoundBlockRecord found_block_record_of(const core::MiningInterface::FoundBlock& blk,
                                              uint64_t last_checked)
{
    FoundBlockRecord rec;
    rec.chain = blk.chain;
    rec.height = blk.height;
    rec.block_hash = blk.hash;
    rec.timestamp = blk.ts;
    rec.status = static_cast<uint8_t>(blk.status);
    rec.check_count = blk.check_count;
    rec.confirmations = blk.confirmations;
    rec.last_checked = last_checked;
    // #159: dashboard-enrichment fields, so a restored row keeps its detail.
    rec.finder_address = blk.miner;
    rec.reward_satoshis = blk.subsidy;
    rec.network_difficulty = blk.network_difficulty;
    rec.share_difficulty = blk.share_difficulty;
    rec.pool_hashrate = blk.pool_hashrate;
    rec.share_hash = blk.share_hash;
    rec.authorship = static_cast<uint8_t>(blk.authorship);
    // #946: explorer fields (fblk v3).
    rec.coinbase_txid = blk.coinbase_txid;
    rec.tx_count = blk.tx_count;
    // #946: DOGE parent (fblk v4); set_found_block_parent re-persists the
    // row, so it survives a restart.
    rec.parent_hash = blk.parent_hash;
    rec.parent_height = blk.parent_height;
    // fblk extension byte: a DOGE row's network_difficulty is the aux
    // chain's own; the row came from --import-found-blocks.
    rec.aux_difficulty_known = blk.aux_difficulty_known;
    rec.imported = blk.imported;
    // fblk extension tail: another node's measured effort of the round.
    rec.imported_effort = blk.imported_effort;
    rec.imported_coverage = blk.imported_coverage;
    rec.imported_prev_hash = blk.imported_prev_hash;
    return rec;
}

/// The ledger row of a stored record (what an older record lacks stays at
/// its default: unknown).
inline core::MiningInterface::FoundBlock found_block_of(const FoundBlockRecord& rec)
{
    using MI = core::MiningInterface;
    MI::FoundBlock blk{};
    blk.height = rec.height;
    blk.hash = rec.block_hash;
    blk.ts = rec.timestamp;
    blk.status = static_cast<MI::BlockStatus>(rec.status);
    blk.check_count = rec.check_count;
    blk.chain = rec.chain;
    blk.confirmations = rec.confirmations;
    // #159: restore enrichment (v1 records => 0).
    blk.miner = rec.finder_address;
    blk.subsidy = rec.reward_satoshis;
    blk.network_difficulty = rec.network_difficulty;
    blk.share_difficulty = rec.share_difficulty;
    blk.pool_hashrate = rec.pool_hashrate;
    blk.share_hash = rec.share_hash;
    blk.authorship = static_cast<MI::BlockAuthorship>(rec.authorship);
    // #946: v1/v2 records leave these unknown (null).
    blk.coinbase_txid = rec.coinbase_txid;
    blk.tx_count = rec.tx_count;
    // #946: v1-v3 records leave the parent unknown (null).
    blk.parent_hash = rec.parent_hash;
    blk.parent_height = rec.parent_height;
    // false on a row written before the flag: its stored difficulty is the
    // parent's.
    blk.aux_difficulty_known = rec.aux_difficulty_known;
    blk.imported = rec.imported;
    if (rec.has_imported_effort()) {
        blk.imported_effort = rec.imported_effort;
        blk.imported_coverage = rec.imported_coverage;
        blk.imported_prev_hash = rec.imported_prev_hash;
    }
    return blk;
}

} // namespace storage
} // namespace c2pool
