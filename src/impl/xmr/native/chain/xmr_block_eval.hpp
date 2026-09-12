// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/chain/xmr_block_eval.hpp
//
// From a WIRE BlockEntry to a BlockConnectInput: parse the block, authenticate
// every transaction body against the id the block commits to, weigh them, and
// total the fees.
//
// This is the seam where an unauthenticated peer's bytes become numbers the
// consensus state is allowed to believe, so the order of operations is the
// point:
//
//   1. parse the block blob (bounds-checked, no re-serialization);
//   2. compute the block's identity -- the tree root binds the tx_hashes into
//      the blob the PoW signs, so from here on the ID LIST IS AUTHENTIC;
//   3. for every body the peer sent, recompute its transaction id and require
//      it to equal the id at the same position. A pruned body proves its id
//      through the prunable hash the wire carries; a full body proves it from
//      its own bytes. Either way, a peer that swaps a transaction is caught
//      HERE, before its weight touches a median;
//   4. only then sum the weights and the fees.
//
// Step 3 is what makes pruned sync (D-4) safe, and it is the check whose
// absence would be invisible: a wrong body still parses, still has a weight,
// and would quietly move the median that sets everyone's reward.
//
// FLUFFY BLOCKS. A block announced without bodies is not an error: the entry
// comes back with `bodies_complete = false` and the index completes it from the
// txpool or asks the peer. It is only a REFUSAL at connect time, never a peer
// fault.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "impl/xmr/native/chain/xmr_consensus_state.hpp"
#include "impl/xmr/native/consensus/xmr_block_id.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/consensus/xmr_tx_weight.hpp"
#include "impl/xmr/native/consensus/xmr_weight.hpp"
#include "impl/xmr/native/contracts/types.hpp"

namespace c2pool::xmr::native {

enum class EvalStatus : std::uint8_t {
    Ok = 0,
    BadBlockBlob,     // the block did not parse
    TxCountMismatch,  // bodies supplied, but not one per tx_hash
    BadTxBlob,        // a body did not parse
    TxIdMismatch,     // a body does not hash to the id the block commits to
    BadCoinbase,      // the coinbase fields did not read back
    WeightOverflow,   // the weight sum does not fit
};

inline const char* to_string(EvalStatus s) noexcept {
    switch (s) {
        case EvalStatus::Ok:              return "Ok";
        case EvalStatus::BadBlockBlob:    return "BadBlockBlob";
        case EvalStatus::TxCountMismatch: return "TxCountMismatch";
        case EvalStatus::BadTxBlob:       return "BadTxBlob";
        case EvalStatus::TxIdMismatch:    return "TxIdMismatch";
        case EvalStatus::BadCoinbase:     return "BadCoinbase";
        case EvalStatus::WeightOverflow:  return "WeightOverflow";
    }
    return "?";
}

// Every one of these is the sender's fault: the bytes are self-inconsistent.
inline constexpr bool eval_status_is_peer_fault(EvalStatus s) noexcept {
    return s != EvalStatus::Ok;
}

// The per-transaction results, kept because the txpool (C3) and the tx-event
// stream need the ids and the key images and should not re-parse.
struct EvaluatedTx {
    Hash          id{};
    TxWeightInfo  info{};
};

struct EvaluatedBlock {
    BlockConnectInput        input{};
    std::vector<EvaluatedTx> txs;
    std::vector<Hash>        key_images;   // every input of every body, for D-12
};

inline EvalStatus evaluate_block(const BlockEntry& entry, EvaluatedBlock& out,
                                 std::string& why) {
    out = EvaluatedBlock{};
    why.clear();

    const BlockParseStatus bs = parse_block(entry.block_blob, out.input.parsed);
    if (bs != BlockParseStatus::Ok) {
        why = std::string("block blob does not parse: ") + to_string(bs);
        return EvalStatus::BadBlockBlob;
    }
    out.input.identity = block_identity(entry.block_blob.data(), out.input.parsed);

    if (!parse_coinbase_fields(entry.block_blob.data(), out.input.parsed, out.input.coinbase)) {
        why = "coinbase fields do not read back";
        return EvalStatus::BadCoinbase;
    }

    const std::size_t n = out.input.parsed.tx_hashes.size();
    if (entry.txs.empty() && n != 0) {
        // Announced without bodies (fluffy, or a pruned peer that had none).
        // Not a fault; the index completes the block and evaluates again.
        out.input.bodies_complete = false;
        return EvalStatus::Ok;
    }
    if (entry.txs.size() != n) {
        why = "block carries " + std::to_string(n) + " transaction ids but "
            + std::to_string(entry.txs.size()) + " bodies";
        return EvalStatus::TxCountMismatch;
    }

    std::uint64_t weight_sum = out.input.parsed.miner_tx.blob_size;
    std::uint64_t fee_sum    = 0;
    out.txs.reserve(n);

    for (std::size_t i = 0; i < n; ++i) {
        const TxBlobEntry& te = entry.txs[i];
        EvaluatedTx et;

        const TxParseStatus ps = te.pruned
            ? parse_tx_pruned(te.blob, et.info)
            : parse_tx_full(te.blob, et.info);
        if (ps != TxParseStatus::Ok) {
            why = "transaction " + std::to_string(i) + " does not parse: " + to_string(ps);
            return EvalStatus::BadTxBlob;
        }

        et.id = te.pruned
            ? tx_hash_from_parts(te.blob.data(), te.blob.size(), et.info, te.prunable_hash)
            : tx_hash_full(te.blob.data(), te.blob.size(), et.info);

        if (!(et.id == out.input.parsed.tx_hashes[i])) {
            why = "transaction " + std::to_string(i)
                + " does not hash to the id the block commits to";
            return EvalStatus::TxIdMismatch;
        }

        if (weight_sum > UINT64_MAX - et.info.weight) {
            why = "block weight sum overflows";
            return EvalStatus::WeightOverflow;
        }
        weight_sum += et.info.weight;
        if (fee_sum > UINT64_MAX - et.info.fee) {
            why = "block fee sum overflows";
            return EvalStatus::WeightOverflow;
        }
        fee_sum += et.info.fee;

        for (const KeyImage& ki : et.info.key_images) out.key_images.push_back(ki);
        out.txs.push_back(std::move(et));
    }

    out.input.block_weight    = weight_sum;
    out.input.fees            = fee_sum;
    out.input.bodies_complete = true;
    return EvalStatus::Ok;
}

} // namespace c2pool::xmr::native
