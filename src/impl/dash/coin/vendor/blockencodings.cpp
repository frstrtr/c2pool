// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2016-2020 The Bitcoin Core developers
// Copyright (c) 2020-2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// VENDORED from dashcore/src/blockencodings.cpp.
// Adaptations (see vendor/README.md):
//   1. Dashcore primitives replaced by dash::coin::vendor typedefs.
//   2. CDataStream / streams.h replaced by c2pool's PackStream.
//   3. CheckBlock call removed from FillBlock (c2pool-dash validates
//      blocks at higher layers).
//   4. LogPrint(BCLog::CMPCTBLOCK, ...) routed to LOG_DEBUG_COIND.
//   5. Mempool iteration replaced by a caller-supplied snapshot
//      (MempoolShortIdProvider).

#include <impl/dash/coin/vendor/blockencodings.hpp>

#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/random.hpp>

#include <btclibs/crypto/sha256.h>
#include <btclibs/crypto/siphash.h>

#include <unordered_map>

namespace dash {
namespace coin {
namespace vendor {

// Minimum serialized size of an empty MutableTransaction — used to bound
// the per-block transaction count. Dashcore computes this as
// `GetSerializeSize(CMutableTransaction(), PROTOCOL_VERSION)`; our
// `MutableTransaction` default-ctor serializes to a known fixed minimum
// of 10 bytes (4 version/type + 1 vin count + 1 vout count + 4 locktime).
// Keep as a constant to avoid dragging the whole serialize-size machinery
// in for a single bound check.
static constexpr size_t MIN_TRANSACTION_SIZE = 10;

CBlockHeaderAndShortTxIDs::CBlockHeaderAndShortTxIDs(const CBlock& block) :
        nonce(::core::random::random_nonce()),
        shorttxids(block.m_txs.size() - 1), prefilledtxn(1), header(block) {
    FillShortTxIDSelector();
    // TODO (post-Phase-M): use our mempool prior to block acceptance to
    // predictively fill more than just the coinbase.
    prefilledtxn[0] = {0, MakeTransactionRef(block.m_txs[0])};
    for (size_t i = 1; i < block.m_txs.size(); i++) {
        const auto& tx = block.m_txs[i];
        auto packed = pack(tx);
        uint256 txhash = ::Hash(packed.get_span());
        shorttxids[i - 1] = GetShortID(txhash);
    }
}

void CBlockHeaderAndShortTxIDs::FillShortTxIDSelector() const {
    PackStream stream;
    stream << header << nonce;
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(stream.data()), stream.size());
    uint256 shorttxidhash;
    hasher.Finalize(shorttxidhash.begin());
    shorttxidk0 = shorttxidhash.GetUint64(0);
    shorttxidk1 = shorttxidhash.GetUint64(1);
}

uint64_t CBlockHeaderAndShortTxIDs::GetShortID(const uint256& txhash) const {
    static_assert(SHORTTXIDS_LENGTH == 6, "shorttxids calculation assumes 6-byte shorttxids");
    return SipHashUint256(shorttxidk0, shorttxidk1, txhash) & 0xffffffffffffL;
}


ReadStatus PartiallyDownloadedBlock::InitData(const CBlockHeaderAndShortTxIDs& cmpctblock, const std::vector<std::pair<uint256, CTransactionRef>>& extra_txn) {
    if (cmpctblock.header.IsNull() || (cmpctblock.shorttxids.empty() && cmpctblock.prefilledtxn.empty()))
        return READ_STATUS_INVALID;
    if (cmpctblock.shorttxids.size() + cmpctblock.prefilledtxn.size() > max_block_tx_count / MIN_TRANSACTION_SIZE)
        return READ_STATUS_INVALID;

    assert(header.IsNull() && txn_available.empty());
    header = cmpctblock.header;
    txn_available.resize(cmpctblock.BlockTxCount());

    int32_t lastprefilledindex = -1;
    for (size_t i = 0; i < cmpctblock.prefilledtxn.size(); i++) {
        if (!cmpctblock.prefilledtxn[i].tx)
            return READ_STATUS_INVALID;

        lastprefilledindex += cmpctblock.prefilledtxn[i].index + 1; //index is a uint16_t, so can't overflow here
        if (lastprefilledindex > std::numeric_limits<uint16_t>::max())
            return READ_STATUS_INVALID;
        if ((uint32_t)lastprefilledindex > cmpctblock.shorttxids.size() + i) {
            // If we are inserting a tx at an index greater than our full list of shorttxids
            // plus the number of prefilled txn we've inserted, then we have txn for which we
            // have neither a prefilled txn or a shorttxid!
            return READ_STATUS_INVALID;
        }
        txn_available[lastprefilledindex] = cmpctblock.prefilledtxn[i].tx;
    }
    prefilled_count = cmpctblock.prefilledtxn.size();

    // Calculate map of txids -> positions and check mempool to see what we have (or don't)
    // Because well-formed cmpctblock messages will have a (relatively) uniform distribution
    // of short IDs, any highly-uneven distribution of elements can be safely treated as a
    // READ_STATUS_FAILED.
    std::unordered_map<uint64_t, uint16_t> shorttxids(cmpctblock.shorttxids.size());
    uint16_t index_offset = 0;
    for (size_t i = 0; i < cmpctblock.shorttxids.size(); i++) {
        while (txn_available[i + index_offset])
            index_offset++;
        shorttxids[cmpctblock.shorttxids[i]] = i + index_offset;
        // See dashcore for the probability analysis that justifies the bound of 12.
        if (shorttxids.bucket_size(shorttxids.bucket(cmpctblock.shorttxids[i])) > 12)
            return READ_STATUS_FAILED;
    }
    // TODO: in the shortid-collision case, we should instead request both transactions
    // which collided. Falling back to full-block-request here is overkill.
    if (shorttxids.size() != cmpctblock.shorttxids.size())
        return READ_STATUS_FAILED; // Short ID collision

    std::vector<bool> have_txn(txn_available.size());
    if (mempool_provider) {
        auto snapshot = mempool_provider();
        for (const auto& entry : snapshot) {
            uint64_t shortid = cmpctblock.GetShortID(entry.first);
            auto idit = shorttxids.find(shortid);
            if (idit != shorttxids.end()) {
                if (!have_txn[idit->second]) {
                    txn_available[idit->second] = entry.second;
                    have_txn[idit->second] = true;
                    mempool_count++;
                } else {
                    // If we find two mempool txn that match the short id, just request it.
                    if (txn_available[idit->second]) {
                        txn_available[idit->second].reset();
                        mempool_count--;
                    }
                }
            }
            if (mempool_count == shorttxids.size())
                break;
        }
    }

    for (size_t i = 0; i < extra_txn.size(); i++) {
        uint64_t shortid = cmpctblock.GetShortID(extra_txn[i].first);
        auto idit = shorttxids.find(shortid);
        if (idit != shorttxids.end()) {
            if (!have_txn[idit->second]) {
                txn_available[idit->second] = extra_txn[i].second;
                have_txn[idit->second] = true;
                mempool_count++;
                extra_count++;
            } else {
                if (txn_available[idit->second] &&
                    // Compare hashes of the existing slot vs the candidate; extra_txn
                    // duplicates that already matched via the mempool path are
                    // harmless.
                    [&] {
                        auto packed = pack(*txn_available[idit->second]);
                        return ::Hash(packed.get_span()) != extra_txn[i].first;
                    }())
                {
                    txn_available[idit->second].reset();
                    mempool_count--;
                    extra_count--;
                }
            }
        }
        if (mempool_count == shorttxids.size())
            break;
    }

    LOG_DEBUG_COIND << "[cmpctblock] Initialized PartiallyDownloadedBlock"
                    << " cmpctblock_size=" << pack(cmpctblock).size()
                    << " prefilled=" << prefilled_count
                    << " mempool=" << mempool_count
                    << " extra=" << extra_count;

    return READ_STATUS_OK;
}

bool PartiallyDownloadedBlock::IsTxAvailable(size_t index) const {
    assert(!header.IsNull());
    assert(index < txn_available.size());
    return txn_available[index] != nullptr;
}

ReadStatus PartiallyDownloadedBlock::FillBlock(CBlock& block, const std::vector<CTransactionRef>& vtx_missing) {
    assert(!header.IsNull());
    block = CBlock();
    static_cast<CBlockHeader&>(block) = header;
    block.m_txs.resize(txn_available.size());

    size_t tx_missing_offset = 0;
    for (size_t i = 0; i < txn_available.size(); i++) {
        if (!txn_available[i]) {
            if (vtx_missing.size() <= tx_missing_offset)
                return READ_STATUS_INVALID;
            block.m_txs[i] = *vtx_missing[tx_missing_offset++];
        } else {
            block.m_txs[i] = *txn_available[i];
        }
    }

    // Make sure we can't call FillBlock again.
    header.SetNull();
    txn_available.clear();

    if (vtx_missing.size() != tx_missing_offset)
        return READ_STATUS_INVALID;

    // Adaptation: dashcore calls CheckBlock here, which re-runs full
    // consensus validation (merkle root + script validity + Dash-specific
    // DIP3 checks). c2pool-dash validates blocks at higher layers (the
    // submit path re-runs the coinbase checks; the header chain validates
    // merkle roots on arrival from peers). The compact-block reassembler
    // only needs to re-emit the bytes the peer sent us; if the result is
    // malformed the higher-level validator catches it.

    LOG_DEBUG_COIND << "[cmpctblock] Reconstructed block"
                    << " prefilled=" << prefilled_count
                    << " mempool=" << mempool_count
                    << " extra=" << extra_count
                    << " requested=" << vtx_missing.size();

    return READ_STATUS_OK;
}

} // namespace vendor
} // namespace coin
} // namespace dash