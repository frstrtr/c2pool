// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2016-2020 The Bitcoin Core developers
// Copyright (c) 2020-2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// VENDORED from dashcore/src/blockencodings.h. See vendor/README.md.
//
// Adaptations from upstream:
//   1. Primitives (CBlockHeader, CBlock, CTransactionRef, CTxMemPool)
//      replaced by c2pool types via shim.hpp typedefs.
//   2. Serialization idioms (SERIALIZE_METHODS(cls, obj) +
//      VectorFormatter<F> + CustomUintFormatter<N> + DifferenceFormatter)
//      re-expressed in c2pool's pack.hpp surface:
//        btclibs idiom                    → c2pool idiom
//        SERIALIZE_METHODS(X, obj){body}  → SERIALIZE_METHODS(X) body
//        VectorFormatter<F>               → ListType<F>
//        CustomUintFormatter<6>           → ShortTxIdFormat
//        DefaultFormatter/TransactionCompression → TxCompressionFormat
//        VectorFormatter<DifferenceFormatter> over indexes → DifferenceListFormat
//        COMPACTSIZE(x)                   → VarInt(x)
//        ser_action.ForRead() { ... }     → formatter-type-discriminated
//                                            post-read hook in FORMAT_METHODS.
//      Wire format is byte-for-byte identical to dashcore.
//   3. CheckBlock() call removed from FillBlock (c2pool-dash validates
//      blocks at higher layers).

#pragma once

#include <impl/dash/coin/vendor/shim.hpp>

#include <core/uint256.hpp>

#include <limits>
#include <type_traits>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

class BlockTransactionsRequest {
public:
    // A BlockTransactionsRequest message
    uint256 blockhash;
    std::vector<uint16_t> indexes;

    C2POOL_SERIALIZE_METHODS(BlockTransactionsRequest)
    {
        READWRITE(obj.blockhash,
                  Using<DifferenceListFormat>(obj.indexes));
    }
};

class BlockTransactions {
public:
    // A BlockTransactions message
    uint256 blockhash;
    std::vector<CTransactionRef> txn;

    BlockTransactions() {}
    explicit BlockTransactions(const BlockTransactionsRequest& req) :
        blockhash(req.blockhash), txn(req.indexes.size()) {}

    C2POOL_SERIALIZE_METHODS(BlockTransactions)
    {
        READWRITE(obj.blockhash,
                  Using<ListType<TxCompressionFormat>>(obj.txn));
    }
};

// Dumb serialization/storage-helper for CBlockHeaderAndShortTxIDs and PartiallyDownloadedBlock
struct PrefilledTransaction {
    // Used as an offset since last prefilled tx in CBlockHeaderAndShortTxIDs,
    // as a proper transaction-in-block-index in PartiallyDownloadedBlock
    uint16_t index;
    CTransactionRef tx;

    C2POOL_SERIALIZE_METHODS(PrefilledTransaction)
    {
        READWRITE(VarInt(obj.index),
                  Using<TxCompressionFormat>(obj.tx));
    }
};

typedef enum ReadStatus_t
{
    READ_STATUS_OK,
    READ_STATUS_INVALID, // Invalid object, peer is sending bogus crap
    READ_STATUS_FAILED, // Failed to process object
    READ_STATUS_CHECKBLOCK_FAILED, // Used only by FillBlock to indicate a
                                   // failure in CheckBlock (c2pool-dash retains
                                   // the enum value for upstream parity even
                                   // though FillBlock never returns it today).
} ReadStatus;

class CBlockHeaderAndShortTxIDs {
private:
    mutable uint64_t shorttxidk0, shorttxidk1;
    uint64_t nonce;

    void FillShortTxIDSelector() const;

    friend class PartiallyDownloadedBlock;

protected:
    std::vector<uint64_t> shorttxids;
    std::vector<PrefilledTransaction> prefilledtxn;

public:
    static constexpr int SHORTTXIDS_LENGTH = 6;

    CBlockHeader header;

    // Dummy for deserialization
    CBlockHeaderAndShortTxIDs() {}

    explicit CBlockHeaderAndShortTxIDs(const CBlock& block);

    uint64_t GetShortID(const uint256& txhash) const;

    size_t BlockTxCount() const { return shorttxids.size() + prefilledtxn.size(); }

    C2POOL_SERIALIZE_METHODS(CBlockHeaderAndShortTxIDs)
    {
        READWRITE(obj.header,
                  obj.nonce,
                  Using<ListType<ShortTxIdFormat>>(obj.shorttxids),
                  obj.prefilledtxn);
        // Post-read integrity check (ser_action.ForRead() branch in
        // upstream): index-set must fit in a uint16, and the short-id
        // SipHash selector must be primed so GetShortID() works.
        if constexpr (std::is_same_v<Formatter, UnserializeFormatter>) {
            if (obj.BlockTxCount() > std::numeric_limits<uint16_t>::max())
                throw std::ios_base::failure("indexes overflowed 16 bits");
            obj.FillShortTxIDSelector();
        }
    }
};

class PartiallyDownloadedBlock {
protected:
    std::vector<CTransactionRef> txn_available;
    size_t prefilled_count = 0, mempool_count = 0, extra_count = 0;

    // Shim: dashcore threads a `CTxMemPool*`; c2pool-dash passes a
    // snapshot provider (see shim.hpp). Null callback = no mempool
    // (pre-Phase-M); reassembly falls straight through to getblocktxn.
    MempoolShortIdProvider mempool_provider;
    // Upper bound on transactions a block may contain. Dashcore reads
    // MaxBlockSize() from ChainParams at call-time; c2pool-dash injects
    // it at construction so blockencodings.cpp stays free of
    // chain-params deps.
    size_t max_block_tx_count;

public:
    CBlockHeader header;

    explicit PartiallyDownloadedBlock(MempoolShortIdProvider provider,
                                      size_t max_block_tx_count_in)
        : mempool_provider(std::move(provider))
        , max_block_tx_count(max_block_tx_count_in) {}

    // extra_txn is a list of extra transactions to look at, in <hash, reference> form
    ReadStatus InitData(const CBlockHeaderAndShortTxIDs& cmpctblock,
                        const std::vector<std::pair<uint256, CTransactionRef>>& extra_txn);
    bool IsTxAvailable(size_t index) const;
    ReadStatus FillBlock(CBlock& block, const std::vector<CTransactionRef>& vtx_missing);
};

} // namespace vendor
} // namespace coin
} // namespace dash