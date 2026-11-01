// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// #968a: BIP 152 compact-block RECEIVE state machine (dashcore
// net_processing.cpp ProcessMessage CMPCTBLOCK / BLOCKTXN, receive half only).
//
// Pure logic, no sockets: the CoinClient handlers feed it the decoded wire
// messages and act on the returned verdict. Kept separate so the KAT drives
// every branch directly.
//
//   cmpctblock -> InitData
//       OK, every tx present (prefilled + mempool)  -> FillBlock -> Complete
//       OK, some tx missing                          -> NeedTxn (getblocktxn),
//                                                       block parked per peer
//       INVALID (bad short-id / prefilled index)     -> Reject (dashcore
//                                                       Misbehaving(100))
//       FAILED (short-id collision)                  -> FallbackFull (getdata
//                                                       MSG_BLOCK)
//   blocktxn -> FillBlock against the peer's parked block
//       no parked block / hash mismatch              -> Ignore (dashcore
//                                                       "unrequested blocktxn")
//       INVALID (too few / too many txs)             -> Reject
//       filled, body does not bind to header merkle  -> FallbackFull
//       filled + binds                               -> Complete
//
// The merkle bind is the adaptation the vendor note asks for: vendor
// FillBlock drops dashcore's CheckBlock, so a short-id collision that pulled
// in the wrong mempool tx would otherwise ride through unchecked. dashcore
// answers that case (READ_STATUS_CHECKBLOCK_FAILED) by fetching the full
// block, and so do we. block_body_binds_to_header also carries the
// CVE-2012-2459 duplicate-padding guard.
//
// One parked block per peer (dashcore keeps one in-flight compact block per
// peer per hash). A new cmpctblock from the same peer replaces the old one.
// on_disconnect drops it.

#include <impl/dash/coin/vendor/blockencodings.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/block_producer.hpp>   // block_body_binds_to_header

#include <core/uint256.hpp>

#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <utility>

namespace dash {
namespace coin {

struct CompactReceiveVerdict
{
    enum class Kind {
        Complete,      // `block` is the reassembled, merkle-bound block
        NeedTxn,       // send `request` as getblocktxn to the same peer
        FallbackFull,  // send getdata MSG_BLOCK for `blockhash`
        Reject,        // malformed by the peer (dashcore Misbehaving)
        Ignore,        // nothing to do (unrequested / stale blocktxn)
    };

    Kind kind{Kind::Ignore};
    uint256 blockhash;
    BlockType block;                           // Complete only
    vendor::BlockTransactionsRequest request;  // NeedTxn only
    const char* reason{""};
};

class CompactBlockReceiver
{
public:
    CompactBlockReceiver(vendor::MempoolShortIdProvider mempool,
                         size_t max_block_tx_count)
        : m_mempool(std::move(mempool))
        , m_max_block_tx_count(max_block_tx_count) {}

    // `blockhash` = X11(header), computed by the caller (the receiver stays
    // free of the X11 dependency).
    CompactReceiveVerdict on_cmpctblock(const std::string& peer,
                                        const vendor::CBlockHeaderAndShortTxIDs& cmpct,
                                        const uint256& blockhash)
    {
        CompactReceiveVerdict v;
        v.blockhash = blockhash;
        m_parked.erase(peer);   // a fresh announcement supersedes the old one

        auto pdb = std::make_unique<vendor::PartiallyDownloadedBlock>(
            m_mempool, m_max_block_tx_count);
        const auto st = pdb->InitData(cmpct, {});
        if (st == vendor::READ_STATUS_INVALID) {
            v.kind = CompactReceiveVerdict::Kind::Reject;
            v.reason = "cmpctblock InitData invalid";
            return v;
        }
        if (st != vendor::READ_STATUS_OK) {
            v.kind = CompactReceiveVerdict::Kind::FallbackFull;
            v.reason = "cmpctblock short-id collision";
            return v;
        }

        vendor::BlockTransactionsRequest req;
        req.blockhash = blockhash;
        const size_t n = cmpct.BlockTxCount();
        for (size_t i = 0; i < n; ++i)
            if (!pdb->IsTxAvailable(i))
                req.indexes.push_back(static_cast<uint16_t>(i));

        if (req.indexes.empty())
            return fill(*pdb, {}, blockhash);

        m_parked[peer] = Parked{blockhash, std::move(pdb)};
        v.kind = CompactReceiveVerdict::Kind::NeedTxn;
        v.request = std::move(req);
        v.reason = "missing transactions";
        return v;
    }

    CompactReceiveVerdict on_blocktxn(const std::string& peer,
                                      const vendor::BlockTransactions& txs)
    {
        CompactReceiveVerdict v;
        v.blockhash = txs.blockhash;
        auto it = m_parked.find(peer);
        if (it == m_parked.end() || it->second.blockhash != txs.blockhash) {
            v.kind = CompactReceiveVerdict::Kind::Ignore;
            v.reason = "unrequested blocktxn";
            return v;
        }
        auto pdb = std::move(it->second.pdb);
        m_parked.erase(it);
        return fill(*pdb, txs.txn, txs.blockhash);
    }

    void on_disconnect(const std::string& peer) { m_parked.erase(peer); }

    size_t parked_count() const { return m_parked.size(); }
    bool has_parked(const std::string& peer) const { return m_parked.count(peer) != 0; }

private:
    struct Parked {
        uint256 blockhash;
        std::unique_ptr<vendor::PartiallyDownloadedBlock> pdb;
    };

    CompactReceiveVerdict fill(vendor::PartiallyDownloadedBlock& pdb,
                               const std::vector<vendor::CTransactionRef>& missing,
                               const uint256& blockhash)
    {
        CompactReceiveVerdict v;
        v.blockhash = blockhash;
        BlockType block;
        if (pdb.FillBlock(block, missing) != vendor::READ_STATUS_OK) {
            v.kind = CompactReceiveVerdict::Kind::Reject;
            v.reason = "blocktxn count does not match the request";
            return v;
        }
        if (!block_body_binds_to_header(block)) {
            v.kind = CompactReceiveVerdict::Kind::FallbackFull;
            v.reason = "reassembled body does not bind to header merkle root";
            return v;
        }
        v.kind = CompactReceiveVerdict::Kind::Complete;
        v.block = std::move(block);
        return v;
    }

    vendor::MempoolShortIdProvider m_mempool;
    size_t m_max_block_tx_count;
    std::map<std::string, Parked> m_parked;
};

} // namespace coin
} // namespace dash
