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
//                                                       block parked
//       INVALID (bad short-id / prefilled index)     -> Reject (dashcore
//                                                       Misbehaving(100))
//       FAILED (short-id collision)                  -> FallbackFull (getdata
//                                                       MSG_BLOCK)
//   blocktxn -> FillBlock against the (peer, hash) park
//       no park for (peer, hash)                     -> Ignore (dashcore
//                                                       "unrequested blocktxn")
//       tx count != the indexes we asked for         -> Ignore, park kept (the
//                                                       lost-body watchdog
//                                                       falls back)
//       filled, body does not bind to header merkle  -> FallbackFull
//       filled + binds                               -> Complete
//
// The merkle bind is the adaptation the vendor note asks for: vendor
// FillBlock drops dashcore's CheckBlock/IsBlockMutated, so a short-id
// collision that pulled in the wrong mempool tx would otherwise ride through
// unchecked. dashcore answers that case (READ_STATUS_FAILED) by fetching the
// full block, and so do we. block_body_binds_to_header also carries the
// CVE-2012-2459 duplicate-padding guard.
//
// Parks are keyed by (peer, block hash), at most MAX_PARKED_PER_PEER per peer
// and MAX_PARKED_TOTAL overall (the oldest goes first). on_disconnect drops a
// peer's parks; drop_block drops every park for one hash (the body landed, or
// the lost-body watchdog fell back to a full block).
//
// compact_gate() is the gate the CoinClient runs BEFORE InitData. A
// cmpctblock is processed ONLY as the answer to our own getdata
// (MSG_CMPCT_BLOCK) to that peer, and only for a header that is already in
// our header chain (it came through getheaders, like every other header).
// Nothing from a cmpctblock is ever fed to the header chain:
//   not our request to this peer        -> Ignore (unsolicited: dropped)
//   header not in our header chain      -> FetchFull (getdata MSG_BLOCK)
//   body already held                   -> Drop      (BLOCK_HAVE_DATA)
//   not more work than our best body,   -> FetchFull (dashcore: we asked, but
//   or more than 2 past it                 the mempool will not help)
//   otherwise                           -> Reconstruct (InitData)

#include <impl/dash/coin/vendor/blockencodings.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/block_producer.hpp>   // block_body_binds_to_header

#include <core/uint256.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

// Dash Core consensus.h MaxBlockSize(fDIP0001Active = true): the block size
// limit in BYTES. PartiallyDownloadedBlock::InitData bounds the tx count by
// MaxBlockSize() / MIN_TRANSACTION_SIZE, so this (not a tx count) is what the
// receiver passes down.
inline constexpr size_t DASH_MAX_BLOCK_SIZE = 2'000'000;

// The header-chain facts the cmpctblock gate needs. Supplied by the owner of
// the HeaderChain (main_dash binds it, compact_mempool_provider.hpp); the
// receiver and the client stay free of the chain itself. Read-only: the
// compact path never adds a header.
struct CompactChainEntry
{
    uint32_t height{0};
    uint256  chain_work;
    uint256  prev_hash;
};

struct CompactChainView
{
    std::function<std::optional<CompactChainEntry>(const uint256&)> lookup;
    std::function<uint256()> tip_hash;                 // best header
    explicit operator bool() const
    {
        return static_cast<bool>(lookup) && static_cast<bool>(tip_hash);
    }
};

struct CompactGateFacts
{
    bool requested{false};         // we sent THIS peer getdata(MSG_CMPCT_BLOCK)
    bool header_known{false};      // the header is already in our header chain
    bool have_body{false};         // the body was already delivered
    bool more_work{false};         // chain work > our best delivered body's
    bool near_tip{false};          // height <= best delivered body + 2
};

enum class CompactGate
{
    Ignore,
    Drop,
    FetchFull,
    Reconstruct,
};

inline CompactGate compact_gate(const CompactGateFacts& f)
{
    if (!f.requested)                 return CompactGate::Ignore;
    if (!f.header_known)              return CompactGate::FetchFull;
    if (f.have_body)                  return CompactGate::Drop;
    if (!f.more_work || !f.near_tip)  return CompactGate::FetchFull;
    return CompactGate::Reconstruct;
}

struct CompactReceiveVerdict
{
    enum class Kind {
        Complete,      // `block` is the reassembled, merkle-bound block
        NeedTxn,       // send `request` as getblocktxn to the same peer
        FallbackFull,  // send getdata MSG_BLOCK for `blockhash`
        Reject,        // malformed by the peer (dashcore Misbehaving)
        Ignore,        // nothing to do (unrequested / mismatched blocktxn)
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
    static constexpr size_t MAX_PARKED_PER_PEER = 2;
    static constexpr size_t MAX_PARKED_TOTAL    = 8;

    // `max_block_size` is the block size limit in bytes (DASH_MAX_BLOCK_SIZE
    // in production), as Dash Core passes MaxBlockSize() to InitData.
    CompactBlockReceiver(vendor::MempoolShortIdProvider mempool,
                         size_t max_block_size)
        : m_mempool(std::move(mempool))
        , m_max_block_size(max_block_size) {}

    // `blockhash` = X11(header), computed by the caller (the receiver stays
    // free of the X11 dependency).
    CompactReceiveVerdict on_cmpctblock(const std::string& peer,
                                        const vendor::CBlockHeaderAndShortTxIDs& cmpct,
                                        const uint256& blockhash)
    {
        CompactReceiveVerdict v;
        v.blockhash = blockhash;
        m_parked.erase(Key{peer, blockhash});   // a repeat of the same block restarts it

        auto pdb = std::make_unique<vendor::PartiallyDownloadedBlock>(
            m_mempool, m_max_block_size);
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

        park(peer, blockhash, std::move(pdb), req.indexes.size());
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
        auto it = m_parked.find(Key{peer, txs.blockhash});
        if (it == m_parked.end()) {
            v.kind = CompactReceiveVerdict::Kind::Ignore;
            v.reason = "unrequested blocktxn";
            return v;
        }
        // Not an answer to what we asked for: ignore it and keep waiting; the
        // lost-body watchdog turns a park that never completes into a full
        // block from another peer. Never punished.
        if (txs.txn.size() != it->second.requested_count) {
            v.kind = CompactReceiveVerdict::Kind::Ignore;
            v.reason = "blocktxn tx count differs from the getblocktxn we sent";
            return v;
        }
        auto pdb = std::move(it->second.pdb);
        m_parked.erase(it);
        return fill(*pdb, txs.txn, txs.blockhash);
    }

    void on_disconnect(const std::string& peer)
    {
        for (auto it = m_parked.begin(); it != m_parked.end();)
            if (it->first.first == peer) it = m_parked.erase(it);
            else ++it;
    }
    void clear_parked() { m_parked.clear(); }

    // Drop every park for `blockhash`. Returns how many were dropped.
    size_t drop_block(const uint256& blockhash)
    {
        size_t n = 0;
        for (auto it = m_parked.begin(); it != m_parked.end();)
            if (it->first.second == blockhash) { it = m_parked.erase(it); ++n; }
            else ++it;
        return n;
    }

    // How many peers have `blockhash` parked.
    size_t parked_count_for(const uint256& blockhash) const
    {
        size_t n = 0;
        for (const auto& [k, _] : m_parked)
            if (k.second == blockhash) ++n;
        return n;
    }

    // #968a slice 3: install (or clear, with nullptr) the mempool the next
    // cmpctblock is matched against. A block already parked keeps the
    // provider it was built with; it only waits for blocktxn.
    void set_mempool_provider(vendor::MempoolShortIdProvider mempool)
    {
        m_mempool = std::move(mempool);
    }
    bool has_mempool_provider() const { return static_cast<bool>(m_mempool); }

    size_t parked_count() const { return m_parked.size(); }
    bool has_parked(const std::string& peer) const
    {
        for (const auto& [k, _] : m_parked)
            if (k.first == peer) return true;
        return false;
    }
    bool has_parked(const std::string& peer, const uint256& blockhash) const
    {
        return m_parked.count(Key{peer, blockhash}) != 0;
    }

private:
    using Key = std::pair<std::string, uint256>;
    struct Parked {
        std::unique_ptr<vendor::PartiallyDownloadedBlock> pdb;
        size_t requested_count{0};   // indexes in the getblocktxn we sent
        uint64_t seq{0};             // park order, for eviction
    };

    void park(const std::string& peer, const uint256& blockhash,
              std::unique_ptr<vendor::PartiallyDownloadedBlock> pdb, size_t requested)
    {
        auto evict_oldest = [this](bool same_peer_only, const std::string& p) {
            auto victim = m_parked.end();
            for (auto it = m_parked.begin(); it != m_parked.end(); ++it) {
                if (same_peer_only && it->first.first != p) continue;
                if (victim == m_parked.end() || it->second.seq < victim->second.seq)
                    victim = it;
            }
            if (victim != m_parked.end()) m_parked.erase(victim);
        };
        size_t mine = 0;
        for (const auto& [k, _] : m_parked)
            if (k.first == peer) ++mine;
        if (mine >= MAX_PARKED_PER_PEER) evict_oldest(true, peer);
        if (m_parked.size() >= MAX_PARKED_TOTAL) evict_oldest(false, peer);
        m_parked[Key{peer, blockhash}] = Parked{std::move(pdb), requested, ++m_seq};
    }

    CompactReceiveVerdict fill(vendor::PartiallyDownloadedBlock& pdb,
                               const std::vector<vendor::CTransactionRef>& missing,
                               const uint256& blockhash)
    {
        CompactReceiveVerdict v;
        v.blockhash = blockhash;
        BlockType block;
        if (pdb.FillBlock(block, missing) != vendor::READ_STATUS_OK) {
            v.kind = CompactReceiveVerdict::Kind::Reject;
            v.reason = "blocktxn does not fill the block";
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
    size_t m_max_block_size;
    std::map<Key, Parked> m_parked;
    uint64_t m_seq{0};
};

} // namespace coin
} // namespace dash
