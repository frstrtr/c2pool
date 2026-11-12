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
// on_disconnect drops it; drop_block drops every peer's park for one hash
// (the body landed, or the lost-body watchdog fell back to a full block).
//
// compact_gate() is the DoS gate the CoinClient runs BEFORE InitData (dashcore
// ProcessMessage CMPCTBLOCK, the part between the header and InitData):
//   prev header unknown                 -> GetHeaders (MaybeSendGetHeaders)
//   header PoW does not meet its nBits  -> Misbehave  (BLOCK_INVALID_HEADER,
//                                                      Misbehaving(100))
//   header refused by the header chain  -> Drop
//   body already held                   -> Drop       (BLOCK_HAVE_DATA)
//   not more work than our best body    -> FetchFull if we asked this peer
//                                          (getdata MSG_BLOCK), else Drop
//   more than 2 blocks past our best    -> FetchFull if asked, else
//   body                                   HeaderOnly (fRevertToHeaderProcessing)
//   asked this peer, or this peer is    -> Reconstruct (InitData)
//   one of our high-bandwidth peers
//   otherwise                           -> HeaderOnly
// So InitData (the short-id map, the mempool walk) only ever runs for a header
// with real PoW that connects to our chain, extends our best body by at most
// two, and that we either requested from this peer or asked this peer to push.

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
// Dash Core net_processing.cpp: we serve cmpctblock / blocktxn only for blocks
// this close to our tip.
inline constexpr int MAX_CMPCTBLOCK_DEPTH = 5;
inline constexpr int MAX_BLOCKTXN_DEPTH   = 10;
// Dash Core net_processing.cpp MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK: at most this
// many peers reconstruct one block at a time.
inline constexpr size_t MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3;

// CheckBlockHeader's proof of work: X11(header) <= the target nBits encodes,
// with nBits itself well formed (Dash Core CheckProofOfWork, minus the
// powLimit bound, which the header chain applies when the header is added).
inline bool header_pow_meets_bits(const uint256& x11_hash, uint32_t bits)
{
    bool negative = false, overflow = false;
    uint256 target;
    target.SetCompact(bits, &negative, &overflow);
    if (negative || overflow || target.IsNull())
        return false;
    return x11_hash <= target;
}

// The header-chain facts the cmpctblock gate needs. Supplied by the owner of
// the HeaderChain (main_dash binds it, compact_mempool_provider.hpp); the
// receiver and the client stay free of the chain itself.
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
    std::function<std::vector<uint256>()> locator;     // for getheaders
    explicit operator bool() const
    {
        return static_cast<bool>(lookup) && static_cast<bool>(tip_hash)
            && static_cast<bool>(locator);
    }
};

struct CompactGateFacts
{
    bool prev_known{false};        // header.hashPrevBlock is in the header chain
    bool pow_ok{false};            // header_pow_meets_bits
    bool header_accepted{false};   // in the header chain after we fed it
    bool have_body{false};         // the body was already delivered
    bool more_work{false};         // chain work > our best delivered body's
    bool near_tip{false};          // height <= best delivered body + 2
    bool requested{false};         // we sent THIS peer getdata(MSG_CMPCT_BLOCK)
    bool high_bandwidth{false};    // we asked THIS peer to push (sendcmpct 1)
};

enum class CompactGate
{
    GetHeaders,
    Misbehave,
    Drop,
    FetchFull,
    HeaderOnly,
    Reconstruct,
};

inline const char* compact_gate_name(CompactGate g)
{
    switch (g) {
    case CompactGate::GetHeaders:  return "getheaders";
    case CompactGate::Misbehave:   return "misbehave";
    case CompactGate::Drop:        return "drop";
    case CompactGate::FetchFull:   return "fetch-full";
    case CompactGate::HeaderOnly:  return "header-only";
    case CompactGate::Reconstruct: return "reconstruct";
    }
    return "?";
}

inline CompactGate compact_gate(const CompactGateFacts& f)
{
    if (!f.prev_known)      return CompactGate::GetHeaders;
    if (!f.pow_ok)          return CompactGate::Misbehave;
    if (!f.header_accepted) return CompactGate::Drop;
    if (f.have_body)        return CompactGate::Drop;
    if (!f.more_work)
        return f.requested ? CompactGate::FetchFull : CompactGate::Drop;
    if (!f.near_tip)
        return f.requested ? CompactGate::FetchFull : CompactGate::HeaderOnly;
    if (f.requested || f.high_bandwidth)
        return CompactGate::Reconstruct;
    return CompactGate::HeaderOnly;
}

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
        m_parked.erase(peer);   // a fresh announcement supersedes the old one

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
    void clear_parked() { m_parked.clear(); }

    // Drop every peer's park for `blockhash`. Returns how many were dropped.
    size_t drop_block(const uint256& blockhash)
    {
        size_t n = 0;
        for (auto it = m_parked.begin(); it != m_parked.end();)
            if (it->second.blockhash == blockhash) { it = m_parked.erase(it); ++n; }
            else ++it;
        return n;
    }

    // The hash `peer` has parked, if any.
    std::optional<uint256> parked_hash(const std::string& peer) const
    {
        auto it = m_parked.find(peer);
        if (it == m_parked.end()) return std::nullopt;
        return it->second.blockhash;
    }

    // How many peers have `blockhash` parked.
    size_t parked_count_for(const uint256& blockhash) const
    {
        size_t n = 0;
        for (const auto& [_, pk] : m_parked)
            if (pk.blockhash == blockhash) ++n;
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
    size_t m_max_block_size;
    std::map<std::string, Parked> m_parked;
};

} // namespace coin
} // namespace dash
