// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_lane_epoch_chain.hpp   (LANE-EPOCH, E1)
//
// The chain side of the epoch rule (xmr_lane_epoch.hpp): one Monero block's
// bytes -> the ChainFact the rule reads. A pure function of the block bytes and
// the structure's pool_tag: every node reads the same fact from the same block.
// ===========================================================================
#pragma once

#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "xmr_coinbase_authority.hpp"   // parse_block / parse_coinbase_prefix / mm_commitment_root
#include "xmr_lane_epoch.hpp"

namespace c2pool::v37n::xmr::epoch {

// sha256d('V37Q') -- OwedLedger::owed_digest() of a ledger without rows (R-A
// tag; pinned against OwedLedger in v37_xmr_epoch_field_kat).
inline bytes32 empty_owed_digest() {
    const std::vector<std::uint8_t> t = {'V', '3', '7', 'Q'};
    return ::v37::sha256d(t);
}

// The 0x03 merge-mining root a lane coinbase committing `owed_digest` carries.
inline bytes32 mm_root_of(std::uint32_t chain_id, const bytes32& owed_digest) {
    const auto r = ::v37::xmr::settle::mm_commitment_root(chain_id, owed_digest);
    bytes32 out{};
    std::memcpy(out.data(), r.data(), 32);
    return out;
}

inline bytes32 empty_root(std::uint32_t chain_id) { return mm_root_of(chain_id, empty_owed_digest()); }

// nullopt: the bytes do not parse as a block (a transport problem the caller retries).
inline std::optional<ChainFact> fact_of_blob(std::uint64_t h, const bytes32& bid, const std::vector<std::uint8_t>& blob,
                                             const bytes32& pool_tag) {
    namespace cons = ::c2pool::xmr::native;
    ChainFact c; c.h = h; c.bid = bid;
    cons::ParsedBlock pb;
    const cons::BlockParseStatus st = cons::parse_block(blob.data(), blob.size(), pb);
    if (st != cons::BlockParseStatus::Ok && st != cons::BlockParseStatus::TxCountMismatch) return std::nullopt;
    ::v37::xmr::settle::ReceivedCoinbase got;
    std::uint64_t height = 0; std::size_t used = 0;
    if (!::c2pool::xmr::assembly::parse_coinbase_prefix(blob.data() + pb.miner_tx_offset, pb.miner_tx_size, got, &height, &used))
        return c;   // not a v37 coinbase: an ordinary block (decided from the bytes)
    if (got.tx_extra.size() < 35) return c;
    const unsigned char* tag = got.tx_extra.data() + got.tx_extra.size() - 35;
    if (tag[0] != 0x03 || tag[1] != 0x21 || tag[2] != 0x00) return c;
    if (credit::classify_lineage(got.tx_extra, pool_tag) != credit::BlockLineage::Own) return c;
    c.own = true;
    c.has_root = true; std::memcpy(c.root.data(), tag + 3, 32);
    c.ep = credit::parse_epoch(got.tx_extra, &c.f);
    c.has_cut = credit::parse_from_tx_extra(got.tx_extra).has_value();
    return c;
}

// E1 CLOSE at a valid opener: every non-zero finalW row is zeroed THROUGH the
// node's event log (one synthetic FOUND with credit = -row + its FINALIZE at
// h + D_conf, id close_event_id), so the ledger is the EMPTY state before the
// opener is decoded and a restart replays the same. A fresh node has no rows:
// nothing is written. Returns the closed rows (the record the caller keeps).
template <class Node>
inline std::map<bytes32, long long> close_ledger(Node& node, std::uint32_t new_seq, const bytes32& opener_bid,
                                                 std::uint64_t h, std::uint64_t d_conf) {
    std::map<bytes32, long long> rows, neg;
    for (const auto& [k, w] : node.ledger().finalW()) if (w != 0) { rows[k] = w; neg[k] = -w; }
    if (neg.empty()) return rows;
    static const char* d = "0123456789abcdef";
    const bytes32 id = close_event_id(new_seq, opener_bid);
    std::string hx; for (auto c : id) { hx += d[c >> 4]; hx += d[c & 15]; }
    (void)node.seed_settled_owed(hx, neg, h + d_conf);
    return rows;
}

} // namespace c2pool::v37n::xmr::epoch
