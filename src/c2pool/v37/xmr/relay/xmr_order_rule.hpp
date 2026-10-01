// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_order_rule.hpp   (handoff gap 4, the A6 remainder)
//
// THE CANONICAL LANE ORDER: key (bin, id), with a bounded late tail.
//
// The canonical ingest (xmr_receipt_ingest.hpp) pushes a closed bin sorted by
// receipt id, bins in ascending order, and a receipt whose bin already closed
// ("late") at the tail. So every honest order is: each entry either raises the
// high-water key H = max (bin, id) placed so far (on time), or sits behind it
// (late). The rule bounds the late case:
//
//     an entry (b, id) may follow high-water H iff  (b, id) > H
//                                                 or b + kLateTailBins >= H.bin
//
// and no receipt id appears twice in the whole order [0, P). The SAME
// predicate (OrderHighWater::admits) is applied by the builder (the ingest
// drops a late receipt it would not admit, instead of pushing it) and by the
// receiver of a relay repair (check_composed_order over our own [0, a0) and
// the served [a0, P)), so an honest winner's order is never refused.
//
// THE OWN TAIL IS BOUNDED. A repeated id has one bin (the bin is a function of
// the receipt: its prev_id's height), and in an order that obeys the rule,
// every entry before one with bin + T < m has a bin < m (the rule at that
// entry bounds the high-water before it). So the walk back from a0 stops at the
// first entry with bin + T < m, where m = the lowest bin in the served suffix:
// nothing before it can repeat a served id or move the served entries' test.
// It also stops at kMaxOwnWalk entries or where our own order is not known
// here (a restart below the tail): the check then uses what it walked.
//
// Integer-only; the verdict depends only on the two orders and the bins.
// ===========================================================================
#pragma once

#include <algorithm>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <sharechain/v37/v37_hash.hpp>

#define C2POOL_XMR_ORDER_RULE 1

namespace c2pool::v37n::xmr::relay {

// The late tail: how many bins a late receipt may sit behind the high-water
// bin (30 Monero blocks, about one hour). Beyond it a receipt is stale work.
inline constexpr std::uint64_t kLateTailBins = 30;
// The longest walk back into our own order (the relay vault's default horizon).
inline constexpr std::uint64_t kMaxOwnWalk = 8640;

struct OrderEntry {
    ::v37::bytes32 id{};
    std::uint64_t  bin = 0;   // origin bin (the coinbase height); 0 = not resolved
};

class OrderHighWater {
public:
    explicit OrderHighWater(std::uint64_t tail = kLateTailBins) : m_tail(tail) {}
    bool admits(std::uint64_t bin, const ::v37::bytes32& id) const {
        if (!m_any || above(bin, id)) return true;
        return bin >= m_bin || m_bin - bin <= m_tail;
    }
    void note(std::uint64_t bin, const ::v37::bytes32& id) {
        if (!m_any || above(bin, id)) { m_any = true; m_bin = bin; m_id = id; }
    }
    bool any() const { return m_any; }
    std::uint64_t bin() const { return m_bin; }
    std::uint64_t tail() const { return m_tail; }

private:
    bool above(std::uint64_t bin, const ::v37::bytes32& id) const {
        return bin > m_bin || (bin == m_bin && m_id < id);
    }
    std::uint64_t  m_tail;
    bool           m_any = false;
    std::uint64_t  m_bin = 0;
    ::v37::bytes32 m_id{};
};

struct OrderCheck {
    bool          ok = true;
    std::string   why;
    std::uint64_t own_walked = 0;       // entries of our own [0, a0) read
    bool          own_complete = true;  // the walk reached its stop (not a gap / the cap)
};

// own_at(pos, e, first): the receipt of our own order that covers lane
// position pos < a0 and its first position (false = not known here).
// `served` = the receipts of the served [a0, P), in order, every bin resolved.
using OwnAtFn = std::function<bool(std::uint64_t pos, OrderEntry& e, std::uint64_t& first)>;
inline OrderCheck check_composed_order(std::uint64_t a0, const std::vector<OrderEntry>& served, const OwnAtFn& own_at,
                                       std::uint64_t tail = kLateTailBins, std::uint64_t max_walk = kMaxOwnWalk) {
    OrderCheck out;
    if (served.empty()) return out;
    std::uint64_t m = served.front().bin;
    for (const auto& e : served) {
        if (e.bin == 0) { out.ok = false; out.why = "a served receipt has no resolved bin"; return out; }
        m = std::min(m, e.bin);
    }
    std::vector<OrderEntry> own;   // walked back from a0 - 1
    for (std::uint64_t pos = a0; pos > 0;) {
        if (out.own_walked >= max_walk) { out.own_complete = false; break; }
        --pos;
        OrderEntry e;
        std::uint64_t first = pos;
        if (!own_at || !own_at(pos, e, first) || e.bin == 0 || first > pos) { out.own_complete = false; break; }
        pos = first;
        own.push_back(e);
        ++out.own_walked;
        if (e.bin < m && m - e.bin > tail) break;   // the stop: nothing earlier can collide
    }
    OrderHighWater hw(tail);
    std::set<::v37::bytes32> seen;
    for (auto it = own.rbegin(); it != own.rend(); ++it) { seen.insert(it->id); hw.note(it->bin, it->id); }
    for (std::size_t i = 0; i < served.size(); ++i) {
        const auto& e = served[i];
        const std::uint64_t pos = a0 + i;   // the receipt index past a0 (one position per receipt, A2)
        if (!seen.insert(e.id).second) {
            out.ok = false;
            out.why = "position " + std::to_string(pos) + " repeats a receipt already placed in the composed order [0," +
                      std::to_string(a0 + served.size()) + ")";
            return out;
        }
        if (!hw.admits(e.bin, e.id)) {
            out.ok = false;
            out.why = "position " + std::to_string(pos) + " (bin " + std::to_string(e.bin) + ") sits behind the high-water bin " +
                      std::to_string(hw.bin()) + " by more than the late tail of " + std::to_string(tail) + " bins";
            return out;
        }
        hw.note(e.bin, e.id);
    }
    return out;
}

// Our own lane order's last kMaxOwnWalk receipts (the ingest's after-push
// callback notes each one). A reloaded receipt carries no bin: at() resolves
// it from its prev_id through bin_of.
class OwnOrderTail {
public:
    using BinOfFn = std::function<std::optional<std::uint64_t>(const ::v37::bytes32& prev_id)>;
    explicit OwnOrderTail(std::size_t cap = kMaxOwnWalk) : m_cap(cap ? cap : 1) {}
    void note(std::uint64_t pos_first, std::uint32_t n_pushes, const ::v37::bytes32& id, std::uint64_t bin,
              const ::v37::bytes32& prev_id = {}) {
        m_items[pos_first] = Item{n_pushes ? n_pushes : 1, id, bin, prev_id};
        while (m_items.size() > m_cap) m_items.erase(m_items.begin());
    }
    bool at(std::uint64_t pos, OrderEntry& e, std::uint64_t& first, const BinOfFn& bin_of = nullptr) const {
        auto it = m_items.upper_bound(pos);
        if (it == m_items.begin()) return false;
        --it;
        if (pos >= it->first + it->second.n) return false;
        first = it->first;
        e.id = it->second.id;
        e.bin = it->second.bin;
        if (e.bin == 0 && bin_of) { if (const auto b = bin_of(it->second.prev_id)) e.bin = *b; }
        return e.bin != 0;
    }
    std::size_t size() const { return m_items.size(); }

private:
    struct Item { std::uint32_t n = 1; ::v37::bytes32 id{}; std::uint64_t bin = 0; ::v37::bytes32 prev_id{}; };
    std::size_t m_cap;
    std::map<std::uint64_t, Item> m_items;
};

}  // namespace c2pool::v37n::xmr::relay
