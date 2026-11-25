// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Dash Core v24.0.0 block assembly puts a pending ProUpServTx of a masternode
/// BEFORE a transaction in the same block that changes or revokes that
/// masternode's operator key (node/miner.cpp addPackageTxs: keyChangedMNs,
/// CTxMemPool::GetServiceUpdatesBeforeKeyChange / IsUnorderableServiceUpdate).
///
/// Both orders are valid blocks: CheckProUpServTx checks the signature against
/// the list at the previous block, and the list builder applies the update
/// after the key change too. But applied after it, the update writes the
/// previous operator's service fields onto the masternode and revives it
/// under the new key (specialtxman.cpp ApplyProUpServTx + Revive), so Core's
/// miner never builds that order: it pulls the update (with its unconfirmed
/// ancestors) in first, and leaves out an update it cannot put first.
///
/// order_service_updates() is that rule over an already selected body (in a
/// valid parent-before-child order):
///   * for each key change K of masternode X (ProUpRegTx with a new key,
///     ProUpRevTx of a masternode holding a key, ProUpSharedRegTx with a new
///     key: GetKeyChangeTarget), every later ProUpServTx(X) moves, with its
///     not yet placed in-body ancestors, to just before K, unless one of those
///     is K itself or a descendant of K, another key change, an MNHF signal,
///     an asset lock or unlock (IsUnorderableServiceUpdate), or a ProUpServTx
///     of a masternode whose key the block already changed;
///   * a ProUpServTx of a masternode whose key changed earlier in the block is
///     left out, with every in-body descendant (a child would spend an output
///     the block no longer creates).
/// Relative order is kept otherwise, so parents still precede children.

#include <core/uint256.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace dash {
namespace coin {

struct ServiceOrderTx {
    uint256 txid;
    std::vector<uint256> spends;               ///< the txids its inputs spend (vin prevout hashes)
    std::optional<uint256> key_change_of;      ///< GetKeyChangeTarget
    std::optional<uint256> service_update_of;  ///< a ProUpServTx: its proTxHash
    bool unorderable_kind{false};              ///< an MNHF signal, asset lock or asset unlock
};

struct ServiceOrderResult {
    std::vector<size_t> order;                 ///< indices into the body, the new order (kept txs only)
    std::vector<std::pair<size_t, std::string>> dropped;
    size_t moved{0};                           ///< txs pulled in front of a key change
};

inline ServiceOrderResult order_service_updates(const std::vector<ServiceOrderTx>& body)
{
    ServiceOrderResult res;
    const size_t n = body.size();
    std::map<uint256, size_t> index_of;
    for (size_t i = 0; i < n; ++i) index_of.emplace(body[i].txid, i);
    std::vector<std::vector<size_t>> parents(n);
    for (size_t i = 0; i < n; ++i)
        for (const auto& h : body[i].spends) {
            auto it = index_of.find(h);
            if (it != index_of.end() && it->second != i) parents[i].push_back(it->second);
        }

    enum class St : uint8_t { Pending, Placed, Dropped };
    std::vector<St> st(n, St::Pending);
    std::set<uint256> key_changed;

    auto drop = [&](size_t i, std::string why) {
        st[i] = St::Dropped;
        res.dropped.emplace_back(i, std::move(why));
    };
    auto has_dropped_parent = [&](size_t i) {
        for (size_t p : parents[i])
            if (st[p] == St::Dropped) return true;
        return false;
    };
    // Is `a` an in-body ancestor of `d`?
    auto descends_from = [&](size_t d, size_t a) {
        std::vector<size_t> stack{d};
        std::set<size_t> seen;
        while (!stack.empty()) {
            const size_t x = stack.back();
            stack.pop_back();
            for (size_t p : parents[x]) {
                if (p == a) return true;
                if (seen.insert(p).second) stack.push_back(p);
            }
        }
        return false;
    };

    for (size_t i = 0; i < n; ++i) {
        if (st[i] != St::Pending) continue;
        if (has_dropped_parent(i)) {
            drop(i, "it spends an output of a left-out tx");
            continue;
        }
        if (body[i].service_update_of && key_changed.count(*body[i].service_update_of)) {
            drop(i, "it would follow an operator key change of masternode "
                        + body[i].service_update_of->GetHex().substr(0, 16));
            continue;
        }
        if (body[i].key_change_of) {
            const uint256& mn = *body[i].key_change_of;
            for (size_t j = i + 1; j < n; ++j) {
                if (st[j] != St::Pending || !body[j].service_update_of || *body[j].service_update_of != mn)
                    continue;
                if (descends_from(j, i)) continue;   // left out when reached
                // The update's package: it and its in-body ancestors not yet placed.
                std::set<size_t> pkg{j};
                std::vector<size_t> stack{j};
                bool ok = true;
                while (!stack.empty() && ok) {
                    const size_t x = stack.back();
                    stack.pop_back();
                    for (size_t p : parents[x]) {
                        if (st[p] == St::Dropped) ok = false;
                        if (st[p] != St::Pending) continue;
                        if (pkg.insert(p).second) stack.push_back(p);
                    }
                }
                for (size_t x : pkg) {
                    if (!ok) break;
                    if (body[x].key_change_of || body[x].unorderable_kind) ok = false;
                    if (body[x].service_update_of && key_changed.count(*body[x].service_update_of)) ok = false;
                }
                if (!ok) continue;   // left out when reached (it follows the key change)
                for (size_t x : pkg) {   // std::set: ascending body order, parents first
                    st[x] = St::Placed;
                    res.order.push_back(x);
                    ++res.moved;
                }
            }
            key_changed.insert(mn);
        }
        st[i] = St::Placed;
        res.order.push_back(i);
    }
    return res;
}

} // namespace coin
} // namespace dash
