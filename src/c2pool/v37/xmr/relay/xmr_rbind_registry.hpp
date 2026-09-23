// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_rbind_registry.hpp   (SEAM-1)
//
// The per-JOB receipt binding the template writes into the coinbase:
//
//     0x02 payload = [extra_nonce 4 | rbind 32 | weight padding | tail]
//     rbind        = rbind_v1(chain_id, side_data_v2)          (relay wire)
//
// Every stratum job gets a FRESH extra_nonce (XmrStratumServer::make_job), so
// extra_nonce is the job key. Right before the job's blob is built the
// stratum server calls the job binder (set_job_binder) with the session's
// login address; the daemon decides the job's payee there -- the node-owner
// fee roll happens HERE, at job issue (v36 work.py) -- and the u16 give-author
// the receipt will carry, and records them. The template then asks
// IXmrSettlementSource::extra_nonce_bind(extra_nonce) for the 32 bytes; the
// share the miner finds on that job is RandomX-bound to (payee, give-author)
// and the relay mint later reads the SAME entry back, so the receipt it mints
// passes check_structural(BindMode::Rbind) on every peer.
//
// Entries are IMMUTABLE once written (a job blob is rebuilt at submit and must
// reproduce the hashed bytes), and the map is bounded FIFO (old jobs age out
// with their templates). Thread-safe: written on the stratum listener thread,
// read on the listener thread (blob build / submit / mint) and the main
// thread (in-process miner).
// ===========================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <mutex>
#include <optional>
#include <unordered_map>

#include "xmr_relay_wire.hpp"   // SideDataV2, rbind_v1

namespace c2pool::v37n::xmr::relay {

struct JobBinding {
    ::v37::ScriptRef payee;             // the payee this job's coinbase commits to
    SideDataV2       side;              // t_origin, identity(payee), chain, give_author
    bytes32          rbind{};           // rbind_v1(chain, side)
    bool             owner_substituted = false;   // bookkeeping only (the owner-fee roll hit)
};

// The binding for one job (pure).
inline JobBinding make_job_binding(u32 chain, u64 share_diff, const ::v37::ScriptRef& payee,
                                   u16 give_author, bool owner_substituted = false) {
    JobBinding b;
    b.payee = payee;
    b.side.t_lo = share_diff;
    b.side.identity = ::v37::xmr::xmr_identity_key(payee);
    b.side.chain_id = chain;
    b.side.give_author = give_author;
    b.rbind = rbind_v1(chain, b.side);
    b.owner_substituted = owner_substituted;
    return b;
}

class RbindRegistry {
public:
    static constexpr std::size_t kBindBytes = 32;
    explicit RbindRegistry(std::size_t cap = std::size_t{1} << 16) : m_cap(cap ? cap : 1) {}

    // First write wins: a bound job's bytes never change (returns false if
    // `extra_nonce` was already bound).
    bool put(u32 extra_nonce, JobBinding b) {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_map.count(extra_nonce)) return false;
        m_map.emplace(extra_nonce, std::move(b));
        m_order.push_back(extra_nonce);
        while (m_order.size() > m_cap) { m_map.erase(m_order.front()); m_order.pop_front(); }
        return true;
    }
    std::optional<JobBinding> get(u32 extra_nonce) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_map.find(extra_nonce);
        if (it == m_map.end()) return std::nullopt;
        return it->second;
    }
    // The template seam (IXmrSettlementSource::extra_nonce_bind): 32 bytes.
    bool bind_bytes(u32 extra_nonce, std::uint8_t* out) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_map.find(extra_nonce);
        if (it == m_map.end()) return false;
        std::memcpy(out, it->second.rbind.data(), kBindBytes);
        return true;
    }
    std::size_t size() const { std::lock_guard<std::mutex> lk(m_mtx); return m_map.size(); }

private:
    mutable std::mutex m_mtx;
    std::size_t m_cap;
    std::unordered_map<u32, JobBinding> m_map;
    std::deque<u32> m_order;
};

} // namespace c2pool::v37n::xmr::relay
