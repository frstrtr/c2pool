// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/fakes/fake_txpool.hpp
//
// Compiling fake for the four C3 surfaces: IRelayedTxSink, ITxpoolSnapshot,
// ITxSource and ITxBlobSource.
//
// The verdict it returns is driven by the AdmissionEvidence mask a test sets on
// each canned transaction (must-fix b), so a wave-1 component can exercise the
// "daemon-confirmed but no fee replica yet" case that a scalar tier could not
// express at all.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "../txpool.hpp"

namespace c2pool::xmr::native::fakes {

class FakeTxpool final : public IRelayedTxSink,
                         public ITxpoolSnapshot,
                         public ITxSource,
                         public ITxBlobSource {
public:
    struct Entry {
        node::TxBacklogEntry      backlog{};
        std::vector<std::uint8_t> blob;
        AdmissionEvidence         evidence   = AdmissionEvidence::Structural;
        bool                      conflicted = false;
        std::uint32_t             seen_from_peers = 1;
        bool                      stem       = false;   // still in the Dandelion++ stem
    };

    // The configured selection policy, standing in for the real pool's config.
    TxpoolSelectPolicy configured{};

    std::map<std::string, Entry> entries;   // keyed by the 32-byte id

    struct RelayCall { PeerRef peer; std::size_t n_blobs; bool fluff; };
    std::vector<RelayCall> relay_calls;

    std::map<std::string, std::vector<Hash>> pins;   // template id -> ids

    // --- IRelayedTxSink ------------------------------------------------------
    std::vector<TxRelayVerdict> on_relayed(const PeerRef& p,
                                           std::vector<std::vector<std::uint8_t>> blobs,
                                           bool dandelionpp_fluff) override {
        relay_calls.push_back({p, blobs.size(), dandelionpp_fluff});
        std::vector<TxRelayVerdict> out;
        out.reserve(blobs.size());
        for (const auto& b : blobs) {
            TxRelayVerdict v;
            if (b.empty()) {
                v.reason = TxRelayVerdict::Reason::Structural;
                v.drop_offense = true;
            } else {
                v.reason   = TxRelayVerdict::Reason::Accepted;
                v.evidence = AdmissionEvidence::Structural;
            }
            out.push_back(v);
        }
        return out;
    }

    std::vector<Hash> complement_request_ids() const override {
        std::vector<Hash> out;
        for (const auto& kv : entries) out.push_back(kv.second.backlog.id);
        return out;
    }

    // --- ITxpoolSnapshot -----------------------------------------------------
    std::vector<node::TxBacklogEntry> selectable_backlog() const override {
        return selectable_backlog(configured);
    }

    std::vector<node::TxBacklogEntry> selectable_backlog(
            const TxpoolSelectPolicy& p) const override {
        std::vector<node::TxBacklogEntry> out;
        for (const auto& kv : entries) {
            const Entry& e = kv.second;
            // Never a knob: a key-image conflict is unselectable at any policy.
            if (e.conflicted) continue;
            if (!covers(e.evidence, p.required)) continue;
            if (e.seen_from_peers < p.min_peers) continue;
            if (e.stem && !p.allow_stem) continue;
            out.push_back(e.backlog);
        }
        return out;
    }

    TxpoolSelectPolicy policy() const override { return configured; }

    std::uint64_t backlog_version() const override { return version_; }

    // --- ITxSource -----------------------------------------------------------
    bool get_tx(const Hash& id, std::vector<std::uint8_t>& full_blob) override {
        const auto it = entries.find(key_of(id));
        if (it == entries.end()) return false;
        full_blob = it->second.blob;
        return true;
    }

    // --- ITxBlobSource -------------------------------------------------------
    bool get_blobs(const std::vector<Hash>& ids,
                   std::vector<std::vector<std::uint8_t>>& out,
                   std::vector<Hash>& missing) override {
        out.clear(); missing.clear();
        for (const Hash& id : ids) {
            const auto it = entries.find(key_of(id));
            if (it == entries.end()) missing.push_back(id);
            else out.push_back(it->second.blob);
        }
        return missing.empty();
    }

    void pin(const Hash& template_id, const std::vector<Hash>& ids) override {
        pins[key_of(template_id)] = ids;
    }
    void unpin(const Hash& template_id) override { pins.erase(key_of(template_id)); }

    // --- test helpers --------------------------------------------------------
    void add(const Hash& id, std::uint64_t weight, std::uint64_t fee,
             AdmissionEvidence ev = EVIDENCE_DAEMONLESS_DEFAULT,
             std::uint32_t peers = 1, bool conflicted = false) {
        Entry e;
        e.backlog.id        = id;
        e.backlog.weight    = weight;
        e.backlog.blob_size = weight;
        e.backlog.fee       = fee;
        e.blob.assign(static_cast<std::size_t>(weight ? weight : 1), 0x11);
        e.evidence        = ev;
        e.seen_from_peers = peers;
        e.conflicted      = conflicted;
        entries[key_of(id)] = std::move(e);
        ++version_;
    }

    static std::string key_of(const Hash& h) {
        return std::string(reinterpret_cast<const char*>(h.data()), h.size());
    }

private:
    std::uint64_t version_ = 1;
};

} // namespace c2pool::xmr::native::fakes
