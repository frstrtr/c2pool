// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/template/xmr_monerod_miner_data.hpp
//
// C4, the daemon half: MonerodMinerDataSource -- the EXISTING option-B path,
// wrapped in the IMinerDataSource seam and not otherwise changed.
//
// This arm is never removed. It is the M0..M4 default, it is what the parity
// oracle judges the native arm against, and it is what the resolver falls back
// to when the native arm loses readiness. Its body is the same three lines the
// provider's refresh() ran before this component existed:
//
//     rpc_post(body_get_miner_data)  ->  parse_miner_data  ->  node::MinerData
//
// including the hex-string difficulty the daemon actually returns
// ("difficulty":"0x39d402"), which is decoded by the production parser rather
// than by a second copy of it here. That is deliberate: the whole value of the
// K-C4-1 KAT is that this arm IS the old path, so a template built through the
// seam is byte-identical to one built before it.
//
// WHY poll() IS NOT ON THE INTERFACE. IMinerDataSource::epoch() is pinned as a
// lock-free read the provider may call on every refresh; a network round trip
// cannot live behind it. So the RPC lives in poll(), a non-virtual method the
// provider drives through a pump function it is given at construction. The
// native arm needs no pump, which is exactly the difference the seam exists to
// hide from the assembler.
//
// THE REBUILD RULE IS THE OLD ONE, UNCHANGED. epoch() reports (height, prev_id)
// and a backlog_seq that is FROZEN AT ZERO, so a consumer comparing epochs takes
// exactly the decision the pre-seam code took: rebuild when the parent tip
// moves, never because the daemon's txpool grew. Nothing this arm can observe
// about the transaction set may become a new rebuild trigger -- that would
// restamp the header timestamp under miners already grinding the current bytes.
// The native arm's backlog sequence is ADDITIVE and opt-in; see its header.
//
// READINESS. The daemon is the authority on its own readiness: a get_miner_data
// that parsed and validated sets every flag, and a transport error or a refusal
// clears them all with the daemon's own words in `why`. There is deliberately
// no attempt to attribute a daemon failure to one of the six windows -- we do
// not know which one it was, and inventing an attribution would put a wrong
// reason in a log line that an operator will act on.
//
// SCOPE FENCE: src/impl/xmr/ only. No consensus digest, no src/sharechain/v37.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/native/contracts/miner_data.hpp"
#include "impl/xmr/node/monero_rpc.hpp"          // body_get_miner_data / parse_miner_data
#include "impl/xmr/node/monerod_transport.hpp"   // IMonerodTransport / RpcResponse

namespace c2pool::xmr::native::tmpl {

class MonerodMinerDataSource final : public IMinerDataSource {
public:
    explicit MonerodMinerDataSource(node::IMonerodTransport& transport)
        : tx_(transport) {}

    MonerodMinerDataSource(const MonerodMinerDataSource&)            = delete;
    MonerodMinerDataSource& operator=(const MonerodMinerDataSource&) = delete;

    const char* name() const override { return "monerod"; }

    // MAIN THREAD. One get_miner_data round trip; updates the cache on success
    // and leaves the previous cache untouched on failure (the provider decides
    // whether a stale-but-valid template may still be served, and it can only
    // decide that if the last good snapshot survives a transport blip).
    bool poll(std::string* why = nullptr) {
        node::MinerData md;
        std::string     err;
        bool            got = false;

        tx_.rpc_post(node::MoneroDaemonRpc::body_get_miner_data(),
                     [&](const node::RpcResponse& r) {
                         if (!r.ok()) { err = "transport: " + r.error; return; }
                         if (auto p = node::MoneroDaemonRpc::parse_miner_data(r.body)) {
                             md = *p; got = true;
                         } else {
                             err = "get_miner_data: parse/validate failed";
                         }
                     });

        if (!got) {
            set_error_(err.empty() ? "get_miner_data: no response" : err, why);
            return false;
        }
        if (!md.valid()) {
            set_error_("get_miner_data: invalid miner_data", why);
            return false;
        }

        std::lock_guard<std::mutex> lk(mtx_);
        cached_    = std::move(md);
        have_      = true;
        last_error_.clear();
        ++polls_;
        if (why) why->clear();
        return true;
    }

    MinerDataReadiness readiness() const override {
        MinerDataReadiness r;
        std::lock_guard<std::mutex> lk(mtx_);
        if (!have_) {
            r.why = last_error_.empty() ? "monerod: no miner data yet" : last_error_;
            return r;
        }
        // The daemon answered and the parser validated: every window it owns is
        // by construction the one it used. All six flags together, or none.
        r.tip_known = r.seed_reach = r.difficulty_window =
        r.weight_window = r.coins_known = r.hf_known = true;
        return r;
    }

    MinerDataEpoch epoch() const override {
        MinerDataEpoch e;
        std::lock_guard<std::mutex> lk(mtx_);
        if (!have_) return e;
        e.height  = cached_.height;
        e.prev_id = cached_.prev_id;
        // backlog_seq stays 0: THIS ARM REPORTS NO BACKLOG SEQUENCE.
        //
        // backlog_seq is an OPT-IN rebuild trigger. A consumer rebuilds when the
        // epoch moves, so any number reported here that moves under an unchanged
        // tip is a new rebuild trigger -- and this arm's rule is the one that
        // serves real miners today, which is (height, prev_id) and nothing else.
        // Reporting the backlog SIZE would have made every daemon txpool change
        // force a reassemble at the poll cadence, restamping the header timestamp
        // under miners who are already grinding those bytes ("Low diff") and
        // churning the retained template ring down to seconds of job history.
        // The daemon arm is the pre-seam path wrapped, and the pre-seam path
        // rebuilt on tip moves only; a frozen 0 keeps that rule EXACTLY.
        //
        // The native arm is additive: it may report a sequence, and only under
        // an explicit non-zero backlog_refresh_s policy (see
        // xmr_native_miner_data.hpp), which is opt-in and off by default.
        e.backlog_seq = 0;
        return e;
    }

    std::optional<node::MinerData> snapshot(std::string* why) const override {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!have_) {
            if (why) *why = last_error_.empty() ? "monerod: no miner data yet" : last_error_;
            return std::nullopt;
        }
        if (why) why->clear();
        return cached_;
    }

    // The daemon relays a found block from its OWN pool, so this arm holds no
    // bodies. C5's ARM A (levin fluffy push) is only reachable with a body
    // source; with this arm alone it is ARM B that delivers, by design.
    const std::vector<std::uint8_t>* tx_body(const Hash&) const override { return nullptr; }

    std::string   last_error() const { std::lock_guard<std::mutex> lk(mtx_); return last_error_; }
    std::uint64_t polls()      const { std::lock_guard<std::mutex> lk(mtx_); return polls_; }
    std::uint64_t failures()   const { std::lock_guard<std::mutex> lk(mtx_); return failures_; }

private:
    void set_error_(std::string e, std::string* why) {
        std::lock_guard<std::mutex> lk(mtx_);
        last_error_ = std::move(e);
        ++failures_;
        if (why) *why = last_error_;
    }

    node::IMonerodTransport& tx_;

    mutable std::mutex mtx_;
    node::MinerData    cached_{};
    bool               have_ = false;
    std::string        last_error_;
    std::uint64_t      polls_ = 0, failures_ = 0;
};

} // namespace c2pool::xmr::native::tmpl
