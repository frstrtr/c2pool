// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/fakes/fake_ports.hpp
//
// Compiling fakes for the remaining four interfaces: IBroadcastPort (C1 out),
// IMinerDataSource (the C4 seam), IBlockRelay (C5) and IParityOracle (C6).
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "../broadcast.hpp"
#include "../miner_data.hpp"
#include "../relay.hpp"
#include "../parity.hpp"

namespace c2pool::xmr::native::fakes {

// ---------------------------------------------------------------------------
class FakeBroadcastPort final : public IBroadcastPort {
public:
    struct Frame { std::uint32_t cmd; std::vector<std::uint8_t> bytes; };
    struct Unicast { PeerRef peer; std::uint32_t cmd; std::vector<std::uint8_t> bytes; };

    std::vector<Frame>   broadcasts;
    std::vector<Unicast> unicasts;
    FluffyMissingHandler fluffy_handler;

    // How many state_normal peers the fake claims to have written to.
    std::size_t state_normal_peers = 0;
    std::map<std::uint32_t, std::size_t> asn_table;

    std::size_t broadcast_notify(std::uint32_t cmd, std::vector<std::uint8_t> frame) override {
        broadcasts.push_back({cmd, std::move(frame)});
        return state_normal_peers;
    }
    bool send_notify(const PeerRef& p, std::uint32_t cmd, std::vector<std::uint8_t> frame) override {
        unicasts.push_back({p, cmd, std::move(frame)});
        return true;
    }
    void set_fluffy_missing_handler(FluffyMissingHandler h) override {
        fluffy_handler = std::move(h);
    }
    std::size_t peer_count() const override { return state_normal_peers; }
    std::map<std::uint32_t, std::size_t> peers_by_asn() const override { return asn_table; }
};

// ---------------------------------------------------------------------------
class FakeMinerDataSource final : public IMinerDataSource {
public:
    explicit FakeMinerDataSource(const char* nm = "fake") : name_(nm) {}

    MinerDataReadiness ready{};
    MinerDataEpoch     ep{};
    std::optional<node::MinerData> data;
    std::map<std::string, std::vector<std::uint8_t>> bodies;

    const char* name() const override { return name_; }

    MinerDataReadiness readiness() const override { return ready; }
    MinerDataEpoch     epoch() const override { return ep; }

    std::optional<node::MinerData> snapshot(std::string* why) const override {
        if (!ready.ok()) {
            if (why) *why = ready.why.empty() ? "not ready" : ready.why;
            return std::nullopt;
        }
        if (!data && why) *why = "no data";
        return data;
    }

    const std::vector<std::uint8_t>* tx_body(const Hash& id) const override {
        const auto it = bodies.find(std::string(reinterpret_cast<const char*>(id.data()), id.size()));
        return it == bodies.end() ? nullptr : &it->second;
    }

    void make_ready() {
        ready.tip_known = ready.seed_reach = ready.difficulty_window = true;
        ready.weight_window = ready.coins_known = ready.hf_known = true;
        ready.why.clear();
    }

private:
    const char* name_;
};

// ---------------------------------------------------------------------------
class FakeBlockRelay final : public IBlockRelay {
public:
    std::vector<BlockRelayRequest> relayed;

    // Canned arm behaviour.
    bool        daemon_armed    = true;
    bool        daemon_accepts  = true;
    std::size_t p2p_peers       = 0;

    BlockRelayVerdict relay(const BlockRelayRequest& req) override {
        relayed.push_back(req);
        BlockRelayVerdict v;
        v.block_id        = req.block_id;
        v.daemon_armed    = daemon_armed;
        v.daemon_accepted = daemon_armed && daemon_accepts;
        v.daemon_rejected = daemon_armed && !daemon_accepts;
        v.p2p_peers_sent  = p2p_peers;
        if (v.daemon_accepted)      v.landed_first = "daemon";
        else if (v.p2p_peers_sent)  v.landed_first = "p2p";
        // Never a silent drop: a verdict that reached nobody must say why.
        if (!v.reached_network())
            v.why = "no state_normal peer and no accepting daemon arm";
        return v;
    }

    bool on_request_fluffy_missing_tx(const Hash&,
                                      const std::vector<std::uint64_t>&,
                                      std::vector<std::uint8_t>& reply_frame) override {
        reply_frame.assign(4, 0x00);
        return true;
    }
};

// ---------------------------------------------------------------------------
class FakeParityOracle final : public IParityOracle {
public:
    std::vector<ParitySample> samples;
    GraduationState           g = GraduationState::Observing;
    ParityCoverage            cov{};
    std::string               revoked_why;

    void on_tip(const node::MainchainEvent& ev, const char* side) override {
        ParitySample s;
        s.kind    = ProbeKind::Tip;
        s.height  = ev.block.height;
        s.prev_id = ev.block.prev_id;
        s.verdict = ParityVerdict::Clean;
        s.note    = side ? side : "";
        record(s);
    }

    void on_serve(const MinerDataEpoch& e, const char* served_arm) override {
        ParitySample s;
        s.kind    = ProbeKind::Template;
        s.height  = e.height;
        s.prev_id = e.prev_id;
        s.verdict = ParityVerdict::Clean;
        s.note    = served_arm ? served_arm : "";
        record(s);
    }

    void on_submit(const Hash&, bool daemon_accepted, std::size_t p2p_peers_sent) override {
        ParitySample s;
        s.kind    = ProbeKind::Submit;
        // Coverage is a measurement: a submit nobody could judge is Void, and
        // Void never counts as agreement.
        s.verdict = (daemon_accepted || p2p_peers_sent) ? ParityVerdict::Clean
                                                        : ParityVerdict::Void;
        record(s);
    }

    GraduationState state() const override { return g; }
    ParityCoverage  coverage() const override { return cov; }

    void revoke(const std::string& why) override {
        g = GraduationState::Revoked;
        revoked_why = why;
    }

private:
    void record(const ParitySample& s) {
        samples.push_back(s);
        ++cov.samples;
        switch (s.verdict) {
            case ParityVerdict::Clean:          ++cov.clean; break;
            case ParityVerdict::Fail:           ++cov.fail; break;
            case ParityVerdict::ServedMismatch: ++cov.served_mismatch; break;
            case ParityVerdict::Void:           ++cov.voided; break;
        }
        cov.no_samples_streak = 0;
    }
};

} // namespace c2pool::xmr::native::fakes
