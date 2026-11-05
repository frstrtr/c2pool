// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_relay_links.hpp
// CarrierLinks: the RelayLinks of PathbRelayNode over the shared carrier
// transport (carrier_net.hpp, CarrierPeerNode, used as it is): [u32 len][frame]
// TCP links, one reader thread per link, the per-link async send queue,
// address bans, the inbound limits (in total and per address) and the bounded
// connect of a discovery dial.
//
// Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "c2pool/v37/carrier_net.hpp"
#include "c2pool/v37/xmr/pathb/pathb_relay_node.hpp"

namespace c2pool::xmr::pathb {

class CarrierLinks final : public RelayLinks {
public:
    CarrierLinks() = default;
    CarrierLinks(const CarrierLinks&) = delete;
    CarrierLinks& operator=(const CarrierLinks&) = delete;

    // The transport itself (its ban clock, its counters; tests).
    ::c2pool::v37n::CarrierPeerNode& net() noexcept { return net_; }

    void bind(FrameFn frame, FrameFn control, EventFn event) override {
        net_.set_inbound_from([frame = std::move(frame)](std::uint64_t p, const std::vector<std::uint8_t>& f) { frame(p, f); });
        net_.set_control([control = std::move(control)](std::uint64_t p, const std::vector<std::uint8_t>& f) { control(p, f); });
        net_.set_on_peer_event([event = std::move(event)](std::uint64_t p, bool up) { event(p, up); });
    }
    void configure(const PathbRelayOptions& o) override {
        net_.set_send_queue(o.send_queue_bytes);
        net_.set_inbound_limits(o.max_inbound, o.max_inbound_per_addr);
        if (o.discovery && o.connect_timeout_ms != 0) net_.set_connect_timeout(std::chrono::milliseconds(o.connect_timeout_ms));
    }
    bool listen(const std::string& host, std::uint16_t port) override { return net_.listen(host, port); }
    std::uint16_t listen_port() const override { return net_.listen_port(); }
    std::uint64_t dial(const std::string& host, std::uint16_t port) override { return net_.add_peer_id(host, port); }
    bool send_to(std::uint64_t p, const std::vector<std::uint8_t>& f) override { return net_.send_to(p, f); }
    void disconnect(std::uint64_t p) override { net_.disconnect(p); }
    void ban_key(std::uint64_t key, std::uint32_t seconds) override { (void)net_.ban_key(key, std::chrono::seconds(seconds)); }
    bool is_banned_key(std::uint64_t key) override { return net_.is_banned_key(key); }
    std::uint64_t addr_key(std::uint64_t p) const override { return net_.addr_key(p); }
    bool is_inbound(std::uint64_t p) const override { return net_.is_inbound(p); }
    bool has_peer(std::uint64_t p) const override { return net_.has_peer(p); }
    std::vector<std::uint64_t> peer_ids() const override { return net_.peer_ids(); }
    std::size_t conns_from(std::uint64_t key) const override { return net_.conns_from(key); }
    std::string remote_ip(std::uint64_t p) const override { return net_.remote_ip(p); }
    std::size_t n_peers() const override { return net_.n_peers(); }
    void stop() override { net_.stop(); }
    std::size_t queued_bytes(std::uint64_t p) const override { return net_.queued_bytes(p); }
    std::size_t send_queue_limit() const override { return net_.send_queue_limit(); }
    std::uint64_t queue_full_drops() const override { return net_.peers_dropped_queue_full(); }

private:
    ::c2pool::v37n::CarrierPeerNode net_;
};

}  // namespace c2pool::xmr::pathb
