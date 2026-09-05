/*
 * This file is part of c2pool <https://github.com/frstrtr/c2pool>
 * Copyright (c) 2024-2026 The c2pool developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

// ===========================================================================
// src/impl/xmr/node/monero_zmq.hpp
//
// AUTHORED for c2pool (not ported). The monerod ZMQ-pub subscriber for the XMR
// lane. Subscribes to the three topics and forwards parsed events to an
// IMoneroNodeObserver. The zmq socket is behind IZmqSubscriber so this carries no
// libzmq / cppzmq dependency and is syntax-checkable in isolation.
//
// PATTERN PROVENANCE (topic set + dispatch; clean reimpl, NO lines copied):
//   SChernykh/p2pool v4.18 @ 128643114f9bea55bfdb95462eaeffa2e3f666bd
//     src/zmq_reader.cpp  set(zmq::sockopt::subscribe, "json-full-chain_main");
//                         set(..., "json-full-miner_data");
//                         set(..., "json-minimal-txpool_add");
//                         parse(): strcmp(topic,...) -> handle_tx /
//                         handle_miner_data / handle_chain_main /
//                         handle_monero_block_broadcast.
//     src/zmq_reader.h    class ZMQReader; the worker+monitor thread pattern,
//                         the TxMempoolData/MinerData/ChainMain scratch members.
//
//   v37 DELTAS:
//     * handle_monero_block_broadcast is DROPPED (it re-gossips a found Monero
//       block for the p2pool pool-model; v37 publishes only via submit_block).
//     * the transport thread + monitor are abstracted behind IZmqSubscriber so
//       the reader is unit-testable and loop-agnostic.
//     * the chain_main block id is NOT taken from the ZMQ payload (which carries
//       content, not the canonical id): it is either computed by the coin leg's
//       block-id hasher or correlated with the next miner_data.prev_id — exactly
//       p2pool's "data.id not filled in here, but c.id should be available".
// ===========================================================================
#pragma once

#include "xmr_node_observer.hpp"
#include "xmr_node_types.hpp"

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

namespace c2pool::xmr::node {

// The three ZMQ topics monerod publishes (monerod --zmq-pub tcp://...:18083).
inline constexpr const char* ZMQ_TOPIC_CHAIN_MAIN  = "json-full-chain_main";
inline constexpr const char* ZMQ_TOPIC_MINER_DATA  = "json-full-miner_data";
inline constexpr const char* ZMQ_TOPIC_TXPOOL_ADD  = "json-minimal-txpool_add";

// --- transport seam ---------------------------------------------------------
// Real build: a ZMQ_SUB socket on its own thread (cppzmq), with a monitor for
// connect/disconnect like p2pool's Monitor. Delivers each publication already
// split into (topic, json_body). A monerod pub frame is "topic:json"; the impl
// splits at the first ':' after the subscribed prefix.
class IZmqSubscriber {
public:
    virtual ~IZmqSubscriber() = default;
    using FrameCb = std::function<void(const std::string& topic, const char* body, std::size_t len)>;

    virtual bool connect(const std::string& endpoint) = 0; // e.g. tcp://127.0.0.1:18083
    virtual void subscribe(const std::string& topic) = 0;
    virtual void set_frame_handler(FrameCb cb) = 0;
    virtual void start() = 0;   // begin the receive loop (own thread)
    virtual void stop() = 0;
    virtual bool is_connected() const = 0;
};

// ===========================================================================
// MoneroZmqReader — wires the three subscriptions to the observer callbacks.
// ===========================================================================
class MoneroZmqReader {
public:
    MoneroZmqReader(IZmqSubscriber& sub, IMoneroNodeObserver& observer)
        : sub_(sub), observer_(observer) {}

    // Connect + subscribe to all three topics + start the loop. Returns false if
    // the initial connect fails (the real subscriber then auto-retries).
    bool start(const std::string& zmq_endpoint);
    void stop();
    bool is_connected() const { return sub_.is_connected(); }

private:
    // Frame dispatch (topic -> parse -> observer). Mirrors p2pool parse().
    void on_frame(const std::string& topic, const char* body, std::size_t len);

    IZmqSubscriber&      sub_;
    IMoneroNodeObserver& observer_;
};

} // namespace c2pool::xmr::node
