// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_join_link.hpp
// The JoinLink of a join attempt bound to the family-C frames of one server:
//   headers   FC_GETHEADERS(from = the zero id, stop, max) -> one FC_HEADERS
//             frame (u64 first_pos | u16 n | n x header)
//   carriers  FC_GETCARRIER(ids, want_bodies) -> at most n FC_CARRIER frames;
//             a body whose id was not asked is not kept
//   buckets   FC_GETBUCKETS -> FC_BUCKETS frames (judged by the attempt's
//             assembly, one per (server, at))
// A reply frame above its buffer: DROP (no token); a reply frame that does
// not decode: refused + 1 strike for the server (the relay node applies it)
// and the request ends NotServed, so the attempt ends as non-service. No frame
// within the abandon timeout (P-53, restarted per frame; the transport's):
// NoReply.
// Fetch-ahead: the attempt names its next FC_GETHEADERS / FC_GETCARRIER
// before it checks the reply it holds (next_headers / next_carriers); the link
// sends it at once and its next headers() / carriers() call with the same
// arguments takes the reply. One request outstanding; nothing is asked that
// the attempt did not name.
// FC_GETBUCKETS keeps to the server's P-42 window (FIX-1): the node's
// BucketWindow of that server (one window per server, shared with the node's
// own FC_GETBUCKETS): sent while at least one frame of the default P-42 is
// left, else when the window has ended (the wait is not non-service).
// JoinTransport: the requests and their replies (sent now, collected later)
// and the clock (the relay node's; the attempt's waits block the join worker).
// close(): the server disconnected; every later request has no reply.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include "impl/xmr/pathb/pathb_join.hpp"
#include "impl/xmr/pathb/pathb_relay_wire.hpp"

#include "c2pool/v37/xmr/pathb/pathb_timers.hpp"  // BucketWindow

namespace c2pool::xmr::pathb {

class JoinTransport {
public:
    virtual ~JoinTransport() = default;
    // Sends a request frame to `peer`; its reply is collected by `ticket`.
    virtual std::uint64_t send(std::uint64_t peer, const std::vector<std::uint8_t>& request) = 0;
    // The frames of the reply to `ticket`, each within timeout_s of the one
    // before (the first within timeout_s of the send); empty: no frame.
    virtual std::vector<std::vector<std::uint8_t>> collect(std::uint64_t ticket, std::uint64_t timeout_s) = 0;
    // A reply nobody will collect.
    virtual void drop(std::uint64_t ticket) = 0;
    virtual std::uint64_t now_s() const = 0;              // seconds
    virtual void wait_until(std::uint64_t t_s) = 0;       // the join worker waits
};

class PathbJoinLink final : public JoinLink {
public:
    PathbJoinLink(std::uint64_t peer, JoinTransport& t, std::uint32_t chain_id, const LaneParams& p,
                  const RelayBuffers& buffers, std::uint64_t headers_frame_bytes, BucketWindow& window)
        : peer_(peer), t_(&t), chain_id_(chain_id), p_(p), buffers_(buffers), headers_frame_(headers_frame_bytes),
          window_(&window) {}
    ~PathbJoinLink() override { reset(); }
    PathbJoinLink(const PathbJoinLink&) = delete;
    PathbJoinLink& operator=(const PathbJoinLink&) = delete;

    std::uint64_t peer() const override { return peer_; }
    std::uint32_t strikes() const noexcept { return strikes_; }
    std::uint64_t requests() const noexcept { return requests_; }
    // the replies of named requests taken: headers, carriers
    std::uint64_t ahead_headers_taken() const noexcept { return ahead_headers_; }
    std::uint64_t ahead_carriers_taken() const noexcept { return ahead_carriers_; }
    bool closed() const noexcept { return closed_; }

    // The server disconnected: no later request is sent (the attempt's next one has no reply).
    void close() {
        reset();
        closed_ = true;
    }
    // The attempt ended: a named request nobody took is dropped.
    void reset() {
        if (ahead_) t_->drop(ahead_->ticket);
        ahead_.reset();
    }

    void next_headers(const Hash32& stop, std::uint64_t max, std::uint64_t) override {
        reset();
        if (closed_) return;
        const std::uint16_t m = static_cast<std::uint16_t>(std::min<std::uint64_t>(max, UINT16_MAX));
        ++requests_;
        ahead_ = Ahead{Ahead::Kind::Headers, stop, m, {}, true,
                       t_->send(peer_, encode_fc_getheaders(GetHeaders{chain_id_, Hash32{}, stop, m}))};
    }
    void next_carriers(const std::vector<Hash32>& ids, bool want_bodies, std::uint64_t) override {
        reset();
        if (closed_) return;
        GetCarrier q;
        q.chain_id = chain_id_;
        q.ids = ids;
        q.want_bodies = want_bodies;
        const std::optional<std::vector<std::uint8_t>> req = encode_fc_getcarrier(q, p_);
        if (!req) return;
        ++requests_;
        ahead_ = Ahead{Ahead::Kind::Carriers, Hash32{}, 0, ids, want_bodies, t_->send(peer_, *req)};
    }

    ChainHeaders headers(const Hash32& stop, std::uint64_t max, std::uint64_t timeout_s) override {
        const std::uint16_t m = static_cast<std::uint16_t>(std::min<std::uint64_t>(max, UINT16_MAX));
        std::optional<std::uint64_t> ticket;
        if (ahead_ && ahead_->kind == Ahead::Kind::Headers && ahead_->stop == stop && ahead_->max == m) {
            ticket = ahead_->ticket;
            ahead_.reset();
            ++ahead_headers_;
        } else {
            reset();
            if (closed_) return ChainHeaders{};
            ++requests_;
            ticket = t_->send(peer_, encode_fc_getheaders(GetHeaders{chain_id_, Hash32{}, stop, m}));
        }
        return read_headers(t_->collect(*ticket, timeout_s));
    }

    CarrierFrames carriers(const std::vector<Hash32>& ids, bool want_bodies, std::uint64_t timeout_s) override {
        std::optional<std::uint64_t> ticket;
        if (ahead_ && ahead_->kind == Ahead::Kind::Carriers && ahead_->ids == ids && ahead_->want == want_bodies) {
            ticket = ahead_->ticket;
            ahead_.reset();
            ++ahead_carriers_;
        } else {
            reset();
            if (closed_) return CarrierFrames{};
            GetCarrier q;
            q.chain_id = chain_id_;
            q.ids = ids;
            q.want_bodies = want_bodies;
            const std::optional<std::vector<std::uint8_t>> req = encode_fc_getcarrier(q, p_);
            if (!req) return CarrierFrames{};
            ++requests_;
            ticket = t_->send(peer_, *req);
        }
        return read_carriers(t_->collect(*ticket, timeout_s), ids);
    }

    BucketFrames buckets(const GetBuckets& q, std::uint64_t timeout_s) override {
        BucketFrames r;
        reset();
        if (closed_) return r;
        const std::optional<std::vector<std::uint8_t>> f = encode_getbuckets(q);
        if (!f) return r;
        if (!window_->may_request(peer_, t_->now_s()))
            if (const std::optional<std::uint64_t> end = window_->window_end(peer_)) t_->wait_until(*end);
        if (closed_) return r;
        window_->requested(peer_, t_->now_s());
        ++requests_;
        r.frames = t_->collect(t_->send(peer_, *f), timeout_s);
        for (const std::vector<std::uint8_t>& fr : r.frames) window_->received(peer_, fr.size(), t_->now_s());
        r.status = r.frames.empty() ? LinkStatus::NoReply : LinkStatus::Served;
        return r;
    }

private:
    struct Ahead {
        enum class Kind : std::uint8_t { Headers, Carriers } kind = Kind::Headers;
        Hash32 stop{};
        std::uint16_t max = 0;
        std::vector<Hash32> ids;
        bool want = true;
        std::uint64_t ticket = 0;
    };

    // One FC_HEADERS frame answers the request: the first within the buffer; the rest is not read.
    ChainHeaders read_headers(const std::vector<std::vector<std::uint8_t>>& fs) {
        ChainHeaders r;
        for (const std::vector<std::uint8_t>& f : fs) {
            if (f.size() > headers_frame_) continue;  // DROP: above the buffer
            HeadersReply rep;
            if (!decode_fc_headers(f, chain_id_, headers_frame_, p_, rep).ok()) {
                ++strikes_;  // refused + 1 strike; the request ends
                r.status = LinkStatus::NotServed;
                return r;
            }
            r.status = LinkStatus::Served;
            r.first_pos = rep.first_pos;
            r.headers = std::move(rep.headers);
            return r;
        }
        return r;  // NoReply
    }

    // At most n FC_CARRIER frames answer n ids; a body whose id was not asked, or asked and already given, is not
    // kept; the frames beyond n are not read.
    CarrierFrames read_carriers(const std::vector<std::vector<std::uint8_t>>& fs, const std::vector<Hash32>& ids) {
        CarrierFrames r;
        std::set<Hash32> want(ids.begin(), ids.end());
        std::size_t read = 0;
        for (const std::vector<std::uint8_t>& f : fs) {
            if (read >= ids.size()) break;  // beyond the request: not read
            ++read;
            if (f.size() > buffers_.frame) continue;  // DROP: above the buffer
            CarrierBodyV3 c;
            if (!check_fc_carrier(f, chain_id_, buffers_).ok()
                || decode_carrier_body_v3(f.data() + kFrameHeaderBytes, f.size() - kFrameHeaderBytes,
                                          CarrierLimits{buffers_.receipt, p_.r_max}, c)
                           != WireError::None) {
                ++strikes_;  // refused + 1 strike; the request ends
                r.status = LinkStatus::NotServed;
                r.bodies.clear();
                return r;
            }
            if (want.erase(receipt_id(c.own)) == 0) continue;  // not asked (or a second copy): not kept
            r.bodies.push_back(std::move(c));
        }
        r.status = fs.empty() ? LinkStatus::NoReply : LinkStatus::Served;
        return r;
    }

    std::uint64_t peer_;
    JoinTransport* t_;
    std::uint32_t chain_id_;
    LaneParams p_;
    RelayBuffers buffers_;
    std::uint64_t headers_frame_;
    BucketWindow* window_;
    std::uint32_t strikes_ = 0;
    std::uint64_t requests_ = 0;
    std::uint64_t ahead_headers_ = 0;
    std::uint64_t ahead_carriers_ = 0;
    bool closed_ = false;
    std::optional<Ahead> ahead_;  // the one request outstanding
};

}  // namespace c2pool::xmr::pathb
