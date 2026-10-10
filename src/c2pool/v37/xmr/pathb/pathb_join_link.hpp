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
//   carriers  FC_GETCARRIER(ids, want_bodies) -> FC_CARRIER frames
//   buckets   FC_GETBUCKETS -> FC_BUCKETS frames (judged by the attempt's
//             assembly, one per (server, at))
// A reply frame above its buffer: DROP (no token); a reply frame that does
// not decode: refused + 1 strike for the server (the relay node applies it)
// and the request ends NotServed, so the attempt ends as non-service. No frame
// within the abandon timeout (P-53, restarted per frame; the transport's):
// NoReply.
// Fetch-ahead (C-10): as soon as a reply is complete the next request is
// sent: after the attempt's first FC_HEADERS reply (stop = the zero id) the
// page below the lowest received header (same max), and so on down the
// server's chain while pages come back; after an FC_GETCARRIER reply of
// consecutive positions of those pages, the next 1 + R_MAX positions not yet
// asked, and so on up to the top page. The attempt's later requests take
// what is already received (a headers request: the headers ending at its
// stop, at most its max; a carriers request: the bodies received, the rest
// asked); one request is in flight at a time; reset() at the attempt's end.
// FC_GETBUCKETS keeps to the server's P-42 window (FIX-1, BucketWindow): sent
// while at least one frame of the default P-42 is left in the window, else
// when the window has ended (the wait is not non-service).
// JoinTransport: the request / reply exchange and the clock (the relay
// node's; it runs on the join worker, its waits blocking there).
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <map>
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
    // The request frame to `peer` and the frames of its reply, each within
    // timeout_s of the one before; empty: no frame within the timeout.
    virtual std::vector<std::vector<std::uint8_t>> exchange(std::uint64_t peer, const std::vector<std::uint8_t>& request,
                                                            std::uint64_t timeout_s) = 0;
    virtual std::uint64_t now_s() const = 0;              // seconds
    virtual void wait_until(std::uint64_t t_s) = 0;       // the join worker waits
};

class PathbJoinLink final : public JoinLink {
public:
    PathbJoinLink(std::uint64_t peer, JoinTransport& t, std::uint32_t chain_id, const LaneParams& p,
                  const RelayBuffers& buffers, std::uint64_t headers_frame_bytes, const BucketWirePolicy& bucket_policy)
        : peer_(peer), t_(&t), chain_id_(chain_id), p_(p), buffers_(buffers), headers_frame_(headers_frame_bytes),
          window_(bucket_policy) {}

    std::uint64_t peer() const override { return peer_; }
    std::uint32_t strikes() const noexcept { return strikes_; }
    std::uint64_t requests() const noexcept { return requests_; }

    ChainHeaders headers(const Hash32& stop, std::uint64_t max, std::uint64_t timeout_s) override {
        if (std::optional<ChainHeaders> held = held_page(stop, max)) return std::move(*held);
        ChainHeaders r = ask_headers(stop, max, timeout_s);
        if (r.status != LinkStatus::Served) return r;
        keep_page(r, max, stop);
        if (stop == Hash32{}) chain_pages(r, max, timeout_s);  // the attempt's first reply: the pages below it
        return r;
    }

    CarrierFrames carriers(const std::vector<Hash32>& ids, bool want_bodies, std::uint64_t timeout_s) override {
        CarrierFrames r;
        std::vector<Hash32> missing;
        for (const Hash32& id : ids)
            if (!want_bodies || bodies_.count(id) == 0) missing.push_back(id);
        if (!missing.empty()) {
            const CarrierFrames got = ask_carriers(missing, want_bodies, timeout_s);
            if (got.status != LinkStatus::Served) return got;
            if (!want_bodies) return got;
            for (const CarrierBodyV3& b : got.bodies) bodies_.emplace(receipt_id(b.own), b);
            for (const Hash32& id : missing) asked_.insert(id);
        }
        r.status = LinkStatus::Served;
        for (const Hash32& id : ids) {
            const auto it = bodies_.find(id);
            if (it != bodies_.end()) r.bodies.push_back(it->second);
        }
        if (want_bodies) chain_bodies(ids, timeout_s);
        return r;
    }

    // The attempt ended: nothing it received is kept for the next one.
    void reset() {
        main_.clear();
        pos_of_.clear();
        page_cap_.reset();
        bodies_.clear();
        asked_.clear();
    }

    BucketFrames buckets(const GetBuckets& q, std::uint64_t timeout_s) override {
        BucketFrames r;
        const std::optional<std::vector<std::uint8_t>> f = encode_getbuckets(q);
        if (!f) return r;
        if (!window_.may_request(peer_, t_->now_s()))
            if (const std::optional<std::uint64_t> end = window_.window_end(peer_)) t_->wait_until(*end);
        window_.requested(peer_, t_->now_s());
        ++requests_;
        r.frames = t_->exchange(peer_, *f, timeout_s);
        for (const std::vector<std::uint8_t>& fr : r.frames) window_.received(peer_, fr.size(), t_->now_s());
        r.status = r.frames.empty() ? LinkStatus::NoReply : LinkStatus::Served;
        return r;
    }

private:
    // The pages of the server's chain received in this attempt (by position) and their ids.
    void keep_page(const ChainHeaders& r, std::uint64_t max, const Hash32& stop) {
        if (r.headers.empty() || r.first_pos == 0) return;
        const std::uint64_t top = r.first_pos + r.headers.size() - 1;
        if (stop != Hash32{} && !main_.empty()) {
            // a page joins the held pages only where its top's id is the parent named by the page above it
            const auto above = main_.find(top + 1);
            if (above == main_.end() || above->second.own.side.tip != stop) return;
        }
        if (r.headers.size() < std::min<std::uint64_t>(max, top))
            page_cap_ = std::min<std::uint64_t>(page_cap_.value_or(UINT64_MAX), r.headers.size());
        for (std::size_t i = 0; i < r.headers.size(); ++i) {
            const std::uint64_t x = r.first_pos + i;
            main_[x] = r.headers[i];
            pos_of_[receipt_id(r.headers[i].own)] = x;
        }
    }
    // The headers ending at `stop` (at most max; what one frame carried) when every one is held.
    std::optional<ChainHeaders> held_page(const Hash32& stop, std::uint64_t max) const {
        if (stop == Hash32{} || max == 0) return std::nullopt;
        const auto it = pos_of_.find(stop);
        if (it == pos_of_.end()) return std::nullopt;
        const std::uint64_t p = it->second;
        const std::uint64_t n = std::min<std::uint64_t>({max, p, page_cap_.value_or(UINT64_MAX)});
        ChainHeaders r;
        r.status = LinkStatus::Served;
        r.first_pos = p - n + 1;
        for (std::uint64_t x = r.first_pos; x <= p; ++x) {
            const auto h = main_.find(x);
            if (h == main_.end()) return std::nullopt;
            r.headers.push_back(h->second);
        }
        return r;
    }
    void chain_pages(const ChainHeaders& first, std::uint64_t max, std::uint64_t timeout_s) {
        std::uint64_t lo = first.first_pos;
        while (lo > 1) {
            const auto low = main_.find(lo);
            if (low == main_.end()) return;
            const Hash32 next = low->second.own.side.tip;
            const ChainHeaders r = ask_headers(next, max, timeout_s);
            if (r.status != LinkStatus::Served || r.headers.empty() || r.first_pos == 0 ||
                r.first_pos + r.headers.size() != lo)
                return;
            keep_page(r, max, next);
            if (main_.find(r.first_pos) == main_.end()) return;
            lo = r.first_pos;
        }
    }
    // After a reply to consecutive positions of the held pages: the next 1 + R_MAX positions not yet asked, one
    // request after the other, up to the top page.
    void chain_bodies(const std::vector<Hash32>& ids, std::uint64_t timeout_s) {
        std::optional<std::uint64_t> top;
        for (const Hash32& id : ids) {
            const auto it = pos_of_.find(id);
            if (it == pos_of_.end()) return;
            if (top && it->second != *top + 1) return;
            top = it->second;
        }
        if (!top) return;
        const std::size_t batch = static_cast<std::size_t>(1 + p_.r_max);
        std::uint64_t x = *top + 1;
        for (;;) {
            std::vector<Hash32> next;
            for (; next.size() < batch; ++x) {
                const auto it = main_.find(x);
                if (it == main_.end()) break;
                const Hash32 id = receipt_id(it->second.own);
                if (asked_.count(id) == 0 && bodies_.count(id) == 0) next.push_back(id);
            }
            if (next.empty()) return;
            const CarrierFrames r = ask_carriers(next, true, timeout_s);
            for (const Hash32& id : next) asked_.insert(id);
            if (r.status != LinkStatus::Served) return;
            for (const CarrierBodyV3& b : r.bodies) bodies_.emplace(receipt_id(b.own), b);
            if (r.bodies.size() < next.size()) return;
        }
    }

    ChainHeaders ask_headers(const Hash32& stop, std::uint64_t max, std::uint64_t timeout_s) {
        ChainHeaders r;
        const std::uint16_t m = static_cast<std::uint16_t>(std::min<std::uint64_t>(max, UINT16_MAX));
        ++requests_;
        const std::vector<std::vector<std::uint8_t>> fs =
                t_->exchange(peer_, encode_fc_getheaders(GetHeaders{chain_id_, Hash32{}, stop, m}), timeout_s);
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

    CarrierFrames ask_carriers(const std::vector<Hash32>& ids, bool want_bodies, std::uint64_t timeout_s) {
        CarrierFrames r;
        GetCarrier q;
        q.chain_id = chain_id_;
        q.ids = ids;
        q.want_bodies = want_bodies;
        const std::optional<std::vector<std::uint8_t>> req = encode_fc_getcarrier(q, p_);
        if (!req) return r;
        ++requests_;
        const std::vector<std::vector<std::uint8_t>> fs = t_->exchange(peer_, *req, timeout_s);
        for (const std::vector<std::uint8_t>& f : fs) {
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
    std::uint32_t strikes_ = 0;
    std::uint64_t requests_ = 0;
    std::map<std::uint64_t, CarrierHeader> main_;  // the server's chain from its pages, by position
    std::map<Hash32, std::uint64_t> pos_of_;
    std::optional<std::uint64_t> page_cap_;        // the headers one frame carried, where a page was cut by its frame
    std::map<Hash32, CarrierBodyV3> bodies_;       // bodies received in this attempt
    std::set<Hash32> asked_;                       // ids whose bodies were asked
    BucketWindow window_;
};

}  // namespace c2pool::xmr::pathb
