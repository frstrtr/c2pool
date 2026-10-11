// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/test/xmr_pathb_relay_test_util.hpp
// Helpers of the relay KATs on the Path B relay node (pathb_relay_node.hpp):
//   Checker        the check harness
//   SynthBlock     a synthetic, byte-exact Monero block (header | miner_tx |
//                  tx hashes) and its id, for the context frames
//   Rig / RNode    Path B relay nodes over loopback TCP (CarrierLinks), each
//                  with its own PathbNode on the rig's regtest raw genesis
//                  (pathb_kat_node.hpp's Monero chain and keys), a RandomX
//                  stub per node, the node's log; its carriers, jobs and
//                  receipt bodies; its HELLO bytes for a raw peer
//   CountingLinks  CarrierLinks that counts the frames it delivers, by opcode,
//                  and shows each to a tap
// Test-only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "c2pool/v37/xmr/pathb/pathb_relay_links.hpp"
#include "c2pool/v37/xmr/pathb/pathb_relay_node.hpp"
#include "c2pool/v37/xmr/relay/xmr_relay_native_ctx.hpp"
#include "impl/xmr/coin/xmr_blob.hpp"
#include "impl/xmr/pathb/test/pathb_kat_node.hpp"

namespace pathb_relay_test {

using namespace c2pool::v37n::xmr::relay;  // u8 / u32 / u64 / bytes32, the kept frames, the context module
namespace pb = ::c2pool::xmr::pathb;
namespace pk = ::pathb_kat;

// ---------------------------------------------------------------------------
// The check harness
// ---------------------------------------------------------------------------
struct Checker {
    int pass = 0, fail = 0;
    void operator()(bool ok, const std::string& what) {
        if (ok)
            ++pass;
        else
            ++fail;
        std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
        std::fflush(stdout);
    }
    int done(const char* name) const {
        std::printf("== %s: %s (%d/%d passed) ==\n", name, fail ? "FAIL" : "OK", pass, pass + fail);
        return fail ? 1 : 0;
    }
};

template <class F>
inline bool wait_until(F cond, std::chrono::milliseconds limit, std::chrono::milliseconds step = std::chrono::milliseconds(20)) {
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        if (cond()) return true;
        std::this_thread::sleep_for(step);
    }
    return cond();
}

inline std::string hex(const std::vector<u8>& v) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (u8 b : v) {
        s.push_back(d[b >> 4]);
        s.push_back(d[b & 15]);
    }
    return s;
}
inline std::string hex(const bytes32& v) { return hex(std::vector<u8>(v.begin(), v.end())); }

// ---------------------------------------------------------------------------
// A synthetic Monero block
// ---------------------------------------------------------------------------
inline void put_varint(std::vector<u8>& b, std::uint64_t v) {
    while (v >= 0x80) {
        b.push_back(static_cast<u8>((v & 0x7f) | 0x80));
        v >>= 7;
    }
    b.push_back(static_cast<u8>(v));
}

inline bytes32 b32_of(u8 seed) {
    bytes32 b{};
    for (int i = 0; i < 32; ++i) b[i] = static_cast<u8>(seed * 31 + i * 7 + 1);
    return b;
}

struct SynthBlock {
    std::vector<u8> full_blob;     // header | miner_tx | varint n | n hashes   (nonce field = 0)
    std::vector<u8> hashing_blob;  // header | tree_root | varint(n+1)         (nonce field = 0)
    std::size_t nonce_offset = 0;
    bytes32 prev_id{};
    std::uint64_t height = 0;
};

// The coinbase tx_extra: 0x01 R | 0x02 [extra_nonce | nonce_tail (when given) | 3 zero bytes | 'V37C' | 8 bytes | 32
// bytes] | 0x03 0x21 0x00 [32 bytes]; n_other_tx transaction hashes.
inline SynthBlock make_block(std::uint64_t height, const bytes32& prev_id, std::uint32_t extra_nonce,
                             const bytes32* nonce_tail, std::size_t n_other_tx, u8 salt) {
    SynthBlock sb;
    sb.prev_id = prev_id;
    sb.height = height;
    std::vector<u8> hdr;
    put_varint(hdr, 16);
    put_varint(hdr, 16);
    put_varint(hdr, 1700000000ull + height);
    hdr.insert(hdr.end(), prev_id.begin(), prev_id.end());
    sb.nonce_offset = hdr.size();
    for (int i = 0; i < 4; ++i) hdr.push_back(0);
    std::vector<u8> pre;
    put_varint(pre, 2);
    put_varint(pre, height + 60);
    put_varint(pre, 1);
    pre.push_back(0xff);
    put_varint(pre, height);
    put_varint(pre, 1);
    put_varint(pre, 600000000000ull + salt);
    pre.push_back(0x03);
    const bytes32 k = b32_of(static_cast<u8>(salt + 3));
    pre.insert(pre.end(), k.begin(), k.end());
    pre.push_back(0x5a);
    std::vector<u8> extra;
    extra.push_back(0x01);
    {
        const bytes32 R = b32_of(static_cast<u8>(salt + 9));
        extra.insert(extra.end(), R.begin(), R.end());
    }
    std::vector<u8> nonce;
    for (int i = 0; i < 4; ++i) nonce.push_back(static_cast<u8>(extra_nonce >> (8 * i)));
    if (nonce_tail) nonce.insert(nonce.end(), nonce_tail->begin(), nonce_tail->end());
    for (int i = 0; i < 3; ++i) nonce.push_back(0);
    const char tail[4] = {'V', '3', '7', 'C'};
    nonce.insert(nonce.end(), tail, tail + 4);
    for (int i = 0; i < 8; ++i) nonce.push_back(static_cast<u8>(i + 1));
    {
        const bytes32 sp = b32_of(static_cast<u8>(salt + 17));
        nonce.insert(nonce.end(), sp.begin(), sp.end());
    }
    extra.push_back(0x02);
    put_varint(extra, nonce.size());
    extra.insert(extra.end(), nonce.begin(), nonce.end());
    extra.push_back(0x03);
    extra.push_back(0x21);
    extra.push_back(0x00);
    {
        const bytes32 mm = b32_of(static_cast<u8>(salt + 23));
        extra.insert(extra.end(), mm.begin(), mm.end());
    }
    put_varint(pre, extra.size());
    pre.insert(pre.end(), extra.begin(), extra.end());
    std::vector<::xmr::coin::Hash256> leaves;
    leaves.push_back(::xmr::coin::coinbase_tx_hash(::xmr::coin::tx_prefix_hash(pre)));
    std::vector<bytes32> others;
    for (std::size_t i = 0; i < n_other_tx; ++i) {
        const bytes32 h = b32_of(static_cast<u8>(salt + 40 + i));
        others.push_back(h);
        ::xmr::coin::Hash256 hh;
        std::memcpy(hh.data(), h.data(), 32);
        leaves.push_back(hh);
    }
    const auto root = ::xmr::coin::tree_root(leaves);
    sb.full_blob = hdr;
    sb.full_blob.insert(sb.full_blob.end(), pre.begin(), pre.end());
    sb.full_blob.push_back(0x00);  // rct_type RCTTypeNull
    put_varint(sb.full_blob, others.size());
    for (const auto& h : others) sb.full_blob.insert(sb.full_blob.end(), h.begin(), h.end());
    sb.hashing_blob = hdr;
    sb.hashing_blob.insert(sb.hashing_blob.end(), root.data(), root.data() + 32);
    put_varint(sb.hashing_blob, leaves.size());
    return sb;
}

// The block id: keccak256(varint(len) | hashing_blob).
inline bytes32 block_id(const SynthBlock& sb) {
    std::vector<u8> pre;
    put_varint(pre, sb.hashing_blob.size());
    pre.insert(pre.end(), sb.hashing_blob.begin(), sb.hashing_blob.end());
    const auto h = ::xmr::coin::keccak256(pre.data(), pre.size());
    bytes32 b;
    std::memcpy(b.data(), h.data(), 32);
    return b;
}

inline std::vector<u8> with_nonce(const SynthBlock& sb, std::uint32_t nonce) {
    std::vector<u8> h = sb.hashing_blob;
    for (int i = 0; i < 4; ++i) h[sb.nonce_offset + i] = static_cast<u8>(nonce >> (8 * i));
    return h;
}

// ---------------------------------------------------------------------------
// CarrierLinks that counts the frames it delivers to the relay node, by opcode
// ---------------------------------------------------------------------------
class CountingLinks final : public pb::RelayLinks {
public:
    using Tap = std::function<void(std::uint64_t peer, const std::vector<std::uint8_t>& frame)>;
    pb::CarrierLinks& inner() noexcept { return in_; }
    ::c2pool::v37n::CarrierPeerNode& net() noexcept { return in_.net(); }
    std::uint64_t frames(u8 op) const noexcept { return n_[op].load(); }
    // Sees every frame before the relay node does (set before start()).
    void set_tap(Tap t) { tap_ = std::move(t); }

    void bind(FrameFn frame, FrameFn control, EventFn event) override {
        in_.bind(
                [this, frame = std::move(frame)](std::uint64_t p, const std::vector<std::uint8_t>& f) {
                    if (!f.empty()) n_[f[0]]++;
                    if (tap_) tap_(p, f);
                    frame(p, f);
                },
                std::move(control), std::move(event));
    }
    void configure(const pb::PathbRelayOptions& o) override { in_.configure(o); }
    bool listen(const std::string& host, std::uint16_t port) override { return in_.listen(host, port); }
    std::uint16_t listen_port() const override { return in_.listen_port(); }
    std::uint64_t dial(const std::string& host, std::uint16_t port) override { return in_.dial(host, port); }
    bool send_to(std::uint64_t p, const std::vector<std::uint8_t>& f) override { return in_.send_to(p, f); }
    void disconnect(std::uint64_t p) override { in_.disconnect(p); }
    void ban_key(std::uint64_t key, std::uint32_t seconds) override { in_.ban_key(key, seconds); }
    bool is_banned_key(std::uint64_t key) override { return in_.is_banned_key(key); }
    std::uint64_t addr_key(std::uint64_t p) const override { return in_.addr_key(p); }
    bool is_inbound(std::uint64_t p) const override { return in_.is_inbound(p); }
    bool has_peer(std::uint64_t p) const override { return in_.has_peer(p); }
    std::vector<std::uint64_t> peer_ids() const override { return in_.peer_ids(); }
    std::size_t conns_from(std::uint64_t key) const override { return in_.conns_from(key); }
    std::string remote_ip(std::uint64_t p) const override { return in_.remote_ip(p); }
    std::size_t n_peers() const override { return in_.n_peers(); }
    void stop() override { in_.stop(); }

private:
    pb::CarrierLinks in_;
    std::array<std::atomic<std::uint64_t>, 256> n_{};
    Tap tap_;
};

// ---------------------------------------------------------------------------
// Path B relay nodes
// ---------------------------------------------------------------------------
using RxFn = std::function<bool(const pb::HashingBlob&, std::uint64_t d, const pb::Hash32& seed)>;

// The blob's nonce (the share's 4 bytes).
inline std::uint32_t nonce_of(const pb::HashingBlob& b) { return b.nonce; }

struct RNode {
    std::string name;
    CountingLinks links;
    std::unique_ptr<pb::PathbNode> node;
    std::unique_ptr<pb::PathbRelayNode> relay;
    std::atomic<std::uint64_t> rx_calls{0};
    RxFn rx;  // the RandomX stub (unset: every hash meets d); set before start()
    // The node's PathbNodeIo::fetch_context as the relay binds it (a Monero block from the own source or a peer).
    std::function<bool(const pb::Hash32& id, std::uint64_t timeout_s)> fetch_context;
    mutable std::mutex lmtx;
    std::vector<std::string> logs;

    explicit RNode(std::string n) : name(std::move(n)) {}
    RNode(const RNode&) = delete;
    RNode& operator=(const RNode&) = delete;
    ~RNode() {
        if (relay) relay->stop();
    }

    pb::PathbRelayNode& r() { return *relay; }
    const pb::PathbRelayStats& st() const { return relay->stats(); }
    bool start() {
        std::string why;
        return start(why);
    }
    bool start(std::string& why) { return relay->start(why); }
    std::uint16_t port() const { return links.listen_port(); }
    std::size_t count_logs(const std::string& needle) const {
        std::lock_guard<std::mutex> lk(lmtx);
        std::size_t n = 0;
        for (const auto& l : logs) n += l.find(needle) != std::string::npos ? 1 : 0;
        return n;
    }
    std::string first_log(const std::string& needle) const {
        std::lock_guard<std::mutex> lk(lmtx);
        for (const auto& l : logs)
            if (l.find(needle) != std::string::npos) return l;
        return {};
    }
    void dump_logs(std::size_t max = 40) const {
        std::lock_guard<std::mutex> lk(lmtx);
        for (std::size_t i = 0; i < logs.size() && i < max; ++i) std::printf("    [%s] %s\n", name.c_str(), logs[i].c_str());
    }
    // This node's Path B HELLO with another node nonce and listen port (a raw peer's HELLO).
    std::vector<u8> hello_bytes(std::uint64_t nonce, std::uint16_t listen_port) {
        const pb::PathbHello h = relay->with_node([&](pb::PathbNode& n) { return n.our_hello(nonce, listen_port); });
        return pb::encode_pathb_hello(h).value_or(std::vector<u8>{});
    }
    pb::Hash32 best() {
        return relay->with_node([](pb::PathbNode& n) { return n.tree().best().id; });
    }
    std::uint64_t best_pos() {
        return relay->with_node([](pb::PathbNode& n) { return n.tree().best().pos; });
    }
    std::size_t pending_size() {
        return relay->with_node([](pb::PathbNode& n) { return n.pending().size(); });
    }
    bool pending_holds(const pb::Hash32& id) {
        return relay->with_node([&](pb::PathbNode& n) { return n.pending().holds(id); });
    }
};

struct Rig {
    pk::KatNet net;  // the Monero chain, the key references, the pool identity
    pk::Harness h;
    std::atomic<std::uint64_t> mon_tip;
    pb::Hash32 other_pool = pk::seq32(0x77);

    Rig() : h(net), mon_tip(h.mon_tip) {}
    Rig(const Rig&) = delete;
    Rig& operator=(const Rig&) = delete;

    // The relay options of a loopback node: listen on an ephemeral port when `listen`; dial `dial`.
    static pb::PathbRelayOptions opts(bool listen, const std::vector<std::uint16_t>& dial = {}) {
        pb::PathbRelayOptions o;
        o.listen = listen;
        o.listen_host = "127.0.0.1";
        o.listen_port = 0;
        for (std::uint16_t p : dial) o.peers.emplace_back("127.0.0.1", p);
        o.hello_timeout_ms = 3000;
        return o;
    }

    // A relay node with its own PathbNode: `launch` builds templates with no Path B peer; `other_pool` names
    // another pool identity (TAG_MISMATCH at HELLO).
    std::unique_ptr<RNode> make(std::string name, pb::PathbRelayOptions o, bool launch = false, bool another_pool = false) {
        auto n = std::make_unique<RNode>(std::move(name));
        RNode* rn = n.get();
        n->relay = std::make_unique<pb::PathbRelayNode>(std::move(o), n->links, pb::RelayClock::system(),
                                                        [rn](const std::string& l) {
                                                            std::lock_guard<std::mutex> lk(rn->lmtx);
                                                            rn->logs.push_back(l);
                                                        });
        pb::PathbNodeIo io = h.io(h.nodes.size());
        io.verify = [rn](const pb::HashingBlob& b, std::uint64_t d, const pb::Hash32& seed) {
            ++rn->rx_calls;
            return rn->rx ? rn->rx(b, d, seed) : true;
        };
        io.monero_tip = [this]() -> std::optional<std::uint64_t> { return mon_tip.load(); };
        pb::PathbNodeConfig c = h.config(pk::kat_table(net), launch);
        if (another_pool) c.identity.pool_id = other_pool;
        pb::PathbNodeIo bound = n->relay->bind_io(std::move(io));
        n->fetch_context = bound.fetch_context;
        n->node = std::make_unique<pb::PathbNode>(c, std::move(bound));
        n->relay->attach(*n->node);
        return n;
    }

    void tick_monero(std::uint64_t by = 1) { mon_tip = std::min<std::uint64_t>(mon_tip.load() + by, pk::kMonTop); }

    // A job of node n for payee k on its best tip (none: no template).
    std::optional<pb::PathbJob> job(RNode& n, std::size_t payee, std::uint32_t extra_nonce = 0) {
        return n.r().with_node([&](pb::PathbNode& pn) -> std::optional<pb::PathbJob> {
            const pb::PathbTemplate t = pn.make_template(h.now);
            if (t.status != pb::TemplateStatus::Ok) return std::nullopt;
            return pn.make_job(t, h.session(payee, extra_nonce));
        });
    }
    // Node n's share of `job` with nonce `nonce` (its own hash: zero meets any d).
    pb::NodeEventResult share(RNode& n, const pb::PathbJob& j, std::uint32_t nonce) {
        return n.r().with_node([&](pb::PathbNode& pn) { return pn.on_own_share(j, nonce, pb::Hash32{}); });
    }
    // Node n mines one carrier on its best tip (Placed: flooded to its peers).
    pb::NodeEventResult mine(RNode& n, std::size_t payee, std::uint32_t nonce) {
        const std::optional<pb::PathbJob> j = job(n, payee, nonce);
        if (!j) return pb::NodeEventResult{};
        return share(n, *j, nonce);
    }
};

// The receipt body of `job` with nonce `nonce` (its id: receipt_id).
inline pb::ReceiptBodyV3 body_of(const pb::PathbJob& j, std::uint32_t nonce) {
    pb::ReceiptBodyV3 r = j.body;
    r.blob.nonce = nonce;
    return r;
}

}  // namespace pathb_relay_test
