// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_dos_dup_block_kat.cpp
//
// D3a: the block DoS bucket must not score honest relay of VALID blocks as a
// flood, and must still score everything else exactly as before.
//
// THE FAILURE THIS PINS. Under a fast block cadence (regtest bursts of ~1
// block/s) every monerod the node is connected to relays every block to it:
// one link delivers the copy that connects, every other link delivers a
// duplicate of a block the node already has. Every one of those pushes was
// charged to that link's 8-token block bucket (refill 0.1/s, sized for one
// block per 120 s), so after about eight blocks every link was dropping frames,
// each drop cost a fault point, and at ten points every monerod link was
// banned -- 'dos: dropped=30..39' and peers=0 for ~30 s on the live D1 rig,
// with nothing but valid blocks on the wire.
//
// THE RULE. A push is still charged on arrival (nothing about it is known
// yet), but once the index finds the block is one it HAS -- it connected, it
// was already on the best chain, or it is held as a valid, resolved alt
// candidate -- the token is handed back (IChainFetcher::credit_known_block).
// A parked orphan, a bodiless announcement, and a rejected block keep their
// charge.
//
// WHAT RUNS. The REAL XmrPeerPool and the REAL ChainIndex (a from-genesis
// regtest index, the reorg-follow KAT's boot, with a model RandomX verifier),
// wired exactly as the node wires them (the pool is the index's fetcher, the
// index is the pool's serving and inbound side), against hand-rolled monerod
// stand-ins on loopback that push real, structurally valid blocks. Nothing in
// this file touches an interface that did not exist before D3a, so the same
// file builds against the pre-fix tree and FAILS there (part A), which is what
// makes it a regression pin rather than a description.
//
//   A. honest burst: 3 links x 40 valid blocks, each block pushed by every
//      link. Fix: 0 frames dropped, 0 bans, all 3 links up, tip at +40.
//      Pre-fix: drops from the ninth block, then every link banned.
//   B. abuse, scored exactly as before (block refill frozen so the message
//      counts are exact, and pinned to the pre-fix numbers):
//      B1. a flood of distinct unknown-parent blocks: banned at message 18
//          (8 admitted, 10 exhaustion points);
//      B2. the SAME unknown-parent block re-pushed: banned at message 18
//          (a parked orphan is not a block we have as valid);
//      B3. a block that does not parse: banned at message 1;
//      B4. a block on our tip whose coinbase overpays: banned at message 1;
//      B5. valid blocks first, then a flood of unknown ones on the SAME link:
//          the valid pushes cost nothing, the flood is banned at message 18
//          of the flood -- exactly what a fresh link sees.
// ---------------------------------------------------------------------------
#include <chrono>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/chain/xmr_fork_choice.hpp"
#include "impl/xmr/native/chain/xmr_pow_gate.hpp"
#include "impl/xmr/native/chain/xmr_row_store.hpp"
#include "impl/xmr/native/consensus/xmr_reward.hpp"
#include "impl/xmr/native/contracts/fakes/fake_txpool.hpp"
#include "impl/xmr/native/p2p/xmr_peer_pool.hpp"
#include "xmr_p2p_kat_util.hpp"

using namespace c2pool::xmr::native;
namespace p2p   = c2pool::xmr::native::p2p;
namespace levin = c2pool::xmr::native::levin;
namespace kat   = c2pool::xmr::native::kat;
namespace asio  = boost::asio;
using tcp = asio::ip::tcp;

namespace {

// =============================================================================
// blocks: the reorg-follow KAT's shape -- a structurally real Monero block with
// one coinbase output and no transactions, on a from-genesis regtest chain
// =============================================================================
Hash tag_id(std::uint64_t tag) {
    Hash h{};
    for (std::size_t i = 0; i < 8; ++i) h[i] = static_cast<std::uint8_t>((tag >> (8 * i)) & 0xff);
    h[31] = 0x5a;
    return h;
}

void put_varint(std::vector<std::uint8_t>& o, std::uint64_t v) { blob_write_varint(o, v); }

BlockEntry make_block(std::uint8_t major, std::uint8_t minor, std::uint64_t timestamp,
                      const Hash& prev, std::uint32_t nonce, std::uint64_t height,
                      std::uint64_t reward, std::uint8_t salt = 0) {
    std::vector<std::uint8_t> b;
    put_varint(b, major);
    put_varint(b, minor);
    put_varint(b, timestamp);
    b.insert(b.end(), prev.begin(), prev.end());
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>((nonce >> (8 * i)) & 0xff));

    put_varint(b, 2);                       // miner_tx version
    put_varint(b, height + 60);             // unlock_time
    put_varint(b, 1);                       // one input
    b.push_back(0xFF);                      // TX_IN_GEN
    put_varint(b, height);
    put_varint(b, 1);                       // one output
    put_varint(b, reward);
    b.push_back(0x03);                      // TX_OUT_TO_TAGGED_KEY
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<std::uint8_t>(0x10 + i));
    b.push_back(salt);                      // view tag doubles as the sibling salt
    put_varint(b, 33);                      // tx_extra length
    b.push_back(0x01);                      // TX_EXTRA_TAG_PUBKEY
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<std::uint8_t>(0x40 + i));
    b.push_back(0x00);                      // rct type NULL

    put_varint(b, 0);                       // no transaction hashes

    BlockEntry e;
    e.block_blob = std::move(b);
    return e;
}

Hash id_of(const BlockEntry& e) {
    EvaluatedBlock ev;
    std::string    why;
    if (evaluate_block(e, ev, why) != EvalStatus::Ok) return Hash{};
    return ev.input.identity.id;
}

// A model RandomX verifier, shaped like c2pool::xmr::LightVerifier: every hash
// meets the (regtest, difficulty 1) target. PoW is not what this file tests.
class ModelVerifier {
public:
    enum class VerifyStatus { Accept, BelowTarget, SeedNotResident, NotInitialized };
    bool prefetch_epoch(const Hash& current, const std::optional<Hash>& next) {
        cur_ = current;
        nxt_ = next;
        return true;
    }
    bool seed_resident(const Hash& s) const {
        if (cur_ && *cur_ == s) return true;
        return nxt_ && *nxt_ == s;
    }
    VerifyStatus verify(const std::uint8_t*, std::size_t, const Hash& seed,
                        std::uint64_t, std::uint64_t, std::uint8_t out[32]) {
        if (!seed_resident(seed)) return VerifyStatus::SeedNotResident;
        for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(i);
        return VerifyStatus::Accept;
    }

private:
    std::optional<Hash> cur_, nxt_;
};

constexpr std::uint8_t  REG_MAJOR  = MAX_IMPLEMENTED_HF_VERSION;
constexpr std::uint64_t GENESIS_TS = 1'700'000'000ull;

U128 u128_of(std::uint64_t lo, std::uint64_t hi) { U128 d; d.lo = lo; d.hi = hi; return d; }

ChainRow genesis_row() {
    ChainRow row;
    row.height                  = 0;
    row.id                      = tag_id(0);
    row.prev_id                 = Hash{};
    row.timestamp               = GENESIS_TS;
    row.major_version           = 1;
    row.minor_version           = 0;
    row.block_weight            = 80;
    row.long_term_weight        = 80;
    row.difficulty              = u128_of(1, 0);
    row.cumulative_difficulty   = u128_of(1, 0);
    row.already_generated_coins = 0;
    row.pow_verified            = true;
    return row;
}

std::uint64_t base_at(std::uint64_t agc) {
    std::uint64_t base = 0;
    (void)get_block_reward(/*penalty_median=*/300'000, /*block_weight=*/300, agc,
                           hf_rules_version(REG_MAJOR), base);
    return base;
}

// A valid chain of `count` blocks on top of `prev` at `prev_height`, priced at
// the emission `agc` standing there. Newest last; NOT offered to anyone.
std::vector<BlockEntry> build_chain(Hash prev, std::uint64_t prev_height, std::uint64_t agc,
                                    std::size_t count, std::uint8_t salt = 0) {
    std::vector<BlockEntry> out;
    for (std::size_t i = 0; i < count; ++i) {
        const std::uint64_t h = prev_height + 1 + i;
        BlockEntry e = make_block(REG_MAJOR, REG_MAJOR, GENESIS_TS + 120 * h, prev,
                                  static_cast<std::uint32_t>(h * 31 + salt), h, base_at(agc), salt);
        agc  = accumulate_generated_coins(agc, base_at(agc));
        prev = id_of(e);
        out.push_back(std::move(e));
    }
    return out;
}

// =============================================================================
// a monerod stand-in that answers the handshake and pushes 2008s on demand
// =============================================================================
constexpr std::uint64_t STANDIN_PEER_ID = 0x00d3a00d3a00d3a0ull;

class StandinDaemon {
public:
    explicit StandinDaemon(asio::io_context& io)
        : acc_(io, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0)), sock_(io) {
        acc_.listen();
        acc_.async_accept(sock_, [this](const boost::system::error_code& ec) {
            if (ec) return;
            arm();
        });
    }

    std::string key() const { return "127.0.0.1:" + std::to_string(acc_.local_endpoint().port()); }

    void push_block(const BlockEntry& e, std::uint64_t peer_height) {
        levin::NewBlock nb;
        nb.b = e;
        nb.current_blockchain_height = peer_height;
        std::vector<std::uint8_t> body;
        levin::MessageError err = levin::MessageError::None;
        if (!levin::encode_new_fluffy_block(nb, body, err)) return;
        write(levin::make_notify(levin::CMD_NEW_FLUFFY_BLOCK, body));
    }

    // A 2008 whose block blob is garbage: the body frames fine, the block in it
    // does not parse.
    void push_garbage_block(std::uint8_t fill) {
        BlockEntry e;
        e.block_blob.assign(24, fill);
        push_block(e, 1);
    }

private:
    void write(const std::vector<std::uint8_t>& frame) {
        boost::system::error_code ec;
        asio::write(sock_, asio::buffer(frame), ec);
    }

    void arm() {
        sock_.async_read_some(asio::buffer(chunk_),
            [this](const boost::system::error_code& ec, std::size_t n) {
                if (ec) return;
                buf_.insert(buf_.end(), chunk_, chunk_ + n);
                drain();
                arm();
            });
    }

    static std::uint64_t le(const std::uint8_t* p, int n) {
        std::uint64_t v = 0;
        for (int i = n - 1; i >= 0; --i) v = (v << 8) | p[i];
        return v;
    }

    void drain() {
        for (;;) {
            if (buf_.size() < levin::HEADER_SIZE) return;
            const std::uint8_t* p = buf_.data();
            const std::uint64_t cb    = le(p + 8, 8);
            const std::uint32_t cmd   = static_cast<std::uint32_t>(le(p + 17, 4));
            const std::uint32_t flags = static_cast<std::uint32_t>(le(p + 25, 4));
            if (cb > 64u * 1024u * 1024u) { buf_.clear(); return; }
            if (buf_.size() < levin::HEADER_SIZE + cb) return;
            buf_.erase(buf_.begin(),
                       buf_.begin() + levin::HEADER_SIZE + static_cast<std::ptrdiff_t>(cb));
            if ((flags & levin::PACKET_RESPONSE) != 0) continue;
            levin::MessageError err = levin::MessageError::None;
            if (cmd == levin::CMD_HANDSHAKE) {
                levin::HandshakeResponse r;
                r.node_data.network_id    = levin::network_id_of(levin::XmrNet::Stagenet);
                r.node_data.peer_id       = STANDIN_PEER_ID;
                r.node_data.my_port       = 38080;
                r.node_data.support_flags = levin::SUPPORT_FLAG_FLUFFY_BLOCKS;
                r.payload_data            = sync();
                std::vector<std::uint8_t> out;
                if (levin::encode_handshake_response(r, out, err))
                    write(levin::make_response(levin::CMD_HANDSHAKE, out, levin::RC_HANDLER_OK));
            } else if (cmd == levin::CMD_TIMED_SYNC) {
                levin::TimedSyncResponse r;
                r.payload_data = sync();
                std::vector<std::uint8_t> out;
                if (levin::encode_timed_sync_response(r, out, err))
                    write(levin::make_response(levin::CMD_TIMED_SYNC, out, levin::RC_HANDLER_OK));
            }
        }
    }

    static PeerSyncData sync() {
        PeerSyncData s;
        s.current_height        = 3;
        s.cumulative_difficulty = u128_of(3, 0);
        s.top_id                = tag_id(0);
        s.top_version           = REG_MAJOR;
        return s;
    }

    tcp::acceptor             acc_;
    tcp::socket               sock_;
    std::uint8_t              chunk_[16384]{};
    std::vector<std::uint8_t> buf_;
};

// =============================================================================
// the node: real index + real pool, wired the way xmr_native_node wires them
// =============================================================================
constexpr std::uint64_t OWN_BLOCKS = 2;   // the chain the node already has

struct Node {
    asio::io_context                      io;
    ModelVerifier                         mv;
    LightVerifierPowSource<ModelVerifier> src{mv};
    ChainIndexOptions                     opts;
    std::unique_ptr<ChainIndex>           idx;
    fakes::FakeTxpool                     txpool;
    std::shared_ptr<p2p::XmrPeerPool>     pool;
    std::vector<std::unique_ptr<StandinDaemon>> links;
    Hash                                  tip_id{};
    std::uint64_t                         tip_agc = 0;

    Node(std::size_t n_links, double block_refill) {
        opts.net         = XmrNet::Regtest;
        opts.require_pow = true;
        opts.tie         = TieBreak::PreferOwn;
        idx = std::make_unique<ChainIndex>(opts, src);
        const ChainRow g = genesis_row();
        idx->seed_direct(g, {DifficultyRow{g.timestamp, g.cumulative_difficulty}},
                         {g.block_weight}, {g.long_term_weight}, {g.timestamp}, {{0, g.id}});
        tip_id = g.id;
        for (BlockEntry& e : build_chain(g.id, 0, 0, OWN_BLOCKS)) {
            const OfferResult r = idx->offer_block(nullptr, e, /*own_mined=*/true);
            kat::check(r.outcome == OfferOutcome::Connected, "rig: own block connects");
            tip_agc = accumulate_generated_coins(tip_agc, base_at(tip_agc));
            tip_id  = r.id;
        }

        for (std::size_t i = 0; i < n_links; ++i)
            links.push_back(std::make_unique<StandinDaemon>(io));

        p2p::XmrPeerPool::Config c;
        c.net = levin::XmrNet::Stagenet;
        c.link.handshake.net          = levin::XmrNet::Stagenet;
        c.link.handshake.our_peer_id  = 0x1122334455667788ull;
        c.link.handshake_timeout_ms   = 2'000;
        c.link.invoke_timeout_ms      = 2'000;
        c.link.timed_sync_interval_ms = 3'600'000;
        c.link.timed_sync_jitter_ms   = 0;
        c.link.peer_timeout_ms        = 3'600'000;
        c.link.tick_ms                = 50;
        c.maintenance_tick_ms         = 25;
        c.connect_timeout_ms          = 2'000;
        c.use_seeds                   = false;   // never dial the real network
        c.dial.target_outbound        = 8;
        c.dial.max_per_netgroup       = 8;       // loopback is all one /16
        c.dial.anchor_slots           = 0;
        c.dial.rotation_interval_ms   = 0;
        c.dos.block_refill            = block_refill;
        for (const auto& l : links) c.manual_peers.push_back(l->key());
        pool = p2p::XmrPeerPool::create(io, c, {idx.get(), idx.get(), &txpool});
        idx->set_fetcher(pool.get());   // exactly as XmrNativeNode does
        pool->start();
        kat::check(wait_for([&] { return pool->peer_count() == n_links; }), "rig: every link is up");
    }

    ~Node() {
        pool->stop();
        pump(100);
    }

    void pump(int ms) {
        io.restart();
        io.run_for(std::chrono::milliseconds(ms));
    }

    template <class F>
    bool wait_for(F pred, int budget_ms = 4000) {
        for (int spent = 0; spent < budget_ms; spent += 5) {
            if (pred()) return true;
            pump(5);
        }
        return pred();
    }

    std::uint64_t tip_height() const {
        const auto t = idx->tip();
        return t ? t->height : 0;
    }

    bool is_connected(const std::string& key) const {
        for (const auto& pr : pool->peers()) if (pr.first.addr == key) return true;
        return false;
    }
};

// Push `frames` one at a time from link 0 until the pool drops the link, and
// return the 1-based message at which it went (0 = never).
template <class Push>
std::size_t messages_until_link_lost(Node& n, std::size_t frames, Push push) {
    const std::string key = n.links[0]->key();
    for (std::size_t i = 0; i < frames; ++i) {
        const std::uint64_t in_before = n.pool->telemetry().frames_in;
        push(i);
        n.wait_for([&] { return n.pool->telemetry().frames_in > in_before; }, 2000);
        n.pump(10);   // let any fault / ban / refund post land
        if (!n.is_connected(key)) return i + 1;
    }
    return 0;
}

// -----------------------------------------------------------------------------
// A. an honest burst: every link relays every block
// -----------------------------------------------------------------------------
void test_honest_burst_costs_nothing() {
    constexpr std::size_t LINKS = 3, BLOCKS = 40;
    Node n(LINKS, /*block_refill=*/0.1);   // the production refill
    const std::vector<BlockEntry> chain = build_chain(n.tip_id, OWN_BLOCKS, n.tip_agc, BLOCKS);

    for (std::size_t b = 0; b < BLOCKS; ++b) {
        const std::uint64_t h = OWN_BLOCKS + 1 + b;
        for (auto& l : n.links) l->push_block(chain[b], h + 1);
        n.wait_for([&] { return n.tip_height() >= h; }, 1000);
        n.pump(5);
    }
    n.pump(100);

    const p2p::PoolTelemetry t = n.pool->telemetry();
    kat::checkf(t.frames_dropped_dos == 0,
                "an honest burst (%zu links x %zu valid blocks) drops no frame (dropped=%llu)",
                LINKS, BLOCKS, static_cast<unsigned long long>(t.frames_dropped_dos));
    kat::checkf(t.bans == 0, "... bans no link (bans=%llu)", static_cast<unsigned long long>(t.bans));
    kat::checkf(n.pool->peer_count() == LINKS, "... keeps every link up (peers=%zu)",
                n.pool->peer_count());
    kat::checkf(n.tip_height() == OWN_BLOCKS + BLOCKS, "... and follows every block (tip=%llu, want %llu)",
                static_cast<unsigned long long>(n.tip_height()),
                static_cast<unsigned long long>(OWN_BLOCKS + BLOCKS));
    kat::checkf(t.blocks_in == LINKS * BLOCKS, "every copy reached the index (%llu)",
                static_cast<unsigned long long>(t.blocks_in));
    std::printf("A honest burst: links=%zu blocks=%zu frames_in=%llu blocks_in=%llu dropped=%llu bans=%llu peers=%zu tip=%llu\n",
                LINKS, BLOCKS, static_cast<unsigned long long>(t.frames_in),
                static_cast<unsigned long long>(t.blocks_in),
                static_cast<unsigned long long>(t.frames_dropped_dos),
                static_cast<unsigned long long>(t.bans), n.pool->peer_count(),
                static_cast<unsigned long long>(n.tip_height()));
}

// -----------------------------------------------------------------------------
// B. abuse is scored exactly as before. Block refill frozen: the counts are
//    exact. Capacity 8, one point per exhaustion, ban at 10 points => a link
//    that only ever sends blocks we cannot take as valid is banned at its 18th.
// -----------------------------------------------------------------------------
constexpr std::size_t FLOOD_BAN_AT = 18;

void test_abuse_is_scored_as_before() {
    // B1. distinct unknown-parent blocks
    {
        Node n(1, 0.0);
        const std::size_t at = messages_until_link_lost(n, 30, [&](std::size_t i) {
            const std::vector<BlockEntry> junk =
                build_chain(tag_id(0x1000 + i), OWN_BLOCKS, n.tip_agc, 1, static_cast<std::uint8_t>(i));
            n.links[0]->push_block(junk[0], OWN_BLOCKS + 2);
        });
        const p2p::PoolTelemetry t = n.pool->telemetry();
        kat::checkf(at == FLOOD_BAN_AT, "B1: a flood of unknown-parent blocks is banned at message %zu (got %zu)",
                    FLOOD_BAN_AT, at);
        kat::checkf(t.bans == 1, "B1: ... as a ban (bans=%llu)", static_cast<unsigned long long>(t.bans));
        std::printf("B1 unknown-parent flood: link lost at message %zu dropped=%llu bans=%llu\n", at,
                    static_cast<unsigned long long>(t.frames_dropped_dos),
                    static_cast<unsigned long long>(t.bans));
    }
    // B2. the same unknown-parent block, over and over
    {
        Node n(1, 0.0);
        const std::vector<BlockEntry> junk = build_chain(tag_id(0x2000), OWN_BLOCKS, n.tip_agc, 1);
        const std::size_t at = messages_until_link_lost(n, 30, [&](std::size_t) {
            n.links[0]->push_block(junk[0], OWN_BLOCKS + 2);
        });
        const p2p::PoolTelemetry t = n.pool->telemetry();
        kat::checkf(at == FLOOD_BAN_AT,
                    "B2: re-pushing one parked orphan is banned at message %zu (got %zu)", FLOOD_BAN_AT, at);
        std::printf("B2 same orphan re-pushed: link lost at message %zu dropped=%llu bans=%llu\n", at,
                    static_cast<unsigned long long>(t.frames_dropped_dos),
                    static_cast<unsigned long long>(t.bans));
    }
    // B3. a block that does not parse
    {
        Node n(1, 0.0);
        const std::size_t at = messages_until_link_lost(n, 5, [&](std::size_t i) {
            n.links[0]->push_garbage_block(static_cast<std::uint8_t>(0xA0 + i));
        });
        const p2p::PoolTelemetry t = n.pool->telemetry();
        kat::checkf(at == 1, "B3: an unparseable block is banned at message 1 (got %zu)", at);
        kat::checkf(t.bans == 1, "B3: ... as a ban (bans=%llu)", static_cast<unsigned long long>(t.bans));
        std::printf("B3 unparseable block: link lost at message %zu bans=%llu\n", at,
                    static_cast<unsigned long long>(t.bans));
    }
    // B4. a block on our tip whose coinbase pays more than the reward
    {
        Node n(1, 0.0);
        const std::uint64_t h = OWN_BLOCKS + 1;
        const BlockEntry bad = make_block(REG_MAJOR, REG_MAJOR, GENESIS_TS + 120 * h, n.tip_id,
                                          static_cast<std::uint32_t>(h * 31), h,
                                          base_at(n.tip_agc) + 1'000'000);
        const std::size_t at = messages_until_link_lost(n, 5, [&](std::size_t) {
            n.links[0]->push_block(bad, h + 1);
        });
        const p2p::PoolTelemetry t = n.pool->telemetry();
        kat::checkf(at == 1, "B4: an overpaying block on our tip is banned at message 1 (got %zu)", at);
        kat::checkf(n.tip_height() == OWN_BLOCKS, "B4: ... and never connects");
        std::printf("B4 invalid block on tip: link lost at message %zu bans=%llu tip=%llu\n", at,
                    static_cast<unsigned long long>(t.bans),
                    static_cast<unsigned long long>(n.tip_height()));
    }
    // B5. valid relay first, then a flood on the same link
    {
        Node n(1, 0.0);
        constexpr std::size_t VALID = 12;
        const std::vector<BlockEntry> chain = build_chain(n.tip_id, OWN_BLOCKS, n.tip_agc, VALID);
        for (std::size_t b = 0; b < VALID; ++b) {
            n.links[0]->push_block(chain[b], OWN_BLOCKS + 2 + b);
            n.wait_for([&] { return n.tip_height() >= OWN_BLOCKS + 1 + b; }, 1000);
            n.pump(10);
        }
        kat::checkf(n.tip_height() == OWN_BLOCKS + VALID,
                    "B5: %zu valid blocks on one link (more than the bucket holds) all connect (tip=%llu)",
                    VALID, static_cast<unsigned long long>(n.tip_height()));
        kat::checkf(n.pool->telemetry().frames_dropped_dos == 0, "B5: ... with no frame dropped");
        const std::uint64_t valid_tip = n.tip_height();
        const std::size_t at = messages_until_link_lost(n, 30, [&](std::size_t i) {
            const std::vector<BlockEntry> junk =
                build_chain(tag_id(0x3000 + i), OWN_BLOCKS, n.tip_agc, 1, static_cast<std::uint8_t>(i));
            n.links[0]->push_block(junk[0], OWN_BLOCKS + 2);
        });
        kat::checkf(at == FLOOD_BAN_AT,
                    "B5: the flood that follows is still banned at message %zu of the flood (got %zu)",
                    FLOOD_BAN_AT, at);
        std::printf("B5 valid-then-flood: tip after %zu valid=%llu, flood link lost at message %zu\n",
                    VALID, static_cast<unsigned long long>(valid_tip), at);
    }
}

} // namespace

int main() {
    test_honest_burst_costs_nothing();
    test_abuse_is_scored_as_before();
    return kat::report("xmr_native_dos_dup_block_kat");
}
