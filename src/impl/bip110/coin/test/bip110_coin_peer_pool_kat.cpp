// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_coin_peer_pool_kat -- c2pool-bip110's coin peer pool
// (bip110::coin::CoinPeerPool, impl/bip110/coin/coin_peer_pool.hpp: the shared
// btc::coin::BasicCoinPeerPool with the BIP-110 coin types), driven with fake
// connections over v2 (164-byte, BLAKE2b) headers and checked bodies.
//
// Proves:
//   [A] the pool's block identity is bip110::coin::block_hash: BLAKE2b for a
//       v2 header (never SHA256d of it), SHA256d for a v1 header.
//   [B] slots: the target of 8, refill from the candidates, a dial without a
//       handshake dropped and reported as a failed dial, connected reported
//       once.
//   [C] candidates (pool_candidates): the explicit fork peers first, in order,
//       then the peer manager's; never a key the pool or a fan-out slot holds;
//       the manager is asked to exclude them all.
//   [D] headers from any pooled peer reach the header chain path; a full batch
//       asks its sender for the next one from the last header's identity; an
//       announced unknown block asks the announcer with the locator.
//   [E] block bodies are fetched and tracked by the BIP-110 identity: the
//       first announcer only, never by SHA256d(header); a body reaches the
//       UTXO connect and then the full_block path once.
//   [F] chain order: a body above its parent waits, the parent is asked for by
//       its identity, both connect in order, one late-connect pass.
//   [G] the BIP-110 body rules gate both paths: a body that is valid for
//       Bitcoin but commits another transaction count, or is over the RDTS
//       weight cap, reaches neither the UTXO connect nor the mempool path; it
//       is asked of another peer without using up an ask; with the cap off the
//       heavy body connects.
//   [H] a won block goes to every connected peer; the same bytes once per
//       kCoinPoolRelayDedupSec, different bytes for the same header both.
//   [I] request_txs (the mempool's parent fetches) asks one connected peer,
//       the next one each call; slot_keys lists dialing and connected slots.
//   [J] a transaction is fetched once by txid and passed on once.
//   [K] a reorg onto a branch whose block was received while it competed:
//       with main_bip110's connect gate (contiguous, active chain only) the
//       kept body (SideBodies) connects after the rollback and the branch's
//       next block follows; without it the view stays at the fork.
//
// No node, no network.

#include <impl/bip110/coin/block_body_check.hpp>
#include <impl/bip110/coin/coin_peer_pool.hpp>
#include <impl/bip110/coin/header_chain.hpp>
#include <impl/bip110/coin/mempool.hpp>
#include <impl/bip110/coin/template_builder.hpp>
#include <impl/bip110/coin/transaction.hpp>
#include <impl/bip110/coin/utxo_side_bodies.hpp>

#include <core/hash.hpp>
#include <core/netaddress.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace bip110::coin;
using btc::coin::kCoinPoolBodyRetrySec;
using btc::coin::kCoinPoolDialTimeoutSec;
using btc::coin::kCoinPoolFullHeadersBatch;
using btc::coin::kCoinPoolRelayDedupSec;

namespace {

int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } \
    else         { std::printf("ok:   %s\n", msg); } \
} while (0)

using Clock = std::chrono::steady_clock;

uint256 sha256d_of(const BlockHeaderType& h)
{
    auto packed = pack(h);
    return Hash(packed.get_span());
}

MutableTransaction make_coinbase(uint32_t tag)
{
    MutableTransaction cb;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.scriptSig.m_data = {0x04, static_cast<unsigned char>(tag & 0xff),
                           static_cast<unsigned char>((tag >> 8) & 0xff),
                           static_cast<unsigned char>((tag >> 16) & 0xff),
                           static_cast<unsigned char>((tag >> 24) & 0xff)};
    in.sequence = 0xffffffff;
    cb.vin.push_back(in);
    TxOut o;
    o.value = 312500000;
    o.scriptPubKey.m_data = {0x51};
    cb.vout.push_back(o);
    return cb;
}

MutableTransaction make_spend(uint32_t n, size_t script_size = 25)
{
    MutableTransaction tx;
    TxIn in;
    in.prevout.hash.SetHex("00000000000000000000000000000000000000000000000000000000000000bb");
    in.prevout.index = n;
    in.scriptSig.m_data = {0x51};
    in.sequence = 0xfffffffe;
    tx.vin.push_back(in);
    TxOut o;
    o.value = 1000;
    o.scriptPubKey.m_data.assign(script_size, 0x51);
    tx.vout.push_back(o);
    return tx;
}

/// A v2 block on `prev` at `height`: a coinbase tagged `tag` and `txs`; the
/// merkle root and m_txcount match unless `txcount` overrides the count.
BlockType make_block(const uint256& prev, uint32_t height, uint32_t tag,
                     std::vector<MutableTransaction> txs = {},
                     std::optional<uint16_t> txcount = std::nullopt)
{
    BlockType b;
    b.m_version = 0x80000000u | 0x20000000u;
    b.m_previous_block = prev;
    b.m_timestamp = 1790000000u + height;
    b.m_bits = 0x1d00ffff;
    b.m_nonce = tag;
    b.m_nonce2 = 1;
    b.m_nonce3 = 2;
    b.m_extranonce.fill(0x5a);
    b.m_flags = 0;
    b.m_clear_bits = 0;
    b.m_xor_key.fill(0x00);
    b.m_height = static_cast<int32_t>(height);
    b.m_mm_rhs.SetNull();
    b.m_txs.push_back(make_coinbase(tag));
    for (auto& tx : txs)
        b.m_txs.push_back(std::move(tx));
    std::vector<uint256> txids;
    for (const auto& tx : b.m_txs)
        txids.push_back(compute_txid(tx));
    b.m_merkle_root = compute_merkle_root(txids);
    b.m_txcount = txcount ? *txcount : static_cast<uint16_t>(b.m_txs.size());
    return b;
}

const BlockHeaderType& header_of(const BlockType& b) { return b; }

std::pair<Transaction, uint256> make_tx(uint32_t locktime)
{
    MutableTransaction mtx;
    mtx.version = 2;
    mtx.locktime = locktime;
    auto packed = pack(TX_NO_WITNESS(mtx));
    return {Transaction(mtx), Hash(packed.get_span())};
}

struct FakePeer;

struct Harness {
    Clock::time_point t = Clock::time_point{} + std::chrono::hours(1000);
    std::map<std::string, FakePeer*> peers;
    std::vector<std::pair<std::string, uint16_t>> candidates;
    std::map<std::string, int> connected_reports;
    std::set<std::string> reported_disconnected, reported_failed;
    std::map<uint256, uint32_t> chain;   // identity -> height
    uint32_t height = 970000;
    bool caught_up = true;
    uint256 root;
    uint256 tip_hash;
    bool rdts_cap = true;               // the body check's RDTS cap
    bool track_utxo = false;
    std::optional<uint32_t> utxo_best;
    std::vector<std::vector<BlockHeaderType>> forwarded;
    std::vector<uint256> forwarded_blocks;   // the full_block path (mempool)
    std::vector<uint256> connected_blocks;   // the UTXO connect
    std::vector<uint256> late_connects;
    int forwarded_txs = 0;
    int announced = 0;
    // Replaces the UTXO-connect model of on_body_in_order (optional).
    std::function<void(const BlockType&)> connect_override;
    std::unique_ptr<CoinPeerPool> pool;

    explicit Harness(size_t n_candidates = 20);

    void advance(int64_t sec) { t += std::chrono::seconds(sec); }

    /// Put a header into the chain (by its identity).
    void add(const BlockHeaderType& h)
    {
        auto it = chain.find(h.m_previous_block);
        if (it == chain.end())
            return;
        const uint32_t hh = it->second + 1;
        const uint256 id = block_hash(h);
        chain.emplace(id, hh);
        if (hh > height) {
            height = hh;
            tip_hash = id;
        }
    }

    FakePeer* peer(const std::string& key)
    {
        auto it = peers.find(key);
        return it == peers.end() ? nullptr : it->second;
    }
};

struct FakePeer : PoolPeer {
    std::map<std::string, FakePeer*>* registry;
    std::string key;
    PoolPeerHooks hooks;
    bool hs{false};
    std::vector<std::vector<uint256>> getheaders;
    std::vector<std::vector<unsigned char>> relayed;
    std::vector<uint256> requested;
    std::vector<uint256> requested_txs;

    FakePeer(std::map<std::string, FakePeer*>* reg, std::string k, PoolPeerHooks hk)
        : registry(reg), key(std::move(k)), hooks(std::move(hk))
    {
        (*registry)[key] = this;
    }
    ~FakePeer() override { registry->erase(key); }

    bool handshaked() const override { return hs; }
    std::string subver() const override { return "/Satoshi:29.4.1/Knots:20260508/"; }
    uint32_t start_height() const override { return 970000; }
    void send_getheaders(const std::vector<uint256>& locator, const uint256&) override
    {
        getheaders.push_back(locator);
    }
    bool relay_block(const std::vector<unsigned char>& b) override
    {
        relayed.push_back(b);
        return true;
    }
    void request_block(const uint256& h) override { requested.push_back(h); }
    void request_tx(const uint256& h) override { requested_txs.push_back(h); }

    void send_headers(const std::vector<BlockHeaderType>& hdrs)
    {
        hooks.headers_message(hdrs.size());
        if (!hdrs.empty())
            hooks.headers(hdrs);
    }

    size_t asked_for(const uint256& h) const
    {
        return static_cast<size_t>(std::count(requested.begin(), requested.end(), h));
    }
};

Harness::Harness(size_t n_candidates)
{
    root.SetHex("00000000000000000000000000000000000000000000000000000000000c0ffe");
    tip_hash = root;
    chain.emplace(root, height);
    for (size_t i = 0; i < n_candidates; ++i)
        candidates.emplace_back("45.2." + std::to_string(i) + ".9", 8333);
    CoinPeerPoolHost h;
    h.dial = [this](const NetService& a, PoolPeerHooks hk) -> std::unique_ptr<PoolPeer> {
        return std::make_unique<FakePeer>(&peers, a.to_string(), std::move(hk));
    };
    h.candidates = [this](const std::set<std::string>& exclude) {
        std::vector<PeerEndpoint> out;
        for (const auto& [host, port] : candidates) {
            const std::string key = host + ":" + std::to_string(port);
            if (exclude.count(key) || reported_failed.count(key) || reported_disconnected.count(key))
                continue;
            if (auto ep = PeerEndpoint::from(host, port))
                out.push_back(*ep);
        }
        return out;
    };
    h.connected = [this](const std::string& k) { ++connected_reports[k]; };
    h.disconnected = [this](const std::string& k) { reported_disconnected.insert(k); };
    h.dial_failed = [this](const std::string& k) { reported_failed.insert(k); };
    h.has_header = [this](const uint256& x) { return chain.count(x) != 0; };
    h.header_height = [this](const uint256& x) -> std::optional<uint32_t> {
        auto it = chain.find(x);
        if (it == chain.end())
            return std::nullopt;
        return it->second;
    };
    h.locator = [this]() { return std::vector<uint256>{tip_hash}; };
    h.tip = [this]() { return tip_hash; };
    h.height = [this]() { return height; };
    h.caught_up = [this]() { return caught_up; };
    // The production check: the c2pool-btc rules plus the BIP-110 rules.
    h.body_valid = [this](const BlockType& b) { return block_body_matches_header(b, rdts_cap); };
    h.body_best_height = [this]() -> std::optional<uint32_t> {
        return track_utxo ? utxo_best : std::nullopt;
    };
    h.on_headers = [this](const std::vector<BlockHeaderType>& hdrs) {
        forwarded.push_back(hdrs);
        for (const auto& x : hdrs)
            add(x);
    };
    h.on_block_announced = [this](const uint256&) { ++announced; };
    h.on_tx = [this](const Transaction&) { ++forwarded_txs; };
    h.on_full_block = [this](const BlockType& b) { forwarded_blocks.push_back(block_hash(b)); };
    h.on_body_in_order = [this](const BlockType& b) {
        const uint256 id = block_hash(b);
        connected_blocks.push_back(id);
        if (connect_override) {
            connect_override(b);
            return;
        }
        auto it = chain.find(id);
        if (track_utxo && it != chain.end() && (!utxo_best || it->second > *utxo_best))
            utxo_best = it->second;
    };
    h.after_late_connect = [this](const BlockType& b) { late_connects.push_back(block_hash(b)); };
    h.now = [this]() { return t; };
    pool = std::make_unique<CoinPeerPool>(std::move(h), kCoinPoolTargetPeers, "[EMB-BIP110]");
}

void handshake(Harness& hx, size_t n)
{
    size_t done = 0;
    for (auto& [key, p] : hx.peers) {
        if (done == n)
            break;
        p->hs = true;
        ++done;
    }
    hx.pool->tick();
}

std::vector<FakePeer*> handshaked_peers(Harness& hx)
{
    std::vector<FakePeer*> out;
    for (auto& [key, p] : hx.peers)
        if (p->hs)
            out.push_back(p);
    return out;
}

size_t asks_for(Harness& hx, const uint256& h)
{
    size_t n = 0;
    for (auto& [key, p] : hx.peers)
        n += p->asked_for(h);
    return n;
}

} // namespace

int run_coin_peer_pool_kat()
{
    // ── [A] the block identity ────────────────────────────────────────────────
    {
        uint256 prev;
        prev.SetHex("00000000000000000000000000000000000000000000000000000000000000ab");
        const BlockType b = make_block(prev, 970001, 1);
        const uint256 id = pool_header_hash(b);
        CHECK(id == block_hash(b) && id == Bip110PoolCoin::header_hash(b),
              "[A] the pool's identity is bip110::coin::block_hash");
        CHECK(!id.IsNull() && id != sha256d_of(b), "[A] a v2 identity is BLAKE2b, not SHA256d(header)");
        BlockHeaderType v1 = header_of(b);
        v1.m_version = 0x20000000u;
        CHECK(pool_header_hash(v1) == sha256d_of(v1), "[A] a v1 identity is SHA256d(header)");
    }

    // ── [B] slots ─────────────────────────────────────────────────────────────
    {
        Harness hx;
        hx.pool->tick();
        CHECK(hx.pool->slot_count() == 8 && hx.peers.size() == 8,
              "[B] 8 slots dialed of 20 candidates");
        handshake(hx, 6);
        CHECK(hx.pool->live_count() == 6 && hx.connected_reports.size() == 6,
              "[B] 6 handshakes reported connected");
        std::set<std::string> silent;
        for (auto& [key, p] : hx.peers)
            if (!p->hs)
                silent.insert(key);
        hx.advance(kCoinPoolDialTimeoutSec);
        hx.pool->tick();
        CHECK(hx.reported_failed == silent, "[B] the 2 silent dials reported as failed dials");
        CHECK(hx.pool->slot_count() == 8, "[B] ... and replaced");
        hx.advance(12);
        hx.pool->tick();
        int max_reports = 0;
        for (const auto& [k, n] : hx.connected_reports)
            max_reports = std::max(max_reports, n);
        CHECK(max_reports == 1, "[B] connected reported once per slot");
    }

    // ── [C] candidates ────────────────────────────────────────────────────────
    {
        const std::vector<NetService> explicit_peers = {
            NetService("203.0.113.7", 8333), NetService("198.51.100.2", 9333),
            NetService("0.0.0.0", 8333), NetService("203.0.113.7", 8333)};
        std::set<std::string> asked_exclude;
        auto manager = [&asked_exclude](const std::set<std::string>& taken) {
            asked_exclude = taken;
            std::vector<PeerEndpoint> out;
            for (const char* host : {"192.0.2.10", "203.0.113.7", "192.0.2.11", "192.0.2.10"})
                out.push_back(*PeerEndpoint::from(host, 8333));
            return out;
        };
        const auto c = pool_candidates(explicit_peers, {"192.0.2.11:8333"}, {"198.51.100.2:9333"},
                                       manager);
        std::vector<std::string> keys;
        for (const auto& ep : c)
            keys.push_back(ep.to_string());
        CHECK((keys == std::vector<std::string>{"203.0.113.7:8333", "192.0.2.10:8333"}),
              "[C] explicit first; a pooled, a fan-out, an invalid and a repeated key skipped");
        CHECK(asked_exclude.count("203.0.113.7:8333") && asked_exclude.count("198.51.100.2:9333")
                  && asked_exclude.count("192.0.2.11:8333"),
              "[C] the manager is asked to exclude the explicit, fan-out and pooled keys");
        const auto none = pool_candidates({}, {}, {}, nullptr);
        CHECK(none.empty(), "[C] no explicit peers and no manager: no candidates");
        const auto only_explicit = pool_candidates(explicit_peers, {}, {}, nullptr);
        CHECK(only_explicit.size() == 2, "[C] explicit peers alone (no discovery)");
    }

    // ── [D] headers from any peer ─────────────────────────────────────────────
    {
        Harness hx;
        hx.caught_up = false;
        hx.pool->tick();
        handshake(hx, 3);
        auto live = handshaked_peers(hx);
        // A 3-header v2 chain from the second peer.
        std::vector<BlockHeaderType> hdrs;
        uint256 prev = hx.root;
        for (uint32_t i = 1; i <= 3; ++i) {
            hdrs.push_back(header_of(make_block(prev, 970000 + i, 100 + i)));
            prev = block_hash(hdrs.back());
        }
        live[1]->send_headers(hdrs);
        CHECK(hx.forwarded.size() == 1 && hx.height == 970003,
              "[D] a connecting v2 batch from any peer reaches the header chain path");
        // A full batch: the sender is asked for the next from its last identity.
        std::vector<BlockHeaderType> full;
        prev = hx.tip_hash;
        for (uint32_t i = 0; i < kCoinPoolFullHeadersBatch; ++i) {
            full.push_back(header_of(make_block(prev, 970004 + i, 1000 + i)));
            prev = block_hash(full.back());
        }
        live[2]->getheaders.clear();
        live[2]->send_headers(full);
        CHECK(!live[2]->getheaders.empty()
                  && live[2]->getheaders.back() == std::vector<uint256>{block_hash(full.back())},
              "[D] a full batch asks its sender from the last header's BLAKE2b identity");
        CHECK(live[2]->getheaders.back().front() != sha256d_of(full.back()),
              "[D] ... not from SHA256d(header)");
        // An announced unknown block asks the announcer with the locator.
        live[0]->getheaders.clear();
        uint256 unknown;
        unknown.SetHex("00000000000000000000000000000000000000000000000000000000000dead1");
        live[0]->hooks.block_announced(unknown);
        CHECK(live[0]->getheaders.size() == 1
                  && live[0]->getheaders[0] == std::vector<uint256>{hx.tip_hash},
              "[D] an unknown announced block asks its announcer with the locator");
    }

    // ── [E] bodies by identity ────────────────────────────────────────────────
    {
        Harness hx;
        hx.pool->tick();
        handshake(hx, 3);
        auto live = handshaked_peers(hx);
        const BlockType blk = make_block(hx.root, 970001, 7, {make_spend(0)});
        hx.add(blk);
        const uint256 id = block_hash(blk);
        CHECK(!live[0]->hooks.fetch(sha256d_of(blk), true),
              "[E] a body announced by SHA256d(header) is not fetched (no such header)");
        CHECK(live[0]->hooks.fetch(id, true), "[E] the first announcer of the identity fetches it");
        CHECK(!live[1]->hooks.fetch(id, true), "[E] a second announcer does not");
        live[0]->hooks.full_block(blk);
        live[1]->hooks.full_block(blk);
        CHECK(hx.connected_blocks == std::vector<uint256>{id}, "[E] the body is connected once");
        CHECK(hx.forwarded_blocks == std::vector<uint256>{id}, "[E] ... and reaches full_block once");
    }

    // ── [F] chain order ───────────────────────────────────────────────────────
    {
        Harness hx;
        hx.track_utxo = true;
        hx.utxo_best = 970000;
        hx.pool->tick();
        handshake(hx, 2);
        auto live = handshaked_peers(hx);
        const BlockType n0 = make_block(hx.root, 970001, 21, {make_spend(1)});
        const BlockType n1 = make_block(block_hash(n0), 970002, 22, {make_spend(2)});
        hx.add(n0);
        hx.add(n1);
        const uint256 h0 = block_hash(n0), h1 = block_hash(n1);
        CHECK(live[0]->hooks.fetch(h1, true), "[F] the child is fetched");
        live[0]->hooks.full_block(n1);
        CHECK(hx.connected_blocks.empty() && hx.forwarded_blocks == std::vector<uint256>{h1},
              "[F] the child's mempool pass runs, its UTXO connect waits");
        CHECK(asks_for(hx, h0) == 1, "[F] the parent is asked for by its BLAKE2b identity");
        FakePeer* asked = live[0]->asked_for(h0) ? live[0] : live[1];
        asked->hooks.full_block(n0);
        CHECK((hx.connected_blocks == std::vector<uint256>{h0, h1}), "[F] both connect in chain order");
        CHECK(hx.utxo_best == std::optional<uint32_t>(970002), "[F] the UTXO view is at the child");
        CHECK(hx.late_connects == std::vector<uint256>{h1}, "[F] one late-connect pass, for the child");
    }

    // ── [G] the BIP-110 body rules gate both paths ────────────────────────────
    {
        Harness hx;
        hx.pool->tick();
        handshake(hx, 3);
        auto live = handshaked_peers(hx);
        // The header commits 3 transactions; the body (which matches the
        // merkle root) has 2.
        const BlockType skew = make_block(hx.root, 970001, 31, {make_spend(3)}, uint16_t{3});
        hx.add(skew);
        const uint256 id = block_hash(skew);
        CHECK(btc::coin::basic_block_body_matches_header<Bip110BodyHashes>(skew),
              "[G] the skewed body passes every c2pool-btc check");
        CHECK(live[0]->hooks.fetch(id, true), "[G] it is fetched");
        live[0]->hooks.full_block(skew);
        CHECK(hx.connected_blocks.empty() && hx.forwarded_blocks.empty(),
              "[G] a wrong transaction count reaches neither the UTXO connect nor the mempool");
        CHECK(asks_for(hx, id) == 1 && live[0]->asked_for(id) == 0,
              "[G] ... and is asked of another peer at once");
        FakePeer* second = live[1]->asked_for(id) ? live[1] : live[2];
        FakePeer* third = second == live[1] ? live[2] : live[1];
        second->hooks.full_block(skew);
        CHECK(hx.connected_blocks.empty() && hx.forwarded_blocks.empty(),
              "[G] the same body from a second peer is refused too");
        CHECK(asks_for(hx, id) == 2 && third->asked_for(id) == 1,
              "[G] ... and the third peer, which sent none, is asked");

        // Over the RDTS weight cap, with the right count.
        Harness hw;
        hw.pool->tick();
        handshake(hw, 2);
        auto wl = handshaked_peers(hw);
        const BlockType heavy =
            make_block(hw.root, 970001, 41, {make_spend(5, 100000), make_spend(6, 100000)});
        hw.add(heavy);
        CHECK(block_weight(heavy) > bip110::RDTS_MAX_BLOCK_WEIGHT,
              "[G] the heavy body is over 800000 WU");
        CHECK(wl[0]->hooks.fetch(block_hash(heavy), true), "[G] the heavy body is fetched");
        wl[0]->hooks.full_block(heavy);
        CHECK(hw.connected_blocks.empty() && hw.forwarded_blocks.empty(),
              "[G] over the RDTS cap: neither the UTXO connect nor the mempool");
        // With the cap off (median time past at or after RDTS_EXPIRY_TIME).
        Harness ho;
        ho.rdts_cap = false;
        ho.pool->tick();
        handshake(ho, 2);
        auto ol = handshaked_peers(ho);
        const BlockType heavy2 =
            make_block(ho.root, 970001, 41, {make_spend(5, 100000), make_spend(6, 100000)});
        ho.add(heavy2);
        CHECK(ol[0]->hooks.fetch(block_hash(heavy2), true), "[G] cap off: fetched");
        ol[0]->hooks.full_block(heavy2);
        CHECK(ho.connected_blocks == std::vector<uint256>{block_hash(heavy2)},
              "[G] cap off: the heavy body connects");
    }

    // ── [H] won-block relay ───────────────────────────────────────────────────
    {
        Harness hx;
        hx.pool->tick();
        handshake(hx, 5);
        const BlockType won = make_block(hx.root, 970001, 51, {make_spend(7)});
        PackStream ps;
        ps << won;
        auto sp = ps.get_span();
        const std::vector<unsigned char> bytes(reinterpret_cast<const unsigned char*>(sp.data()),
                                               reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
        CHECK(hx.pool->broadcast_block(bytes) == 5, "[H] a won block goes to all 5 connected peers");
        size_t got = 0;
        for (auto& [k, p] : hx.peers)
            got += p->relayed.size();
        CHECK(got == 5, "[H] ... and to no dialing one");
        CHECK(hx.pool->broadcast_block(bytes) == 5, "[H] the same bytes again: reported, not resent");
        got = 0;
        for (auto& [k, p] : hx.peers)
            got += p->relayed.size();
        CHECK(got == 5, "[H] ... nothing resent");
        std::vector<unsigned char> other = bytes;
        other.push_back(0x00);   // different bytes, same header
        CHECK(hx.pool->broadcast_block(other) == 5, "[H] different bytes for the same header go out");
        hx.advance(kCoinPoolRelayDedupSec);
        CHECK(hx.pool->broadcast_block(bytes) == 5, "[H] after the dedupe window the bytes go again");
        got = 0;
        for (auto& [k, p] : hx.peers)
            got += p->relayed.size();
        CHECK(got == 15, "[H] 3 relays reached the 5 peers");
    }

    // ── [I] request_txs and slot_keys ─────────────────────────────────────────
    {
        Harness hx;
        hx.pool->tick();
        uint256 a, b;
        a.SetHex("00000000000000000000000000000000000000000000000000000000000000a1");
        b.SetHex("00000000000000000000000000000000000000000000000000000000000000b2");
        CHECK(hx.pool->request_txs({a}) == 0, "[I] no connected peer: nobody asked");
        CHECK(hx.pool->slot_keys().size() == 8, "[I] slot_keys lists the 8 dialing slots");
        handshake(hx, 3);
        CHECK(hx.pool->request_txs({}) == 0, "[I] nothing to ask: nobody asked");
        std::set<std::string> asked;
        for (int i = 0; i < 3; ++i) {
            CHECK(hx.pool->request_txs({a, b}) == 1, "[I] one peer asked per call");
            for (auto& [k, p] : hx.peers)
                if (p->requested_txs.size() == static_cast<size_t>(2))
                    asked.insert(k);
        }
        CHECK(asked.size() == 3, "[I] three calls asked the three connected peers in turn");
        const auto keys = hx.pool->slot_keys();
        CHECK(keys.size() == 8, "[I] slot_keys lists dialing and connected slots");
        bool all = true;
        for (const auto& k : keys)
            all = all && hx.peer(k) != nullptr;
        CHECK(all, "[I] every slot key is a dialed connection");
    }

    // ── [J] transactions ──────────────────────────────────────────────────────
    {
        Harness hx;
        hx.pool->tick();
        handshake(hx, 2);
        auto live = handshaked_peers(hx);
        const auto [tx, txid] = make_tx(77);
        CHECK(txid == Bip110PoolCoin::txid(tx), "[J] the pool's txid is SHA256d of the non-witness form");
        CHECK(live[0]->hooks.fetch(txid, false), "[J] the first announcer fetches the transaction");
        CHECK(!live[1]->hooks.fetch(txid, false), "[J] a second announcer does not");
        live[0]->hooks.tx(tx);
        live[1]->hooks.tx(tx);
        CHECK(hx.forwarded_txs == 1, "[J] the transaction is passed on once");
    }

    // ── [K] a reorg onto a branch received while it competed ──────────────────
    for (const bool keep_side : {true, false}) {
        Harness hx;
        hx.track_utxo = true;
        hx.utxo_best = 970000;
        uint256 view_best = hx.root;
        std::map<uint32_t, uint256> active = {{970000, hx.root}};
        SideBodies side(8);
        // main_bip110's utxo_try_connect gate: above the best, contiguous, the
        // active chain's block.
        auto try_connect = [&](const BlockType& b) -> bool {
            const uint256 id = block_hash(b);
            auto it = hx.chain.find(id);
            if (it == hx.chain.end() || it->second <= *hx.utxo_best)
                return false;
            if (b.m_previous_block != view_best)
                return false;
            if (active[it->second] != id)
                return false;
            view_best = id;
            hx.utxo_best = it->second;
            return true;
        };
        hx.connect_override = [&](const BlockType& b) {
            if (try_connect(b))
                side.connect_ready(try_connect);
            else if (keep_side)
                side.keep(b);
        };
        hx.pool->tick();
        handshake(hx, 2);
        auto live = handshaked_peers(hx);
        const BlockType a1 = make_block(hx.root, 970001, 61, {make_spend(11)});
        hx.add(a1);
        active[970001] = block_hash(a1);
        live[0]->hooks.fetch(block_hash(a1), true);
        live[0]->hooks.full_block(a1);
        const bool a1_in = view_best == block_hash(a1);
        // A competing block at the same height: fetched (its mempool pass),
        // not connected.
        const BlockType b1 = make_block(hx.root, 970001, 62, {make_spend(12)});
        hx.add(b1);
        const bool b1_fetched = live[1]->hooks.fetch(block_hash(b1), true);
        live[1]->hooks.full_block(b1);
        const bool b1_kept = side.holds(block_hash(b1));
        // b2 on b1: the header chain follows b; the tip-changed handler rolls
        // the view back to the fork and connects the kept bodies.
        const BlockType b2 = make_block(block_hash(b1), 970002, 63, {make_spend(13)});
        hx.add(b2);
        active[970001] = block_hash(b1);
        active[970002] = block_hash(b2);
        view_best = hx.root;
        hx.utxo_best = 970000;
        side.connect_ready(try_connect);
        live[0]->hooks.fetch(block_hash(b2), true);
        live[0]->hooks.full_block(b2);
        hx.advance(btc::coin::kCoinPoolBodyHoldSec);
        hx.pool->poll();
        if (keep_side) {
            CHECK(a1_in && b1_fetched && b1_kept,
                  "[K] the competing block's body was fetched and kept, not connected");
            CHECK(view_best == block_hash(b2) && hx.utxo_best == std::optional<uint32_t>(970002),
                  "[K] after the rollback the kept body connects and the branch's next follows");
        } else {
            CHECK(view_best == hx.root,
                  "[K] without the kept body the view stays at the fork (why it is kept)");
        }
    }

    std::printf("%s\n", g_fail == 0 ? "bip110_coin_peer_pool_kat PASS" : "bip110_coin_peer_pool_kat FAIL");
    return g_fail;
}
