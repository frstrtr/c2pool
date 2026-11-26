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
//       the next one each call, all of them in one request (one getdata);
//       slot_keys lists dialing and connected slots.
//   [J] a transaction is fetched once by txid and passed on once.
//   [K] the UTXO view's follower (UtxoFollower) over the real pool: a reorg
//       onto a branch whose block was received while it competed (the kept
//       body connects after the rollback, then the branch's next block).
//   [L] the view at the fork point when the other branch wins without a
//       rollback: the kept body connects on the tip change (before the
//       plain-extension return), or after the child's body fails to connect.
//   [M] a 20-block gap: the catch-up step fetches the active chain's next 4
//       blocks (fetch_bodies) until the view is at the tip; the serve gate is
//       closed while the view is behind.
//   [N] a gap past kReanchorGap: the view is re-anchored and the tip's body
//       fetched; it anchors the view at the tip.
//   [O] an empty view anchors at the tip's body (catch-up); a view whose best
//       left the active chain without a tip change (a restart) is rolled
//       back, or re-anchored if the rollback fails.
//   [P] fetch_bodies: a block below the fetch window is fetched; a pending or
//       held one is left alone; a received one is asked again and connects
//       without a second full_block pass; never asked of a peer that sent a
//       bad body.
//   [Q] on_bad_body: once per peer and block, with the number of such peers.
//   [R] utxo_connect_gate and utxo_view_fresh.
//   [S] a rollback that fails: the view is suspended (no connect, even when
//       the chain flips back) and re-anchored at once; a failed re-anchor is
//       retried after kReanchorRetrySec by the tick, whatever the header sync.
//   [T] the work bump: a connect that brings the view to the tip calls
//       on_fresh once (the tip's body; a held body released by its parent;
//       the first connect after a re-anchor), and no other connect does.
//   [U] a view behind whose next body never comes: re-anchored at the tip
//       after kStuckReanchorSec, not before.
//   [W] the stuck re-anchor with a kept body at or above the anchor floor:
//       the emptied view anchors on it at once (no fetch of the tip's body),
//       kept bodies below the floor are dropped; ticks during header sync
//       restart the stuck clock, so the first catch-up after it fetches.
//   [V] an empty view anchors only at or above tip - kInFlight; an older
//       active body (a late catch-up body) neither anchors nor is kept; an
//       active block at or below the view's height is not kept, a competing
//       one is.
//
// No node, no network.

#include <impl/bip110/coin/block_body_check.hpp>
#include <impl/bip110/coin/coin_peer_pool.hpp>
#include <impl/bip110/coin/header_chain.hpp>
#include <impl/bip110/coin/mempool.hpp>
#include <impl/bip110/coin/template_builder.hpp>
#include <impl/bip110/coin/transaction.hpp>
#include <impl/bip110/coin/utxo_follow.hpp>

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
    // Replaces the UTXO-connect model of on_body_in_order (optional), and
    // the body consumer's best height.
    std::function<void(const BlockType&)> connect_override;
    std::function<std::optional<uint32_t>()> best_override;
    // on_bad_body reports: (block identity, bad peers).
    std::vector<std::pair<uint256, size_t>> bad_reports;
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
    std::vector<std::vector<uint256>> tx_batches;
    void request_txs(const std::vector<uint256>& txids) override
    {
        tx_batches.push_back(txids);
        PoolPeer::request_txs(txids);
    }

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
        if (best_override)
            return best_override();
        return track_utxo ? utxo_best : std::nullopt;
    };
    h.on_bad_body = [this](const BlockType& b, size_t peers) {
        bad_reports.emplace_back(block_hash(b), peers);
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

/// A UTXO view for UtxoFollower over a Harness: the active chain, the view's
/// best, its connect / rollback / re-anchor, and the pool's fetch_bodies.
struct ViewModel {
    Harness& hx;
    std::map<uint32_t, uint256> active;          // the active chain
    std::map<uint256, uint256> parent;           // id -> parent
    std::map<uint256, BlockType> bodies;         // id -> body, for delivery
    uint256 best;                                // the view (null: empty)
    uint32_t best_h = 0;
    std::vector<uint256> connected;
    int rollbacks = 0, reanchors = 0, kept_passes = 0, fresh_bumps = 0;
    bool rollback_ok = true, reanchor_ok = true;
    std::unique_ptr<UtxoFollower> f;

    explicit ViewModel(Harness& h) : hx(h)
    {
        active[hx.height] = hx.root;
        best = hx.root;
        best_h = hx.height;
        UtxoFollowHost fh;
        fh.view = [this]() { return std::make_pair(best, best_h); };
        fh.tip_height = [this]() { return hx.height; };
        fh.active_at = [this](uint32_t at) -> std::optional<uint256> {
            auto it = active.find(at);
            if (it == active.end()) return std::nullopt;
            return it->second;
        };
        fh.height_of = [this](const uint256& id) -> std::optional<uint32_t> {
            auto it = hx.chain.find(id);
            if (it == hx.chain.end()) return std::nullopt;
            return it->second;
        };
        fh.connect = [this](const BlockType& b, uint32_t at) {
            best = block_hash(b);
            best_h = at;
            connected.push_back(best);
            return true;
        };
        fh.after_kept = [this]() { ++kept_passes; };
        fh.on_fresh = [this]() { ++fresh_bumps; };
        fh.rollback = [this]() {
            ++rollbacks;
            if (!rollback_ok)
                return false;
            while (!best.IsNull()) {
                auto it = active.find(best_h);
                if (it != active.end() && it->second == best)
                    break;
                best = parent[best];
                --best_h;
            }
            return true;
        };
        fh.reanchor = [this]() {
            ++reanchors;
            if (!reanchor_ok)
                return false;
            best.SetNull();
            best_h = 0;
            return true;
        };
        fh.fetch = [this](const std::vector<uint256>& ids) { hx.pool->fetch_bodies(ids); };
        fh.now = [this]() { return hx.t; };
        f = std::make_unique<UtxoFollower>(std::move(fh));
        hx.connect_override = [this](const BlockType& b) { f->on_body(b); };
        hx.best_override = [this]() -> std::optional<uint32_t> {
            if (best.IsNull()) return std::nullopt;
            return best_h;
        };
    }

    /// A header into the chain; `tip`: it is the header tip (and its branch
    /// the active chain from its height down to `fork_h`).
    void header(const BlockType& b, bool tip)
    {
        hx.add(b);
        const uint256 id = block_hash(b);
        parent[id] = b.m_previous_block;
        bodies[id] = b;
        if (!tip)
            return;
        hx.tip_hash = id;
        hx.height = hx.chain[id];
        uint256 at = id;
        for (uint32_t h = hx.height; active.count(h) == 0 || active[h] != at; --h) {
            active[h] = at;
            at = parent[at];
            if (at.IsNull() || !hx.chain.count(at))
                break;
        }
        for (auto it = active.upper_bound(hx.height); it != active.end();)
            it = active.erase(it);
    }

    /// Deliver every body the pool asked of a connected peer and that was not
    /// delivered yet; returns the number delivered.
    size_t deliver_requested(std::set<std::pair<std::string, size_t>>& done)
    {
        size_t n = 0;
        for (auto& [key, p] : hx.peers) {
            for (size_t i = 0; i < p->requested.size(); ++i) {
                if (!done.insert({key, i}).second)
                    continue;
                auto it = bodies.find(p->requested[i]);
                if (it == bodies.end())
                    continue;
                p->hooks.full_block(it->second);
                ++n;
            }
        }
        return n;
    }
};

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
        // A host-name entry: resolved addresses take its place.
        CHECK(is_peer_hostname(NetService("seed.example.org", 8333))
                  && !is_peer_hostname(NetService("203.0.113.7", 8333))
                  && !is_peer_hostname(NetService("2001:db8::1", 8333))
                  && !is_peer_hostname(NetService("0.0.0.0", 8333)),
              "[C] a host name is told from an IP literal");
        std::vector<NetService> list = {NetService("203.0.113.7", 8333),
                                        NetService("seed.example.org", 8333),
                                        NetService("198.51.100.2", 9333)};
        const size_t added = add_resolved_peers(
            list, NetService("seed.example.org", 8333),
            {NetService("192.0.2.20", 8333), NetService("203.0.113.7", 8333), NetService("192.0.2.21", 8333)});
        std::vector<std::string> order;
        for (const auto& ep : pool_candidates(list, {}, {}, nullptr))
            order.push_back(ep.to_string());
        CHECK(added == 2
                  && (order == std::vector<std::string>{"203.0.113.7:8333", "192.0.2.20:8333",
                                                        "192.0.2.21:8333", "198.51.100.2:9333"}),
              "[C] its addresses keep its place among the explicit peers, each once");
        CHECK(peer_resolve_backoff_sec(0) == 30 && peer_resolve_backoff_sec(1) == 60
                  && peer_resolve_backoff_sec(5) == 960 && peer_resolve_backoff_sec(6) == 1800
                  && peer_resolve_backoff_sec(40) == 1800,
              "[C] a failed resolve is tried again after 30 s, doubling, at most 30 min");
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
        bool one_batch = true;
        for (auto& [k, p] : hx.peers)
            if (p->hs)
                one_batch = one_batch && p->tx_batches.size() == 1
                            && (p->tx_batches[0] == std::vector<uint256>{a, b});
        CHECK(one_batch, "[I] each call is one request for both transactions");
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
    {
        Harness hx;
        ViewModel vm(hx);
        hx.pool->tick();
        handshake(hx, 2);
        auto live = handshaked_peers(hx);
        const BlockType a1 = make_block(hx.root, 970001, 61, {make_spend(11)});
        vm.header(a1, true);
        vm.f->on_tip_changed();
        live[0]->hooks.fetch(block_hash(a1), true);
        live[0]->hooks.full_block(a1);
        const bool a1_in = vm.best == block_hash(a1);
        // A competing block at the same height: fetched (its mempool pass),
        // kept, not connected.
        const BlockType b1 = make_block(hx.root, 970001, 62, {make_spend(12)});
        vm.header(b1, false);
        const bool b1_fetched = live[1]->hooks.fetch(block_hash(b1), true);
        live[1]->hooks.full_block(b1);
        CHECK(a1_in && b1_fetched && vm.f->keeps(block_hash(b1)) && vm.best == block_hash(a1),
              "[K] the competing block's body is fetched and kept, not connected");
        // b2 on b1: the chain follows b; the tip change rolls the view back to
        // the fork and connects the kept body; b2's body follows.
        const BlockType b2 = make_block(block_hash(b1), 970002, 63, {make_spend(13)});
        vm.header(b2, true);
        CHECK(vm.f->on_tip_changed() == UtxoFollower::TipChange::RolledBack && vm.rollbacks == 1
                  && vm.best == block_hash(b1),
              "[K] the tip change rolls the view back and the kept body connects");
        live[0]->hooks.fetch(block_hash(b2), true);
        live[0]->hooks.full_block(b2);
        CHECK(vm.best == block_hash(b2) && vm.best_h == 970002 && vm.f->fresh(),
              "[K] the branch's next block follows; the view is at the tip");
    }

    // ── [L] the view at the fork point; the other branch wins, no rollback ───
    for (const bool tip_change_first : {true, false}) {
        Harness hx;
        ViewModel vm(hx);   // the view at P (the root)
        hx.pool->tick();
        handshake(hx, 2);
        auto live = handshaked_peers(hx);
        const BlockType a = make_block(hx.root, 970001, 71, {make_spend(21)});
        const BlockType b = make_block(hx.root, 970001, 72, {make_spend(22)});
        vm.header(a, true);
        vm.f->on_tip_changed();
        CHECK(live[0]->hooks.fetch(block_hash(a), true), "[L] a's body is fetched");
        vm.header(b, true);   // the equal-work switch: b is the tip
        vm.f->on_tip_changed();
        live[0]->hooks.full_block(a);
        CHECK(vm.best == hx.root && vm.f->keeps(block_hash(a)),
              "[L] a's body is kept (b is the active block), the view stays at P");
        // a2 on a: a's branch wins; the view's best P is still on the active
        // chain (no rollback).
        const BlockType a2 = make_block(block_hash(a), 970002, 73, {make_spend(23)});
        vm.header(a2, true);
        if (tip_change_first) {
            CHECK(vm.f->on_tip_changed() == UtxoFollower::TipChange::None && vm.rollbacks == 0
                      && vm.best == block_hash(a),
                  "[L] the tip change connects the kept a before the plain-extension return");
        }
        live[1]->hooks.fetch(block_hash(a2), true);
        live[1]->hooks.full_block(a2);
        hx.advance(btc::coin::kCoinPoolBodyHoldSec);
        hx.pool->poll();
        CHECK(vm.best == block_hash(a2) && vm.best_h == 970002,
              tip_change_first ? "[L] then a2's body connects"
                               : "[L] without the tip change: a2's body connects a, then a2");
    }

    // ── [M] a 20-block gap: the catch-up step ────────────────────────────────
    {
        Harness hx;
        ViewModel vm(hx);
        hx.pool->tick();
        handshake(hx, 3);
        uint256 prev = hx.root;
        std::vector<BlockType> chain20;
        for (uint32_t i = 1; i <= 20; ++i) {
            chain20.push_back(make_block(prev, 970000 + i, 800 + i, {make_spend(100 + i)}));
            prev = block_hash(chain20.back());
        }
        for (const auto& blk : chain20)
            vm.header(blk, true);
        CHECK(!vm.f->fresh(), "[M] 20 blocks behind: the serve gate's view term is closed");
        // The tip's body comes by announcement first (the gap is too large for
        // the pool's hold): kept.
        auto live = handshaked_peers(hx);
        CHECK(live[0]->hooks.fetch(block_hash(chain20.back()), true), "[M] the tip's body is fetched");
        live[0]->hooks.full_block(chain20.back());
        CHECK(vm.f->keeps(block_hash(chain20.back())), "[M] ... and kept");
        std::set<std::pair<std::string, size_t>> done;
        bool bounded = true, ordered = true;
        int steps = 0;
        for (; steps < 20 && vm.best != block_hash(chain20.back()); ++steps) {
            const auto step = vm.f->catch_up();
            bounded = bounded && step.fetched.size() <= UtxoFollower::kInFlight;
            if (step.step != UtxoFollower::Step::Fetch)
                ordered = false;
            vm.deliver_requested(done);
            hx.advance(3);
            hx.pool->poll();
        }
        CHECK(bounded && ordered, "[M] each step fetches at most 4 bodies of the active chain");
        CHECK(vm.best == block_hash(chain20.back()) && vm.best_h == 970020,
              "[M] the view reaches the tip (the kept tip body connects last)");
        bool in_order = vm.connected.size() == 20;
        for (size_t i = 0; in_order && i < 20; ++i)
            in_order = vm.connected[i] == block_hash(chain20[i]);
        CHECK(in_order, "[M] the 20 blocks connect in chain order");
        CHECK(vm.f->fresh(), "[M] at the tip: the serve gate's view term is open");
    }

    // ── [N] a gap past kReanchorGap: re-anchor ────────────────────────────────
    {
        Harness hx;
        ViewModel vm(hx);
        hx.pool->tick();
        handshake(hx, 2);
        uint256 prev = hx.root;
        BlockType last;
        for (uint32_t i = 1; i <= UtxoFollower::kReanchorGap + 12; ++i) {
            last = make_block(prev, 970000 + i, 5000 + i);
            prev = block_hash(last);
            vm.header(last, true);
        }
        const auto step = vm.f->catch_up();
        CHECK(step.step == UtxoFollower::Step::Reanchor && vm.reanchors == 1 && vm.best.IsNull()
                  && step.fetched == std::vector<uint256>{block_hash(last)},
              "[N] 300 behind: the view is re-anchored and the tip's body fetched");
        std::set<std::pair<std::string, size_t>> done;
        vm.deliver_requested(done);
        CHECK(vm.best == block_hash(last) && vm.f->fresh(),
              "[N] the tip's body anchors the view at the tip");
    }

    // ── [O] the first anchor; a view off the active chain at catch-up ─────────
    {
        Harness hx;
        ViewModel vm(hx);
        vm.best.SetNull();   // an empty view (the live case after the fork)
        vm.best_h = 0;
        hx.pool->tick();
        handshake(hx, 2);
        const BlockType t1 = make_block(hx.root, 970001, 91, {make_spend(31)});
        vm.header(t1, true);
        CHECK(!vm.f->fresh(), "[O] an empty view: the serve gate's view term is closed");
        const auto step = vm.f->catch_up();
        CHECK(step.step == UtxoFollower::Step::Anchor
                  && step.fetched == std::vector<uint256>{block_hash(t1)},
              "[O] an empty view: the tip's body is fetched");
        std::set<std::pair<std::string, size_t>> done;
        vm.deliver_requested(done);
        CHECK(vm.best == block_hash(t1) && vm.f->fresh(), "[O] ... and anchors the view");
        // The chain moves to another branch while the view is not told (a
        // restart): the catch-up step rolls back.
        const BlockType u1 = make_block(hx.root, 970001, 92, {make_spend(32)});
        const BlockType u2 = make_block(block_hash(u1), 970002, 93, {make_spend(33)});
        vm.header(u1, false);
        vm.header(u2, true);
        const auto back = vm.f->catch_up();
        CHECK(back.step == UtxoFollower::Step::Rollback && vm.rollbacks == 1 && vm.best == hx.root,
              "[O] the view's best off the active chain: rolled back to the fork");
        // A view off the chain whose rollback fails: re-anchored.
        Harness hy;
        ViewModel vy(hy);
        vy.rollback_ok = false;
        const BlockType x1 = make_block(hy.root, 970001, 94);
        const BlockType y1 = make_block(hy.root, 970001, 95);
        vy.header(x1, true);
        vy.best = block_hash(x1);
        vy.best_h = 970001;
        vy.header(y1, true);
        const auto ra = vy.f->catch_up();
        CHECK(ra.step == UtxoFollower::Step::Reanchor && vy.rollbacks == 1 && vy.reanchors == 1,
              "[O] a failed rollback: the view is re-anchored");
    }

    // ── [P] fetch_bodies ──────────────────────────────────────────────────────
    {
        Harness hx;
        hx.pool->tick();
        handshake(hx, 3);
        auto live = handshaked_peers(hx);
        uint256 prev = hx.root;
        std::vector<BlockType> c;
        for (uint32_t i = 1; i <= 12; ++i) {
            c.push_back(make_block(prev, 970000 + i, 600 + i, {make_spend(200 + i)}));
            prev = block_hash(c.back());
            hx.add(c.back());
        }
        const uint256 old_id = block_hash(c[0]);   // 12 below the tip: no announcement fetch
        CHECK(!live[0]->hooks.fetch(old_id, true), "[P] an announced block 12 below the tip is not fetched");
        CHECK(hx.pool->fetch_bodies({old_id}) == 1 && asks_for(hx, old_id) == 1,
              "[P] fetch_bodies asks for it");
        CHECK(hx.pool->fetch_bodies({old_id}) == 0, "[P] a pending one is left to its retries");
        uint256 unknown;
        unknown.SetHex("00000000000000000000000000000000000000000000000000000000000beef1");
        CHECK(hx.pool->fetch_bodies({unknown}) == 0, "[P] a block whose header is not held is not asked");
        FakePeer* asked = nullptr;
        for (auto* p : live)
            if (p->asked_for(old_id))
                asked = p;
        asked->hooks.full_block(c[0]);
        CHECK(hx.connected_blocks == std::vector<uint256>{old_id}
                  && hx.forwarded_blocks == std::vector<uint256>{old_id},
              "[P] it is delivered (connect, full_block)");
        CHECK(hx.pool->fetch_bodies({old_id}) == 1, "[P] a received one is asked again");
        for (auto* p : live)
            if (!p->requested.empty() && p->requested.back() == old_id)
                p->hooks.full_block(c[0]);
        CHECK(hx.connected_blocks.size() == 2 && hx.forwarded_blocks.size() == 1,
              "[P] ... and connects again without a second full_block pass");
        // A tip body three peers sent bad: on_bad_body per peer ([Q] below).
        const BlockType skew = make_block(prev, 970013, 699, {make_spend(299)}, uint16_t{9});
        hx.add(skew);
        const uint256 sid = block_hash(skew);
        CHECK(live[0]->hooks.fetch(sid, true), "[P] the skewed tip body is fetched");
        live[0]->hooks.full_block(skew);
        FakePeer* reasked = live[1]->asked_for(sid) ? live[1] : live[2];
        reasked->hooks.full_block(skew);
        FakePeer* third = reasked == live[1] ? live[2] : live[1];
        third->hooks.full_block(skew);
        // A received body is never asked again of a peer that sent a bad one.
        {
            Harness h2;
            h2.pool->tick();
            handshake(h2, 2);
            auto l2 = handshaked_peers(h2);
            const BlockType v = make_block(h2.root, 970001, 690, {make_spend(290)});
            h2.add(v);
            const uint256 vid = block_hash(v);
            CHECK(l2[0]->hooks.fetch(vid, true), "[P] a body is fetched");
            BlockType junk = v;
            junk.m_txs[1].vout[0].value += 1;   // the merkle root no longer matches
            l2[0]->hooks.full_block(junk);
            l2[1]->hooks.full_block(v);
            // Twice, so the round robin starts at each peer once.
            const size_t a0 = l2[0]->asked_for(vid), a1 = l2[1]->asked_for(vid);
            bool asked_ok = true;
            for (int round = 0; round < 2; ++round) {
                asked_ok = asked_ok && h2.pool->fetch_bodies({vid}) == 1;
                l2[1]->hooks.full_block(v);   // received again
            }
            CHECK(asked_ok && l2[0]->asked_for(vid) == a0 && l2[1]->asked_for(vid) == a1 + 2,
                  "[P] asked again of the peer that sent the good body, never the bad one");
        }

        // ── [Q] on_bad_body ───────────────────────────────────────────────────
        size_t reports = 0;
        std::vector<size_t> counts;
        for (const auto& [id, n] : hx.bad_reports)
            if (id == sid) {
                ++reports;
                counts.push_back(n);
            }
        CHECK((counts == std::vector<size_t>{1, 2, 3}),
              "[Q] one report per peer that sent a bad body, with the count so far");
        live[0]->hooks.full_block(skew);
        size_t again = 0;
        for (const auto& [id, n] : hx.bad_reports)
            if (id == sid) ++again;
        CHECK(reports == 3 && again == 3, "[Q] the same peer again: no second report");
    }

    // ── [R] the connect gate and the freshness term ───────────────────────────
    {
        uint256 v, other, id;
        v.SetHex("00000000000000000000000000000000000000000000000000000000000000a1");
        other.SetHex("00000000000000000000000000000000000000000000000000000000000000a2");
        id.SetHex("00000000000000000000000000000000000000000000000000000000000000a3");
        CHECK(utxo_connect_gate(uint256(), 0, id, other, 970005, id) == UtxoConnectGate::Connect,
              "[R] an empty view: any active block anchors it");
        CHECK(utxo_connect_gate(uint256(), 0, id, other, 970005, other) == UtxoConnectGate::NotActive,
              "[R] an empty view: a block off the active chain does not");
        CHECK(utxo_connect_gate(v, 100, id, v, 100, id) == UtxoConnectGate::Below,
              "[R] at the view's best height: below");
        CHECK(utxo_connect_gate(v, 100, id, other, 101, id) == UtxoConnectGate::NotContiguous,
              "[R] a parent other than the view's best: non-contiguous");
        CHECK(utxo_connect_gate(v, 100, id, v, 101, other) == UtxoConnectGate::NotActive,
              "[R] the next block of a branch not followed: not active");
        CHECK(utxo_connect_gate(v, 100, id, v, 101, id) == UtxoConnectGate::Connect,
              "[R] the active chain's next block: connect");
        CHECK(utxo_connect_gate(uint256(), 0, id, other, 970005, id, 970006) == UtxoConnectGate::StaleAnchor
                  && utxo_connect_gate(uint256(), 0, id, other, 970006, id, 970006) == UtxoConnectGate::Connect,
              "[R] an empty view: below the anchor floor a block does not anchor, at it it does");
        auto at = [&](uint32_t h) -> std::optional<uint256> {
            if (h == 100) return v;
            return std::nullopt;
        };
        CHECK(utxo_view_fresh(v, 100, 100, at, 0) && !utxo_view_fresh(v, 100, 101, at, 0)
                  && utxo_view_fresh(v, 100, 101, at, 1) && !utxo_view_fresh(uint256(), 0, 100, at, 0)
                  && !utxo_view_fresh(other, 100, 100, at, 0),
              "[R] fresh: on the active chain within max_lag of the tip; never empty");
    }

    // ── [S] a rollback that fails ─────────────────────────────────────────────
    {
        Harness hx;
        ViewModel vm(hx);
        hx.pool->tick();
        handshake(hx, 2);
        auto live = handshaked_peers(hx);
        const BlockType a1 = make_block(hx.root, 970001, 81, {make_spend(41)});
        vm.header(a1, true);
        vm.f->on_tip_changed();
        vm.f->on_body(a1);
        vm.rollback_ok = false;
        vm.reanchor_ok = false;
        const BlockType b1 = make_block(hx.root, 970001, 82, {make_spend(42)});
        const BlockType b2 = make_block(block_hash(b1), 970002, 83, {make_spend(43)});
        vm.header(b1, false);
        vm.header(b2, true);
        CHECK(vm.f->on_tip_changed() == UtxoFollower::TipChange::RollbackFailed && vm.rollbacks == 1
                  && vm.reanchors == 1 && vm.f->suspended(),
              "[S] the rollback fails: a re-anchor at once (it fails too: suspended)");
        // The chain flips back to a before the re-anchor; a2 comes.
        const BlockType a2 = make_block(block_hash(a1), 970002, 84, {make_spend(44)});
        hx.advance(1);
        const BlockType a3 = make_block(block_hash(a2), 970003, 85, {make_spend(45)});
        vm.header(a2, true);
        vm.header(a3, true);
        CHECK(vm.f->on_tip_changed() == UtxoFollower::TipChange::RollbackFailed && vm.rollbacks == 1
                  && vm.reanchors == 1,
              "[S] a tip change while suspended: no rollback attempt, the re-anchor not yet due");
        vm.f->on_body(a2);
        CHECK(vm.best == block_hash(a1) && vm.connected.size() == 1 && vm.f->kept() == 0,
              "[S] suspended: the flipped-back chain's next body does not connect");
        vm.reanchor_ok = true;
        CHECK(vm.f->on_tick(false).step == UtxoFollower::Step::ReanchorFailed && vm.reanchors == 1,
              "[S] the re-anchor is retried only after kReanchorRetrySec");
        hx.advance(UtxoFollower::kReanchorRetrySec);
        const auto r = vm.f->on_tick(false);
        CHECK(r.step == UtxoFollower::Step::Reanchor && vm.reanchors == 2 && !vm.f->suspended()
                  && vm.best.IsNull() && r.fetched == std::vector<uint256>{block_hash(a3)},
              "[S] then re-anchored by the tick (header sync not caught up), the tip's body fetched");
        const int bumps = vm.fresh_bumps;
        vm.f->on_body(a3);
        CHECK(vm.best == block_hash(a3) && vm.fresh_bumps == bumps + 1,
              "[S] the tip's body anchors the view; one work bump (the first connect after it)");
    }

    // ── [T] the work bump when the view reaches the tip ──────────────────────
    {
        Harness hx;
        ViewModel vm(hx);   // at the root, the tip: fresh
        hx.pool->tick();
        handshake(hx, 2);
        auto live = handshaked_peers(hx);
        CHECK(vm.f->fresh() && vm.fresh_bumps == 0, "[T] at the tip: fresh, no bump yet");
        const BlockType n1 = make_block(hx.root, 970001, 121, {make_spend(51)});
        vm.header(n1, true);
        vm.f->on_tip_changed();
        CHECK(!vm.f->fresh(), "[T] the header at tip+1: not fresh");
        live[0]->hooks.fetch(block_hash(n1), true);
        live[0]->hooks.full_block(n1);
        CHECK(vm.best == block_hash(n1) && vm.fresh_bumps == 1,
              "[T] its body connects: exactly one bump");
        // Two headers; the tip's body comes before its parent's.
        const BlockType n2 = make_block(block_hash(n1), 970002, 122, {make_spend(52)});
        const BlockType n3 = make_block(block_hash(n2), 970003, 123, {make_spend(53)});
        vm.header(n2, true);
        vm.header(n3, true);
        vm.f->on_tip_changed();
        live[1]->hooks.fetch(block_hash(n3), true);
        live[1]->hooks.full_block(n3);
        CHECK(vm.fresh_bumps == 1, "[T] the tip's body held for its parent: no bump");
        FakePeer* asked = live[0]->asked_for(block_hash(n2)) ? live[0] : live[1];
        asked->hooks.full_block(n2);
        CHECK(vm.best == block_hash(n3) && vm.fresh_bumps == 2,
              "[T] the parent connects (not at the tip: no bump), then the tip: one bump");
    }

    // ── [U] the next body never comes ─────────────────────────────────────────
    {
        Harness hx;
        ViewModel vm(hx);
        hx.pool->tick();
        handshake(hx, 2);
        const BlockType n1 = make_block(hx.root, 970001, 131, {make_spend(61)});
        vm.header(n1, true);
        const auto first = vm.f->catch_up();
        CHECK(first.step == UtxoFollower::Step::Fetch
                  && first.fetched == std::vector<uint256>{block_hash(n1)},
              "[U] behind by one: its body is fetched");
        bool early = false;
        for (int64_t t = 0; t + 60 < UtxoFollower::kStuckReanchorSec; t += 60) {
            hx.advance(60);
            early = early || vm.f->catch_up().step == UtxoFollower::Step::Reanchor;
        }
        CHECK(!early && vm.reanchors == 0, "[U] no re-anchor before kStuckReanchorSec");
        hx.advance(60);
        const auto late = vm.f->catch_up();
        CHECK(late.step == UtxoFollower::Step::Reanchor && vm.reanchors == 1
                  && late.fetched == std::vector<uint256>{block_hash(n1)},
              "[U] after it: re-anchored at the tip, the tip's body fetched");
    }

    // ── [W] the stuck re-anchor anchors on a kept body; the stuck clock ──────
    {
        Harness hx;
        ViewModel vm(hx);   // the view at the root (970000)
        hx.pool->tick();
        handshake(hx, 2);
        uint256 prev = hx.root;
        std::vector<BlockType> c;
        for (uint32_t i = 1; i <= 8; ++i) {
            c.push_back(make_block(prev, 970000 + i, 160 + i, {make_spend(80 + i)}));
            prev = block_hash(c.back());
            vm.header(c.back(), true);
        }
        // c1's body never comes; c3 (below the floor 970004) and c6 are kept.
        vm.f->on_body(c[2]);
        vm.f->on_body(c[5]);
        CHECK(vm.f->keeps(block_hash(c[2])) && vm.f->keeps(block_hash(c[5])),
              "[W] c3 and c6 are kept (non-contiguous)");
        vm.f->catch_up();
        hx.advance(UtxoFollower::kStuckReanchorSec);
        const auto r = vm.f->catch_up();
        CHECK(r.step == UtxoFollower::Step::Reanchor && vm.reanchors == 1 && r.fetched.empty()
                  && vm.best == block_hash(c[5]) && vm.best_h == 970006,
              "[W] stuck: re-anchored on the kept c6 at once, the tip's body not fetched");
        CHECK(!vm.f->keeps(block_hash(c[2])), "[W] the kept c3, below the floor, is dropped");

        // Ticks during header sync restart the stuck clock.
        Harness hy;
        ViewModel vy(hy);
        hy.pool->tick();
        handshake(hy, 2);
        const BlockType n1 = make_block(hy.root, 970001, 171, {make_spend(91)});
        vy.header(n1, true);
        vy.f->catch_up();   // the stuck clock starts
        for (int i = 0; i < 40; ++i) {
            hy.advance(60);
            vy.f->on_tick(/*header_sync_caught_up=*/false);
        }
        const auto after = vy.f->on_tick(true);
        CHECK(after.step == UtxoFollower::Step::Fetch && vy.reanchors == 0,
              "[W] 40 min of header sync later: the first catch-up fetches, no stuck re-anchor");
    }

    // ── [V] the anchor floor; what is kept ────────────────────────────────────
    {
        Harness hx;
        ViewModel vm(hx);
        vm.best.SetNull();
        vm.best_h = 0;
        uint256 prev = hx.root;
        std::vector<BlockType> c;
        for (uint32_t i = 1; i <= 10; ++i) {
            c.push_back(make_block(prev, 970000 + i, 140 + i, {make_spend(70 + i)}));
            prev = block_hash(c.back());
            vm.header(c.back(), true);
        }
        CHECK(!vm.f->on_body(c[4]) && vm.best.IsNull() && vm.f->kept() == 0,
              "[V] an active body below tip - kInFlight neither anchors nor is kept");
        CHECK(vm.f->on_body(c[5]) && vm.best == block_hash(c[5]),
              "[V] one at tip - kInFlight anchors the view");
        CHECK(!vm.f->on_body(c[4]) && vm.f->kept() == 0,
              "[V] an active block below the view's height is not kept");
        const BlockType sib = make_block(block_hash(c[4]), 970006, 199, {make_spend(99)});
        vm.header(sib, false);
        CHECK(!vm.f->on_body(sib) && vm.f->keeps(block_hash(sib)),
              "[V] a competing block at the view's height is kept");
    }

    std::printf("%s\n", g_fail == 0 ? "bip110_coin_peer_pool_kat PASS" : "bip110_coin_peer_pool_kat FAIL");
    return g_fail;
}
