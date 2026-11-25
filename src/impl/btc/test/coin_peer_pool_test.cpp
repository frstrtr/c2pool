// The standalone coin peer pool (impl/btc/coin/coin_peer_pool.hpp): slot
// target and refill, headers and announcements from any pooled peer, the
// header-source tick over the pool, block bodies (fetched once, checked,
// retried, in chain order), transactions (fetched once, next announcer on a
// miss), the won-block fan-out and the dashboard rows. Driven with fake
// connections.
#include <gtest/gtest.h>

#include <impl/btc/coin/coin_peer_pool.hpp>

#include <algorithm>
#include <chrono>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace btc::coin;

namespace {

using Clock = std::chrono::steady_clock;

BlockHeaderType make_header(const uint256& prev, uint32_t nonce)
{
    BlockHeaderType h;
    h.m_version = 0x20000000;
    h.m_previous_block = prev;
    h.m_timestamp = 1700000000u + nonce;
    h.m_bits = 0x1d00ffff;
    h.m_nonce = nonce;
    return h;
}

std::vector<BlockHeaderType> make_chain(const uint256& prev, size_t n, uint32_t salt)
{
    std::vector<BlockHeaderType> out;
    uint256 p = prev;
    for (size_t i = 0; i < n; ++i) {
        out.push_back(make_header(p, salt * 100000u + static_cast<uint32_t>(i)));
        p = pool_header_hash(out.back());
    }
    return out;
}

uint256 some_hash(uint32_t n)
{
    return pool_header_hash(make_header(uint256::ZERO, 900000000u + n));
}

BlockType body_of(const BlockHeaderType& h)
{
    BlockType b;
    static_cast<BlockHeaderType&>(b) = h;
    return b;
}

/// A transaction and the txid it is announced by.
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
    std::map<std::string, FakePeer*> peers;   // current connections by key
    std::vector<std::pair<std::string, uint16_t>> candidates;
    std::map<std::string, int> connected_reports;
    std::set<std::string> reported_disconnected, reported_failed;
    std::map<uint256, uint32_t> chain;        // header hash -> height
    uint32_t height = 100;
    bool caught_up = false;
    int empty_hints = 0;
    int announced = 0;
    uint256 root;
    uint256 tip_hash;                         // the header tip's block
    std::set<uint256> bad_bodies;
    bool track_utxo = false;
    std::optional<uint32_t> utxo_best;
    std::vector<std::vector<BlockHeaderType>> forwarded;
    std::vector<uint256> forwarded_blocks;   // the full_block path (on arrival)
    std::vector<uint256> connected_blocks;   // the UTXO connect (in chain order)
    std::vector<uint256> late_connects;      // after_late_connect
    int forwarded_txs = 0;
    std::unique_ptr<CoinPeerPool> pool;

    explicit Harness(size_t n_candidates = 20, size_t target = kCoinPoolTargetPeers);

    std::vector<uint256> locator() const { return {root}; }

    void advance(int64_t sec) { t += std::chrono::seconds(sec); }

    /// Put a header into the chain.
    void add(const BlockHeaderType& h)
    {
        auto it = chain.find(h.m_previous_block);
        if (it == chain.end())
            return;
        const uint32_t hh = it->second + 1;
        const uint256 bh = pool_header_hash(h);
        chain.emplace(bh, hh);
        if (hh > height) {   // more work: the new tip (a same-height sibling is not)
            height = hh;
            tip_hash = bh;
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
    std::string sv{"/Satoshi:28.1.0/"};
    uint32_t height{900000};
    bool relay_throws{false};
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
    std::string subver() const override { return sv; }
    uint32_t start_height() const override { return height; }
    void send_getheaders(const std::vector<uint256>& locator, const uint256&) override
    {
        getheaders.push_back(locator);
    }
    bool relay_block(const std::vector<unsigned char>& b) override
    {
        if (relay_throws)
            throw std::runtime_error("socket gone");
        relayed.push_back(b);
        return true;
    }
    void request_block(const uint256& h) override { requested.push_back(h); }
    void request_tx(const uint256& h) override { requested_txs.push_back(h); }

    /// A headers message, as NodeP2P reports one.
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

Harness::Harness(size_t n_candidates, size_t target)
{
    root = some_hash(0);
    tip_hash = root;
    chain.emplace(root, height);
    for (size_t i = 0; i < n_candidates; ++i)
        candidates.emplace_back("44.1." + std::to_string(i) + ".7", 8333);
    CoinPeerPoolHost h;
    h.dial = [this](const NetService& a, PoolPeerHooks hk) -> std::unique_ptr<PoolPeer> {
        return std::make_unique<FakePeer>(&peers, a.to_string(), std::move(hk));
    };
    // The peer manager's shape: candidates not excluded and not backed off.
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
    h.locator = [this]() { return locator(); };
    h.tip = [this]() { return tip_hash; };
    h.after_late_connect = [this](const BlockType& b) { late_connects.push_back(pool_header_hash(b)); };
    h.height = [this]() { return height; };
    h.caught_up = [this]() { return caught_up; };
    h.on_empty_headers = [this]() { ++empty_hints; };
    h.body_valid = [this](const BlockType& b) { return bad_bodies.count(pool_header_hash(b)) == 0; };
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
    h.on_full_block = [this](const BlockType& b) { forwarded_blocks.push_back(pool_header_hash(b)); };
    // The UTXO connect's shape: a block above its best is connected.
    h.on_body_in_order = [this](const BlockType& b) {
        const uint256 bh = pool_header_hash(b);
        connected_blocks.push_back(bh);
        auto it = chain.find(bh);
        if (track_utxo && it != chain.end() && (!utxo_best || it->second > *utxo_best))
            utxo_best = it->second;
    };
    h.now = [this]() { return t; };
    pool = std::make_unique<CoinPeerPool>(std::move(h), target);
}

/// Complete `n` handshakes of the dialed connections (observed by a tick).
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

void clear_asks(Harness& hx)
{
    for (auto& [key, p] : hx.peers)
        p->getheaders.clear();
}

size_t asks_for(Harness& hx, const uint256& h)
{
    size_t n = 0;
    for (auto& [key, p] : hx.peers)
        n += p->asked_for(h);
    return n;
}

} // namespace

// ── Slots: the target, the refill, failed dials and lost links ─────────────
TEST(BtcCoinPeerPool, KeepsTheTargetAndRefills)
{
    EXPECT_EQ(kCoinPoolTargetPeers, 8u);
    EXPECT_EQ(pool_dials_needed(0, 8), 8u);
    EXPECT_EQ(pool_dials_needed(3, 8), 5u);
    EXPECT_EQ(pool_dials_needed(8, 8), 0u);
    EXPECT_EQ(pool_dials_needed(9, 8), 0u);

    EXPECT_EQ(pool_slot_verdict(true, true, 9999, 9999), PoolSlotVerdict::Keep);
    EXPECT_EQ(pool_slot_verdict(false, false, kCoinPoolDialTimeoutSec - 1, 0), PoolSlotVerdict::Keep);
    EXPECT_EQ(pool_slot_verdict(false, false, kCoinPoolDialTimeoutSec, 0), PoolSlotVerdict::DialFailed);
    EXPECT_EQ(pool_slot_verdict(false, true, 9999, kCoinPoolLostGraceSec - 1), PoolSlotVerdict::Keep);
    EXPECT_EQ(pool_slot_verdict(false, true, 9999, kCoinPoolLostGraceSec), PoolSlotVerdict::Disconnected);

    Harness hx;
    hx.caught_up = true;   // no header-source failover inside the windows below
    hx.pool->tick();
    EXPECT_EQ(hx.pool->slot_count(), 8u);   // capped at the target, not the 20 offered
    EXPECT_EQ(hx.peers.size(), 8u);
    EXPECT_EQ(hx.pool->live_count(), 0u);

    handshake(hx, 6);
    EXPECT_EQ(hx.pool->live_count(), 6u);
    EXPECT_EQ(hx.connected_reports.size(), 6u);
    EXPECT_EQ(hx.pool->slot_count(), 8u);   // nothing to refill

    // The two that never handshake are dropped as failed dials and replaced.
    std::set<std::string> silent;
    for (auto& [key, p] : hx.peers)
        if (!p->hs)
            silent.insert(key);
    hx.advance(kCoinPoolDialTimeoutSec);
    hx.pool->tick();
    EXPECT_EQ(hx.reported_failed, silent);
    EXPECT_EQ(hx.pool->slot_count(), 8u);
    for (const auto& k : silent)
        EXPECT_EQ(hx.peer(k), nullptr);

    // A link that drops and comes back within the grace window: one slot,
    // reported connected once, asked again on its new handshake.
    FakePeer* flap = handshaked_peers(hx).front();
    const std::string flap_key = flap->key;
    flap->hs = false;
    hx.advance(12);
    hx.pool->tick();
    flap->hs = true;
    flap->getheaders.clear();
    hx.advance(12);
    hx.pool->tick();
    EXPECT_EQ(hx.connected_reports[flap_key], 1);
    EXPECT_EQ(flap->getheaders.size(), 1u);
    EXPECT_EQ(hx.pool->live_count(), 6u);

    // A handshaked peer whose link stays down past the grace window is
    // dropped as a disconnect.
    FakePeer* lost = handshaked_peers(hx)[1];
    const std::string lost_key = lost->key;
    lost->hs = false;
    hx.advance(12);
    hx.pool->tick();
    EXPECT_NE(hx.peer(lost_key), nullptr);
    EXPECT_EQ(hx.pool->live_count(), 5u);
    hx.advance(kCoinPoolLostGraceSec);
    hx.pool->tick();
    EXPECT_EQ(hx.peer(lost_key), nullptr);
    EXPECT_EQ(hx.reported_disconnected.count(lost_key), 1u);
    EXPECT_EQ(hx.pool->slot_count(), 8u);

    // Fewer candidates than the target: every one is dialed, none twice.
    Harness few(3);
    few.pool->tick();
    few.pool->tick();
    EXPECT_EQ(few.pool->slot_count(), 3u);
}

// ── Headers from any pooled peer ────────────────────────────────────────────
TEST(BtcCoinPeerPool, HeadersFromAnyPeerFeedTheChain)
{
    EXPECT_EQ(pool_headers_verdict(0, true, false), PoolHeadersVerdict::Ignore);
    EXPECT_EQ(pool_headers_verdict(1, true, false), PoolHeadersVerdict::Forward);
    EXPECT_EQ(pool_headers_verdict(1999, true, false), PoolHeadersVerdict::Forward);
    EXPECT_EQ(pool_headers_verdict(2000, true, false), PoolHeadersVerdict::ForwardAndContinue);
    EXPECT_EQ(pool_headers_verdict(2000, true, true), PoolHeadersVerdict::Ignore);
    EXPECT_EQ(pool_headers_verdict(3, false, false), PoolHeadersVerdict::AskSender);
    EXPECT_EQ(pool_headers_verdict(4, false, false), PoolHeadersVerdict::Ignore);

    Harness hx;
    hx.pool->tick();
    handshake(hx, 2);
    auto live = handshaked_peers(hx);
    ASSERT_EQ(live.size(), 2u);
    FakePeer* a = live[0];
    FakePeer* b = live[1];
    clear_asks(hx);

    // A full batch from A: into the chain, and A is asked for the next one
    // from the batch's last header.
    auto batch = make_chain(hx.root, kCoinPoolFullHeadersBatch, 1);
    a->send_headers(batch);
    ASSERT_EQ(hx.forwarded.size(), 1u);
    EXPECT_EQ(hx.forwarded[0].size(), kCoinPoolFullHeadersBatch);
    ASSERT_EQ(a->getheaders.size(), 1u);
    EXPECT_EQ(a->getheaders[0], std::vector<uint256>{pool_header_hash(batch.back())});
    EXPECT_TRUE(b->getheaders.empty());

    // The same batch from B: nothing new, not passed on, nobody asked.
    b->send_headers(batch);
    EXPECT_EQ(hx.forwarded.size(), 1u);
    EXPECT_TRUE(b->getheaders.empty());

    // A one-header announcement from B on top: into the chain, no follow-up.
    auto tip = make_chain(pool_header_hash(batch.back()), 1, 2);
    b->send_headers(tip);
    ASSERT_EQ(hx.forwarded.size(), 2u);
    EXPECT_TRUE(b->getheaders.empty());

    // A small batch that does not connect: not passed on; its sender is asked
    // from the chain's locator.
    auto orphan = make_chain(some_hash(7), 1, 3);
    a->getheaders.clear();
    a->send_headers(orphan);
    EXPECT_EQ(hx.forwarded.size(), 2u);
    ASSERT_EQ(a->getheaders.size(), 1u);
    EXPECT_EQ(a->getheaders[0], hx.locator());

    // A large batch that does not connect: ignored.
    auto big_orphan = make_chain(some_hash(8), 10, 4);
    b->send_headers(big_orphan);
    EXPECT_EQ(hx.forwarded.size(), 2u);
    EXPECT_TRUE(b->getheaders.empty());

    // The genesis header (no parent) connects by itself.
    auto genesis = make_chain(uint256::ZERO, 1, 5);
    b->send_headers(genesis);
    ASSERT_EQ(hx.forwarded.size(), 3u);
    EXPECT_TRUE(b->getheaders.empty());
}

// ── getheaders on an unknown announced block ───────────────────────────────
TEST(BtcCoinPeerPool, UnknownAnnouncementAsksThatPeerWithTheLocator)
{
    EXPECT_TRUE(pool_announce_asks(false, std::numeric_limits<int64_t>::max(), false, false));
    EXPECT_FALSE(pool_announce_asks(true, kCoinPoolAskResponseSec - 1, true, false));
    EXPECT_TRUE(pool_announce_asks(true, kCoinPoolAskResponseSec, true, false));
    EXPECT_FALSE(pool_announce_asks(false, kCoinPoolAskEverySec - 1, true, false));
    EXPECT_FALSE(pool_announce_asks(false, 600, false, true));
    EXPECT_TRUE(pool_announce_asks(false, 600, true, true));

    Harness hx;
    hx.caught_up = true;
    hx.pool->tick();
    handshake(hx, 2);
    auto live = handshaked_peers(hx);
    FakePeer* a = live[0];
    FakePeer* b = live[1];
    clear_asks(hx);

    // A known block: nothing.
    b->hooks.block_announced(hx.root);
    EXPECT_TRUE(b->getheaders.empty());

    // An unknown one: that peer, and only it, gets the full locator.
    const uint256 x = some_hash(11);
    b->hooks.block_announced(x);
    ASSERT_EQ(b->getheaders.size(), 1u);
    EXPECT_EQ(b->getheaders[0], hx.locator());
    EXPECT_TRUE(a->getheaders.empty());

    // Unanswered: no second ask of B for another block within the window.
    hx.advance(kCoinPoolAskEverySec);
    b->hooks.block_announced(some_hash(12));
    EXPECT_EQ(b->getheaders.size(), 1u);
    // B answers (any headers message): the next unknown announcement asks again.
    b->send_headers({});
    b->hooks.block_announced(some_hash(13));
    EXPECT_EQ(b->getheaders.size(), 2u);
    // ... but not twice within kCoinPoolAskEverySec.
    b->send_headers({});
    b->hooks.block_announced(some_hash(14));
    EXPECT_EQ(b->getheaders.size(), 2u);

    // Caught up: every announcer of a block is asked.
    const uint256 y = some_hash(15);
    hx.advance(kCoinPoolAskEverySec);
    a->hooks.block_announced(y);
    b->send_headers({});
    b->hooks.block_announced(y);
    EXPECT_EQ(a->getheaders.size(), 1u);
    EXPECT_EQ(b->getheaders.size(), 3u);

    // Catching up: only the first announcer of a block.
    hx.caught_up = false;
    hx.advance(kCoinPoolAskResponseSec);
    clear_asks(hx);
    const uint256 z = some_hash(16);
    a->hooks.block_announced(z);
    b->hooks.block_announced(z);
    EXPECT_EQ(a->getheaders.size(), 1u);
    EXPECT_TRUE(b->getheaders.empty());
}

// ── The header-source tick over the pool ───────────────────────────────────
TEST(BtcCoinPeerPool, HeaderSourceStepOverThePool)
{
    Harness hx;
    hx.pool->tick();
    // A fresh handshake asks that peer from the locator.
    handshake(hx, 3);
    auto live = handshaked_peers(hx);
    for (auto* p : live) {
        ASSERT_EQ(p->getheaders.size(), 1u);
        EXPECT_EQ(p->getheaders[0], hx.locator());
    }

    // Catching up, ticks without progress: one peer each, round robin.
    std::vector<std::string> asked_keys;
    for (int i = 0; i < 2; ++i) {
        clear_asks(hx);
        hx.advance(12);
        hx.pool->tick();
        size_t asked = 0;
        for (auto* p : live)
            if (!p->getheaders.empty()) {
                ++asked;
                asked_keys.push_back(p->key);
            }
        EXPECT_EQ(asked, 1u);
    }
    ASSERT_EQ(asked_keys.size(), 2u);
    EXPECT_NE(asked_keys[0], asked_keys[1]);

    // A tick with progress (headers arrived): nobody.
    clear_asks(hx);
    live[0]->send_headers(make_chain(hx.root, 5, 21));
    hx.advance(12);
    hx.pool->tick();
    size_t asked = 0;
    for (auto* p : live)
        asked += p->getheaders.size();
    EXPECT_EQ(asked, 0u);

    // No progress for kNoProgressFailoverSec: the peer that moved the tip
    // least recently is dropped (a disconnect) and replaced -- not the one
    // that just sent headers.
    const std::string answered = live[0]->key;
    hx.advance(kNoProgressFailoverSec);
    hx.pool->tick();
    EXPECT_EQ(hx.reported_disconnected.size(), 1u);
    EXPECT_EQ(hx.reported_disconnected.count(answered), 0u);
    EXPECT_EQ(hx.pool->slot_count(), 8u);
    EXPECT_EQ(hx.pool->live_count(), 2u);

    // A peer handshaked less than kCoinPoolFailoverMinAgeSec ago is not a
    // failover victim.
    Harness yp;
    yp.pool->tick();
    yp.advance(30);
    for (auto& [key, p] : yp.peers)
        p->hs = true;
    yp.pool->tick();
    yp.advance(kNoProgressFailoverSec - 30);
    yp.pool->tick();   // no progress since construction: a failover
    EXPECT_TRUE(yp.reported_disconnected.empty());
    EXPECT_EQ(yp.pool->live_count(), 8u);

    // Caught up: quiet within the refresh window churns nothing; at the
    // refresh every live peer is asked; at the failover one is replaced and
    // every other live peer is asked.
    Harness cu;
    cu.caught_up = true;
    cu.pool->tick();
    handshake(cu, 4);
    clear_asks(cu);
    cu.advance(kCaughtUpRefreshSec - 12);
    cu.pool->tick();
    for (auto* p : handshaked_peers(cu))
        EXPECT_TRUE(p->getheaders.empty());
    cu.advance(12);
    cu.pool->tick();
    for (auto* p : handshaked_peers(cu))
        EXPECT_EQ(p->getheaders.size(), 1u);
    EXPECT_TRUE(cu.reported_disconnected.empty());
    cu.advance(kCaughtUpFailoverSec - kCaughtUpRefreshSec - 10);
    cu.pool->tick();   // the next refresh
    clear_asks(cu);
    cu.advance(10);
    cu.pool->tick();   // the failover, the refresh not due
    EXPECT_EQ(cu.reported_disconnected.size(), 1u);
    auto rest = handshaked_peers(cu);
    ASSERT_EQ(rest.size(), 3u);
    for (auto* p : rest)
        EXPECT_EQ(p->getheaders.size(), 1u);

    // An empty answer from a peer at exactly our height: header sync is caught
    // up (a batch of 0 < 2000). From a higher or lower peer, or a non-empty
    // answer: not.
    EXPECT_TRUE(pool_empty_headers_caught_up(0, 100, 100));
    EXPECT_FALSE(pool_empty_headers_caught_up(0, 101, 100));
    EXPECT_FALSE(pool_empty_headers_caught_up(0, 99, 100));
    EXPECT_FALSE(pool_empty_headers_caught_up(1, 100, 100));
    Harness eh;
    eh.pool->tick();
    handshake(eh, 3);
    auto ep = handshaked_peers(eh);
    ep[0]->height = eh.height;
    ep[0]->send_headers({});
    EXPECT_EQ(eh.empty_hints, 1);
    ep[1]->height = eh.height + 1;
    ep[1]->send_headers({});
    EXPECT_EQ(eh.empty_hints, 1);
    ep[2]->height = eh.height - 1;
    ep[2]->send_headers({});
    EXPECT_EQ(eh.empty_hints, 1);
    const auto known = make_header(eh.root, 77);
    eh.add(known);
    ep[0]->height = eh.height;
    ep[0]->send_headers({known});   // one header we hold: ignored, not empty
    EXPECT_EQ(eh.empty_hints, 1);
}

// ── Block bodies: fetched once, retried, checked ───────────────────────────
TEST(BtcCoinPeerPool, BodiesAreFetchedOnceAndRetried)
{
    EXPECT_EQ(pool_body_retry_sec(true), kCoinPoolTipBodyRetrySec);
    EXPECT_EQ(pool_body_retry_sec(false), kCoinPoolBodyRetrySec);

    Harness hx;
    hx.caught_up = true;   // no header-source failover inside the windows below
    hx.pool->tick();
    handshake(hx, 3);
    auto live = handshaked_peers(hx);
    FakePeer* a = live[0];
    FakePeer* b = live[1];

    // The first announcer of a block whose header the chain holds fetches it.
    const auto blk = make_header(hx.root, 31);
    hx.add(blk);
    const uint256 bh = pool_header_hash(blk);
    EXPECT_TRUE(a->hooks.fetch(bh, true));
    EXPECT_FALSE(b->hooks.fetch(bh, true));
    // A block whose header the chain does not hold: not fetched, not tracked.
    EXPECT_FALSE(a->hooks.fetch(pool_header_hash(make_header(some_hash(5), 1)), true));
    EXPECT_EQ(hx.pool->tracked_bodies(), 1u);

    // The body reaches the coin node once, whoever sends it.
    a->hooks.full_block(body_of(blk));
    b->hooks.full_block(body_of(blk));
    ASSERT_EQ(hx.forwarded_blocks.size(), 1u);
    EXPECT_EQ(hx.forwarded_blocks[0], bh);
    EXPECT_FALSE(b->hooks.fetch(bh, true));

    // A body nobody asked for is dropped.
    const auto sibling = make_header(hx.root, 34);
    hx.add(sibling);
    a->hooks.full_block(body_of(sibling));
    EXPECT_EQ(hx.forwarded_blocks.size(), 1u);

    // A body not received is asked of another peer after kCoinPoolBodyRetrySec
    // (not the tip), each time of a different peer than the last, at most
    // kCoinPoolBodyMaxAsks asks in all.
    const auto two = make_chain(bh, 2, 33);
    hx.add(two[0]);
    hx.add(two[1]);
    const uint256 missing = pool_header_hash(two[0]);
    EXPECT_TRUE(a->hooks.fetch(missing, true));
    hx.advance(kCoinPoolBodyRetrySec - 1);
    hx.pool->tick();
    EXPECT_EQ(asks_for(hx, missing), 0u);
    hx.advance(1);
    hx.pool->tick();
    EXPECT_EQ(asks_for(hx, missing), 1u);
    EXPECT_EQ(a->asked_for(missing), 0u);   // not the peer that did not deliver
    FakePeer* first_retry = nullptr;
    for (auto* p : live)
        if (p->asked_for(missing))
            first_retry = p;
    ASSERT_NE(first_retry, nullptr);
    hx.advance(kCoinPoolBodyRetrySec);
    hx.pool->tick();
    EXPECT_EQ(asks_for(hx, missing), 2u);
    EXPECT_EQ(first_retry->asked_for(missing), 1u);   // the next ask went elsewhere
    for (int i = 0; i < 3; ++i) {
        hx.advance(kCoinPoolBodyRetrySec);
        hx.pool->tick();
    }
    EXPECT_EQ(asks_for(hx, missing), static_cast<size_t>(kCoinPoolBodyMaxAsks - 1));
    // Given up: a later announcement may fetch it again.
    EXPECT_TRUE(b->hooks.fetch(missing, true));
}

TEST(BtcCoinPeerPool, TipBodyIsRetriedWithinSecondsAndNotGivenUp)
{
    // The retry rule.
    EXPECT_EQ(pool_body_retry(true, 1, kCoinPoolTipBodyRetrySec - 1, 0), PoolBodyRetry::Wait);
    EXPECT_EQ(pool_body_retry(true, 1, kCoinPoolTipBodyRetrySec, 0), PoolBodyRetry::Ask);
    EXPECT_EQ(pool_body_retry(false, 1, kCoinPoolBodyRetrySec - 1, 0), PoolBodyRetry::Wait);
    EXPECT_EQ(pool_body_retry(false, 1, kCoinPoolBodyRetrySec, 0), PoolBodyRetry::Ask);
    // Out of asks: the tip's block is asked again every kCoinPoolBodyRetrySec ...
    EXPECT_EQ(pool_body_retry(true, kCoinPoolBodyMaxAsks, kCoinPoolBodyRetrySec - 1, 9999),
              PoolBodyRetry::Wait);
    EXPECT_EQ(pool_body_retry(true, kCoinPoolBodyMaxAsks + 5, kCoinPoolBodyRetrySec, 9999),
              PoolBodyRetry::Ask);
    // ... any other block is kept until kCoinPoolBodyKeepSec after the first ask.
    EXPECT_EQ(pool_body_retry(false, kCoinPoolBodyMaxAsks, 9999, kCoinPoolBodyKeepSec - 1),
              PoolBodyRetry::Wait);
    EXPECT_EQ(pool_body_retry(false, kCoinPoolBodyMaxAsks, 9999, kCoinPoolBodyKeepSec),
              PoolBodyRetry::GiveUp);

    Harness hx;
    hx.caught_up = true;
    hx.pool->tick();
    handshake(hx, 3);
    auto live = handshaked_peers(hx);
    const auto tip = make_header(hx.root, 51);
    hx.add(tip);   // the chain's tip
    const uint256 th = pool_header_hash(tip);
    EXPECT_TRUE(live[0]->hooks.fetch(th, true));
    hx.advance(kCoinPoolTipBodyRetrySec - 1);
    hx.pool->poll();
    EXPECT_EQ(asks_for(hx, th), 0u);
    hx.advance(1);
    hx.pool->poll();
    EXPECT_EQ(live[1]->asked_for(th), 1u);
    hx.advance(kCoinPoolTipBodyRetrySec);
    hx.pool->poll();
    EXPECT_EQ(asks_for(hx, th), 2u);   // kCoinPoolBodyMaxAsks asks sent in all
    // Out of asks within seconds, but the tip's block is kept and asked again.
    hx.advance(kCoinPoolTipBodyRetrySec);
    hx.pool->poll();
    EXPECT_EQ(asks_for(hx, th), 2u);
    hx.advance(kCoinPoolBodyRetrySec);
    hx.pool->poll();
    EXPECT_EQ(asks_for(hx, th), 3u);
    hx.advance(kCoinPoolBodyRetrySec * 3);
    hx.pool->poll();
    hx.pool->poll();
    EXPECT_EQ(hx.pool->tracked_bodies(), 1u);
    // It arrives late: taken.
    live[2]->hooks.full_block(body_of(tip));
    ASSERT_EQ(hx.forwarded_blocks.size(), 1u);
    EXPECT_EQ(hx.forwarded_blocks[0], th);

    // Once the tip moved on, the old tip's block is given up like any other.
    Harness mv;
    mv.caught_up = true;
    mv.pool->tick();
    handshake(mv, 3);
    auto mlive = handshaked_peers(mv);
    const auto old_tip = make_header(mv.root, 53);
    mv.add(old_tip);
    const uint256 oh = pool_header_hash(old_tip);
    ASSERT_TRUE(mlive[0]->hooks.fetch(oh, true));
    mv.advance(kCoinPoolTipBodyRetrySec);
    mv.pool->poll();
    mv.advance(kCoinPoolTipBodyRetrySec);
    mv.pool->poll();   // kCoinPoolBodyMaxAsks asks sent
    mv.add(make_header(oh, 54));   // a new tip
    mv.advance(kCoinPoolBodyKeepSec);
    mv.pool->poll();
    EXPECT_EQ(mv.pool->tracked_bodies(), 0u);
    mlive[1]->hooks.full_block(body_of(old_tip));
    EXPECT_TRUE(mv.forwarded_blocks.empty());
}

TEST(BtcCoinPeerPool, LateBodyIsTakenWithinTheKeepWindow)
{
    Harness hx;
    hx.caught_up = true;
    hx.pool->tick();
    handshake(hx, 3);
    auto live = handshaked_peers(hx);
    const auto two = make_chain(hx.root, 2, 55);
    hx.add(two[0]);
    hx.add(two[1]);
    const uint256 x = pool_header_hash(two[0]);   // not the tip
    ASSERT_TRUE(live[0]->hooks.fetch(x, true));
    hx.advance(kCoinPoolBodyRetrySec);
    hx.pool->tick();
    hx.advance(kCoinPoolBodyRetrySec);
    hx.pool->tick();
    EXPECT_EQ(asks_for(hx, x), 2u);   // out of asks
    hx.advance(kCoinPoolBodyKeepSec - 2 * kCoinPoolBodyRetrySec - 1);
    hx.pool->tick();
    EXPECT_EQ(hx.pool->tracked_bodies(), 1u);
    live[0]->hooks.full_block(body_of(two[0]));   // the first peer, late
    ASSERT_EQ(hx.forwarded_blocks.size(), 1u);
    EXPECT_EQ(hx.forwarded_blocks[0], x);
}

TEST(BtcCoinPeerPool, BodiesNotMatchingTheHeaderDoNotUseUpAsks)
{
    Harness hx;
    hx.caught_up = true;
    hx.pool->tick();
    handshake(hx, 5);
    auto live = handshaked_peers(hx);
    const auto two = make_chain(hx.root, 2, 56);
    hx.add(two[0]);
    hx.add(two[1]);
    const uint256 x = pool_header_hash(two[0]);   // not the tip
    ASSERT_TRUE(live[0]->hooks.fetch(x, true));
    hx.bad_bodies.insert(x);
    // Three bodies that do not match, each asked of another peer at once.
    FakePeer* sender = live[0];
    std::set<FakePeer*> sent;
    for (int i = 0; i < 3; ++i) {
        sent.insert(sender);
        sender->hooks.full_block(body_of(two[0]));
        FakePeer* next = nullptr;
        for (auto* p : live)
            if (p->asked_for(x) == 1 && !sent.count(p))
                next = p;
        ASSERT_NE(next, nullptr);
        sender = next;
    }
    EXPECT_TRUE(hx.forwarded_blocks.empty());
    EXPECT_EQ(asks_for(hx, x), 3u);
    // None of them used up an ask: the retry still asks at kCoinPoolBodyRetrySec.
    hx.bad_bodies.erase(x);
    hx.advance(kCoinPoolBodyRetrySec);
    hx.pool->tick();
    EXPECT_EQ(asks_for(hx, x), 4u);
    sender->hooks.full_block(body_of(two[0]));
    ASSERT_EQ(hx.forwarded_blocks.size(), 1u);
}

TEST(BtcCoinPeerPool, JunkBodiesFromUnaskedOrAlreadyBadPeersAskNobody)
{
    Harness hx;
    hx.caught_up = true;
    hx.pool->tick();
    handshake(hx, 4);
    auto live = handshaked_peers(hx);
    const auto two = make_chain(hx.root, 2, 57);
    hx.add(two[0]);
    hx.add(two[1]);
    const uint256 x = pool_header_hash(two[0]);
    ASSERT_TRUE(live[0]->hooks.fetch(x, true));
    hx.bad_bodies.insert(x);
    // A peer nobody asked: no getdata, however many it sends.
    for (int i = 0; i < 5; ++i)
        live[2]->hooks.full_block(body_of(two[0]));
    EXPECT_EQ(asks_for(hx, x), 0u);
    // The asked peer: one re-ask, the first time only.
    live[0]->hooks.full_block(body_of(two[0]));
    EXPECT_EQ(asks_for(hx, x), 1u);
    live[0]->hooks.full_block(body_of(two[0]));
    live[2]->hooks.full_block(body_of(two[0]));
    EXPECT_EQ(asks_for(hx, x), 1u);
    EXPECT_EQ(live[2]->asked_for(x), 0u);   // a junk sender is not asked
}

TEST(BtcCoinPeerPool, TheTipIsTheTipBlockNotItsHeight)
{
    Harness hx;
    hx.caught_up = true;
    hx.pool->tick();
    handshake(hx, 2);
    auto live = handshaked_peers(hx);
    const auto tip = make_header(hx.root, 58);
    const auto sibling = make_header(hx.root, 59);   // the same height, not the tip
    hx.add(tip);
    hx.add(sibling);
    ASSERT_EQ(hx.tip_hash, pool_header_hash(tip));
    const uint256 sh = pool_header_hash(sibling);
    ASSERT_TRUE(live[0]->hooks.fetch(sh, true));
    hx.advance(kCoinPoolTipBodyRetrySec);
    hx.pool->poll();
    EXPECT_EQ(asks_for(hx, sh), 0u);   // not the tip's short retry
    hx.advance(kCoinPoolBodyRetrySec - kCoinPoolTipBodyRetrySec);
    hx.pool->poll();
    EXPECT_EQ(asks_for(hx, sh), 1u);
}

TEST(BtcCoinPeerPool, BodyNotMatchingItsHeaderIsAskedOfAnotherPeer)
{
    Harness hx;
    hx.caught_up = true;
    hx.pool->tick();
    handshake(hx, 3);
    auto live = handshaked_peers(hx);
    FakePeer* a = live[0];
    const auto blk = make_header(hx.root, 52);
    hx.add(blk);
    const uint256 bh = pool_header_hash(blk);
    ASSERT_TRUE(a->hooks.fetch(bh, true));
    hx.bad_bodies.insert(bh);
    a->hooks.full_block(body_of(blk));
    EXPECT_TRUE(hx.forwarded_blocks.empty());
    EXPECT_EQ(a->asked_for(bh), 0u);
    FakePeer* other = nullptr;
    for (auto* p : live)
        if (p->asked_for(bh))
            other = p;
    ASSERT_NE(other, nullptr);   // asked of another peer at once
    hx.bad_bodies.erase(bh);
    other->hooks.full_block(body_of(blk));
    ASSERT_EQ(hx.forwarded_blocks.size(), 1u);
    EXPECT_EQ(hx.forwarded_blocks[0], bh);
}

TEST(BtcCoinPeerPool, BodiesAreConnectedInChainOrder)
{
    EXPECT_EQ(pool_body_order(std::nullopt, 500), PoolBodyOrder::Deliver);
    EXPECT_EQ(pool_body_order(100, 100), PoolBodyOrder::Deliver);
    EXPECT_EQ(pool_body_order(100, 101), PoolBodyOrder::Deliver);
    EXPECT_EQ(pool_body_order(100, 102), PoolBodyOrder::Hold);
    EXPECT_EQ(pool_body_order(100, 101 + kCoinPoolMaxBodyGap), PoolBodyOrder::Hold);
    EXPECT_EQ(pool_body_order(100, 102 + kCoinPoolMaxBodyGap), PoolBodyOrder::DeliverWithGap);

    // N+1 before N: its full_block pass (mempool cleanup) runs at once, its
    // UTXO connect waits; N is asked for, then both connect in order.
    Harness hx;
    hx.caught_up = true;
    hx.track_utxo = true;
    hx.utxo_best = 100;
    hx.pool->tick();
    handshake(hx, 2);
    auto live = handshaked_peers(hx);
    const auto n = make_chain(hx.root, 2, 61);
    hx.add(n[0]);
    hx.add(n[1]);
    const uint256 h0 = pool_header_hash(n[0]);
    const uint256 h1 = pool_header_hash(n[1]);
    ASSERT_TRUE(live[0]->hooks.fetch(h1, true));
    live[0]->hooks.full_block(body_of(n[1]));
    EXPECT_EQ(hx.forwarded_blocks, std::vector<uint256>{h1});
    EXPECT_TRUE(hx.connected_blocks.empty());
    EXPECT_EQ(asks_for(hx, h0), 1u);
    FakePeer* asked = live[0]->asked_for(h0) ? live[0] : live[1];
    asked->hooks.full_block(body_of(n[0]));
    EXPECT_EQ(hx.connected_blocks, (std::vector<uint256>{h0, h1}));
    EXPECT_EQ(hx.forwarded_blocks, (std::vector<uint256>{h1, h0}));
    EXPECT_EQ(hx.utxo_best, std::optional<uint32_t>(102));
    // The held one's UTXO-based mempool maintenance runs after its connect.
    EXPECT_EQ(hx.late_connects, std::vector<uint256>{h1});

    // A parent that does not come: the held body connects after the hold limit.
    Harness hl;
    hl.caught_up = true;
    hl.track_utxo = true;
    hl.utxo_best = 100;
    hl.pool->tick();
    handshake(hl, 2);
    auto hlive = handshaked_peers(hl);
    const auto m = make_chain(hl.root, 2, 62);
    hl.add(m[0]);
    hl.add(m[1]);
    const uint256 m1 = pool_header_hash(m[1]);
    ASSERT_TRUE(hlive[0]->hooks.fetch(m1, true));
    hlive[0]->hooks.full_block(body_of(m[1]));
    EXPECT_EQ(hl.forwarded_blocks, std::vector<uint256>{m1});
    hl.advance(kCoinPoolBodyHoldSec - 1);
    hl.pool->poll();
    EXPECT_TRUE(hl.connected_blocks.empty());
    hl.advance(1);
    hl.pool->poll();
    EXPECT_EQ(hl.connected_blocks, std::vector<uint256>{m1});
    EXPECT_EQ(hl.late_connects, std::vector<uint256>{m1});

    // A gap of more than kCoinPoolMaxBodyGap blocks (a node that was down):
    // connected as it is.
    Harness gp;
    gp.caught_up = true;
    gp.track_utxo = true;
    gp.utxo_best = 100;
    gp.pool->tick();
    handshake(gp, 1);
    auto gpeer = handshaked_peers(gp).front();
    const auto far = make_chain(gp.root, kCoinPoolMaxBodyGap + 2, 63);
    for (const auto& x : far)
        gp.add(x);
    const uint256 top = pool_header_hash(far.back());
    ASSERT_TRUE(gpeer->hooks.fetch(top, true));
    gpeer->hooks.full_block(body_of(far.back()));
    EXPECT_EQ(gp.connected_blocks, std::vector<uint256>{top});
    EXPECT_EQ(gp.forwarded_blocks, std::vector<uint256>{top});
    EXPECT_TRUE(gp.late_connects.empty());

    // The hold full: one more body is not connected out of order; its
    // full_block pass runs once, it is not downloaded again while the hold is
    // full, and is asked for (its connect only) once the hold has room.
    Harness hf;
    hf.caught_up = true;
    hf.track_utxo = true;
    hf.utxo_best = 100;
    hf.pool->tick();
    handshake(hf, 2);
    auto flive = handshaked_peers(hf);
    const auto c = make_chain(hf.root, kCoinPoolMaxBodyGap + 1, 65);   // heights 101..107
    for (const auto& x : c)
        hf.add(x);
    for (size_t i = 1; i < c.size(); ++i) {
        ASSERT_TRUE(flive[0]->hooks.fetch(pool_header_hash(c[i]), true));
        flive[0]->hooks.full_block(body_of(c[i]));
    }
    EXPECT_TRUE(hf.connected_blocks.empty());   // six held
    const auto side = make_header(pool_header_hash(c[1]), 66);   // height 103, beside c[2]
    hf.add(side);
    const uint256 sh = pool_header_hash(side);
    ASSERT_TRUE(flive[0]->hooks.fetch(sh, true));
    flive[0]->hooks.full_block(body_of(side));
    EXPECT_TRUE(hf.connected_blocks.empty());
    EXPECT_EQ(std::count(hf.forwarded_blocks.begin(), hf.forwarded_blocks.end(), sh), 1);
    EXPECT_FALSE(flive[1]->hooks.fetch(sh, true));   // still tracked: asked for again later
    hf.advance(kCoinPoolTipBodyRetrySec);
    hf.pool->poll();
    EXPECT_EQ(asks_for(hf, sh), 0u);   // the hold is still full
    // The parent of the first held body arrives: all six connect in order.
    const uint256 c0 = pool_header_hash(c[0]);
    FakePeer* asked0 = flive[0]->asked_for(c0) ? flive[0] : flive[1];
    asked0->hooks.full_block(body_of(c[0]));
    std::vector<uint256> want;
    for (const auto& x : c)
        want.push_back(pool_header_hash(x));
    EXPECT_EQ(hf.connected_blocks, want);
    EXPECT_EQ(hf.late_connects.size(), c.size() - 1);   // the six held ones
    // Room again: the side block is asked for once, connected, and its
    // full_block pass does not run a second time.
    hf.advance(kCoinPoolTipBodyRetrySec);
    hf.pool->poll();
    ASSERT_EQ(asks_for(hf, sh), 1u);
    FakePeer* again = flive[0]->asked_for(sh) ? flive[0] : flive[1];
    again->hooks.full_block(body_of(side));
    EXPECT_EQ(hf.connected_blocks.back(), sh);
    EXPECT_EQ(std::count(hf.forwarded_blocks.begin(), hf.forwarded_blocks.end(), sh), 1);
    EXPECT_EQ(hf.late_connects.back(), sh);
}

TEST(BtcCoinPeerPool, OnlyBodiesNearTheTipAreFetched)
{
    EXPECT_TRUE(pool_body_wanted(100, 100, std::nullopt));
    EXPECT_TRUE(pool_body_wanted(100 - kCoinPoolMaxBodyGap - 1, 100, std::nullopt));
    EXPECT_FALSE(pool_body_wanted(100 - kCoinPoolMaxBodyGap - 2, 100, std::nullopt));
    EXPECT_TRUE(pool_body_wanted(101, 101, 101));    // a block at the UTXO set's height
    EXPECT_FALSE(pool_body_wanted(100, 101, 101));   // below it

    Harness hx;
    hx.caught_up = true;
    hx.pool->tick();
    handshake(hx, 1);
    FakePeer* p = handshaked_peers(hx).front();
    const auto c = make_chain(hx.root, 20, 67);   // heights 101..120
    for (const auto& x : c)
        hx.add(x);
    EXPECT_FALSE(p->hooks.fetch(pool_header_hash(c[4]), true));    // 105: history
    EXPECT_FALSE(p->hooks.fetch(pool_header_hash(c[11]), true));   // 112
    EXPECT_TRUE(p->hooks.fetch(pool_header_hash(c[12]), true));    // 113 = 120 - 7
    hx.track_utxo = true;
    hx.utxo_best = 118;
    EXPECT_FALSE(p->hooks.fetch(pool_header_hash(c[16]), true));   // 117 < 118
    EXPECT_TRUE(p->hooks.fetch(pool_header_hash(c[17]), true));    // 118
    EXPECT_EQ(hx.pool->tracked_bodies(), 2u);
}

TEST(BtcCoinPeerPool, TrackedBodiesAreBoundedWithRoomForTheTip)
{
    Harness hx;
    hx.caught_up = true;
    hx.pool->tick();
    handshake(hx, 1);
    FakePeer* p = handshaked_peers(hx).front();
    const auto main = make_chain(hx.root, 3, 68);   // 101, 102, 103 (the tip)
    for (const auto& x : main)
        hx.add(x);
    const uint256 parent = pool_header_hash(main[0]);
    std::vector<BlockHeaderType> sides;   // height 102, beside main[1]
    for (uint32_t i = 0; i <= kCoinPoolBodiesMax; ++i) {
        sides.push_back(make_header(parent, 690000u + i));
        hx.add(sides.back());
    }
    for (size_t i = 0; i < kCoinPoolBodiesMax; ++i) {
        ASSERT_TRUE(p->hooks.fetch(pool_header_hash(sides[i]), true));
        hx.advance(1);   // sides[0] is the oldest
    }
    EXPECT_EQ(hx.pool->tracked_bodies(), kCoinPoolBodiesMax);
    // Full of bodies being fetched, none of them the tip's: no more ...
    EXPECT_FALSE(p->hooks.fetch(pool_header_hash(sides[kCoinPoolBodiesMax]), true));
    // ... but the tip's block takes the place of the oldest.
    EXPECT_TRUE(p->hooks.fetch(pool_header_hash(main[2]), true));
    EXPECT_EQ(hx.pool->tracked_bodies(), kCoinPoolBodiesMax);
    EXPECT_FALSE(p->hooks.fetch(pool_header_hash(sides[0]), true));   // evicted, no room
    // A received body makes room.
    p->hooks.full_block(body_of(sides[1]));
    EXPECT_EQ(hx.forwarded_blocks.size(), 1u);
    EXPECT_TRUE(p->hooks.fetch(pool_header_hash(sides[0]), true));
    EXPECT_EQ(hx.pool->tracked_bodies(), kCoinPoolBodiesMax);
}

TEST(BtcCoinPeerPool, OnlyATipMovingBatchRanksAPeerForFailover)
{
    Harness hx;
    hx.pool->tick();
    handshake(hx, 2);
    auto live = handshaked_peers(hx);
    FakePeer* a = live[0];
    FakePeer* b = live[1];
    const std::string a_key = a->key;   // a is gone after the failover
    hx.advance(12);
    b->send_headers(make_chain(hx.root, 5, 71));   // moves the tip 100 -> 105
    hx.pool->tick();
    hx.advance(12);
    a->send_headers({make_header(hx.root, 72)});   // a new side header at 101: no tip move
    ASSERT_EQ(hx.forwarded.size(), 2u);
    EXPECT_EQ(hx.height, 105u);
    hx.pool->tick();
    hx.advance(kNoProgressFailoverSec - 12);
    hx.pool->tick();   // no progress since B's batch: a failover
    EXPECT_EQ(hx.reported_disconnected.size(), 1u);
    EXPECT_EQ(hx.reported_disconnected.count(a_key), 1u);
}

// ── Transactions: fetched once, next announcer on a miss ───────────────────
TEST(BtcCoinPeerPool, TransactionsAreFetchedOnceWithFallback)
{
    Harness hx;
    hx.caught_up = true;
    hx.pool->tick();
    handshake(hx, 3);
    auto live = handshaked_peers(hx);
    FakePeer* a = live[0];
    FakePeer* b = live[1];
    FakePeer* c = live[2];

    auto [tx, txid] = make_tx(7);
    EXPECT_TRUE(a->hooks.fetch(txid, false));
    EXPECT_FALSE(b->hooks.fetch(txid, false));
    EXPECT_FALSE(c->hooks.fetch(txid, false));
    EXPECT_FALSE(a->hooks.fetch(txid, false));

    // Not received: asked of the next announcer after kCoinPoolTxRetrySec.
    hx.advance(kCoinPoolTxRetrySec - 1);
    hx.pool->tick();
    EXPECT_TRUE(b->requested_txs.empty());
    hx.advance(1);
    hx.pool->tick();
    ASSERT_EQ(b->requested_txs.size(), 1u);
    EXPECT_EQ(b->requested_txs[0], txid);
    EXPECT_TRUE(c->requested_txs.empty());
    // B delivers: passed on once; a late copy from A is not; C is never asked.
    b->hooks.tx(tx);
    a->hooks.tx(tx);
    EXPECT_EQ(hx.forwarded_txs, 1);
    hx.advance(kCoinPoolTxRetrySec);
    hx.pool->tick();
    EXPECT_TRUE(c->requested_txs.empty());

    // After kCoinPoolSeenTtlSec the entry is gone: fetched again.
    hx.advance(kCoinPoolSeenTtlSec);
    hx.pool->tick();
    EXPECT_EQ(hx.pool->tracked_txs(), 0u);
    EXPECT_TRUE(c->hooks.fetch(txid, false));

    // At the bound the oldest entry goes first.
    Harness cap;
    cap.pool->tick();
    handshake(cap, 1);
    FakePeer* p = handshaked_peers(cap).front();
    for (uint32_t i = 0; i < kCoinPoolSeenTxMax; ++i)
        ASSERT_TRUE(p->hooks.fetch(some_hash(1000 + i), false));
    EXPECT_EQ(cap.pool->tracked_txs(), kCoinPoolSeenTxMax);
    EXPECT_TRUE(p->hooks.fetch(some_hash(999), false));
    EXPECT_EQ(cap.pool->tracked_txs(), kCoinPoolSeenTxMax);
    EXPECT_FALSE(p->hooks.fetch(some_hash(1001), false));   // still tracked
    EXPECT_TRUE(p->hooks.fetch(some_hash(1000), false));    // the oldest: evicted
}

// ── A won block goes to every connected pooled peer ────────────────────────
TEST(BtcCoinPeerPool, WonBlockReachesEveryConnectedPeer)
{
    Harness hx;
    hx.pool->tick();
    handshake(hx, 6);
    const std::vector<unsigned char> block(300, 0xab);
    EXPECT_EQ(hx.pool->broadcast_block(block), 6u);
    for (auto& [key, p] : hx.peers) {
        if (p->hs) {
            ASSERT_EQ(p->relayed.size(), 1u);
            EXPECT_EQ(p->relayed[0], block);
        } else {
            EXPECT_TRUE(p->relayed.empty());   // no handshake: not sent
        }
    }
    // The same bytes again: not resent.
    EXPECT_EQ(hx.pool->broadcast_block(block), 6u);
    for (auto& [key, p] : hx.peers)
        EXPECT_LE(p->relayed.size(), 1u);
    // The same header with different bytes (the share-chain reconstruction
    // after the stratum block): sent.
    std::vector<unsigned char> same_header(block.begin(), block.begin() + 80);
    same_header.resize(300, 0xee);
    EXPECT_EQ(hx.pool->broadcast_block(same_header), 6u);
    for (auto& [key, p] : hx.peers)
        if (p->hs) {
            ASSERT_EQ(p->relayed.size(), 2u);
            EXPECT_EQ(p->relayed[1], same_header);
        }
    for (auto& [key, p] : hx.peers)
        p->relayed.clear();

    // One connection failing does not stop the others.
    std::vector<unsigned char> block2(300, 0xcd);
    handshaked_peers(hx).front()->relay_throws = true;
    EXPECT_EQ(hx.pool->broadcast_block(block2), 5u);
    size_t got = 0;
    for (auto& [key, p] : hx.peers)
        if (p->relayed.size() == 1)
            ++got;
    EXPECT_EQ(got, 5u);
    // After kCoinPoolRelayDedupSec the same block may go out again.
    hx.advance(kCoinPoolRelayDedupSec);
    EXPECT_EQ(hx.pool->broadcast_block(block), 5u);
    // ask_all: getheaders to every connected peer (the tip-reconcile poll).
    clear_asks(hx);
    EXPECT_EQ(hx.pool->ask_all(hx.locator()), 6u);

    // A relay that reached nobody does not block the next try.
    Harness empty;
    EXPECT_EQ(empty.pool->broadcast_block(block), 0u);
    empty.pool->tick();
    handshake(empty, 2);
    EXPECT_EQ(empty.pool->broadcast_block(block), 2u);
}

// ── Dashboard rows ──────────────────────────────────────────────────────────
TEST(BtcCoinPeerPool, DashboardRowsListEveryConnectedPeer)
{
    std::vector<CoinPeerRow> live = {
        {"44.2.0.1:8333", true, "/Satoshi:28.1.0/", 925000, 60},
        {"192.168.1.5:8333", false, "/Satoshi:27.0.0/", 925010, 30},
    };
    auto rows = coin_peer_rows(live, {"44.2.0.1:8333", "44.2.0.9:8333"});
    EXPECT_EQ(rows.max_start_height, 925010u);
    ASSERT_EQ(rows.peers.size(), 3u);
    EXPECT_EQ(rows.peers[0]["addr"], "44.2.0.1:8333");
    EXPECT_EQ(rows.peers[0]["subver"], "/Satoshi:28.1.0/");
    EXPECT_EQ(rows.peers[0]["startingheight"], 925000);
    EXPECT_EQ(rows.peers[0]["conntime"], 60);
    EXPECT_EQ(rows.peers[0]["connected"], true);
    EXPECT_EQ(rows.peers[1]["addr"], "private");   // not routable: never by address
    EXPECT_EQ(rows.peers[1]["connected"], true);
    EXPECT_EQ(rows.peers[2]["addr"], "44.2.0.9:8333");   // idle; the connected one is not repeated
    EXPECT_EQ(rows.peers[2]["connected"], false);
    EXPECT_FALSE(rows.peers[2].contains("startingheight"));

    // The pool's rows: every pooled peer with a completed handshake, with its
    // version's subver / height and the time since the handshake.
    Harness hx(0);
    hx.candidates = {{"44.3.0.1", 8333}, {"10.0.0.7", 8333}, {"44.3.0.2", 8333}};
    hx.pool->tick();
    ASSERT_EQ(hx.peers.size(), 3u);
    hx.peers["44.3.0.1:8333"]->hs = true;
    hx.peers["10.0.0.7:8333"]->hs = true;
    hx.peers["10.0.0.7:8333"]->height = 925001;
    hx.pool->tick();
    hx.advance(45);
    auto pr = hx.pool->rows();
    ASSERT_EQ(pr.size(), 2u);
    std::map<std::string, CoinPeerRow> by_addr;
    for (const auto& r : pr)
        by_addr[r.addr] = r;
    EXPECT_TRUE(by_addr.at("44.3.0.1:8333").routable);
    EXPECT_FALSE(by_addr.at("10.0.0.7:8333").routable);
    EXPECT_EQ(by_addr.at("10.0.0.7:8333").start_height, 925001u);
    EXPECT_EQ(by_addr.at("44.3.0.1:8333").subver, "/Satoshi:28.1.0/");
    EXPECT_EQ(by_addr.at("44.3.0.1:8333").conntime, 45);
    auto dash = coin_peer_rows(pr, {});
    ASSERT_EQ(dash.peers.size(), 2u);
    for (const auto& p : dash.peers)
        EXPECT_NE(p["addr"], "10.0.0.7:8333");
}

// ── A dropped connection's late events are ignored ─────────────────────────
TEST(BtcCoinPeerPool, DroppedConnectionEventsAreIgnored)
{
    Harness hx(8);
    hx.pool->tick();
    FakePeer* p = hx.peers.begin()->second;
    const PoolPeerHooks saved = p->hooks;
    hx.advance(kCoinPoolDialTimeoutSec);
    hx.pool->tick();   // never handshaked: dropped (no candidates left to refill)
    EXPECT_EQ(hx.pool->slot_count(), 0u);
    saved.headers_message(1);
    saved.headers(make_chain(hx.root, 1, 41));
    EXPECT_TRUE(hx.forwarded.empty());
    EXPECT_FALSE(saved.fetch(some_hash(42), true));
    EXPECT_FALSE(saved.fetch(some_hash(43), false));
    const auto blk = make_header(hx.root, 43);
    hx.add(blk);
    saved.full_block(body_of(blk));
    EXPECT_TRUE(hx.forwarded_blocks.empty());
    auto [tx, txid] = make_tx(44);
    saved.tx(tx);
    EXPECT_EQ(hx.forwarded_txs, 0);
    saved.block_announced(some_hash(45));
    EXPECT_EQ(hx.announced, 0);
}
