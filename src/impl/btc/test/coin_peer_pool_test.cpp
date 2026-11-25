// The standalone coin peer pool (impl/btc/coin/coin_peer_pool.hpp): slot
// target and refill, headers and announcements from any pooled peer, the
// header-source tick over the pool, once-only body / transaction fetches, the
// won-block fan-out and the dashboard rows. Driven with fake connections.
#include <gtest/gtest.h>

#include <impl/btc/coin/coin_peer_pool.hpp>

#include <chrono>
#include <limits>
#include <map>
#include <memory>
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

struct FakePeer;

struct Harness {
    Clock::time_point t = Clock::time_point{} + std::chrono::hours(1000);
    std::map<std::string, FakePeer*> peers;   // current connections by key
    std::vector<std::pair<std::string, uint16_t>> candidates;
    std::set<std::string> reported_connected, reported_disconnected, reported_failed;
    std::set<uint256> chain;
    uint32_t height = 100;
    bool caught_up = false;
    int empty_hints = 0;
    uint256 root;
    std::vector<std::vector<BlockHeaderType>> forwarded;
    std::vector<uint256> forwarded_blocks;
    int forwarded_txs = 0;
    std::unique_ptr<CoinPeerPool> pool;

    explicit Harness(size_t n_candidates = 20, size_t target = kCoinPoolTargetPeers);

    std::vector<uint256> locator() const { return {root}; }

    void advance(int64_t sec) { t += std::chrono::seconds(sec); }

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

    /// A headers message, as NodeP2P reports one.
    void send_headers(const std::vector<BlockHeaderType>& hdrs)
    {
        hooks.headers_message(hdrs.size());
        if (!hdrs.empty())
            hooks.headers(hdrs);
    }
};

Harness::Harness(size_t n_candidates, size_t target)
{
    root = some_hash(0);
    chain.insert(root);
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
    h.connected = [this](const std::string& k) { reported_connected.insert(k); };
    h.disconnected = [this](const std::string& k) { reported_disconnected.insert(k); };
    h.dial_failed = [this](const std::string& k) { reported_failed.insert(k); };
    h.has_header = [this](const uint256& x) { return chain.count(x) != 0; };
    h.locator = [this]() { return locator(); };
    h.height = [this]() { return height; };
    h.caught_up = [this]() { return caught_up; };
    h.on_empty_headers = [this]() { ++empty_hints; };
    h.on_headers = [this](const std::vector<BlockHeaderType>& hdrs) {
        forwarded.push_back(hdrs);
        for (const auto& x : hdrs)
            if (chain.insert(pool_header_hash(x)).second)
                ++height;
    };
    h.on_tx = [this](const Transaction&) { ++forwarded_txs; };
    h.on_full_block = [this](const BlockType& b) { forwarded_blocks.push_back(pool_header_hash(b)); };
    h.now = [this]() { return t; };
    pool = std::make_unique<CoinPeerPool>(std::move(h), target);
}

/// Dial a full pool and complete `n` handshakes (observed by a tick).
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
    EXPECT_EQ(hx.reported_connected.size(), 6u);
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

    // A handshaked peer whose link goes down keeps its slot for the grace
    // window (the driver redials it), then is dropped as a disconnect.
    FakePeer* lost = handshaked_peers(hx).front();
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
    clear_asks(hx);

    // Catching up, a tick without progress: one peer is asked.
    hx.advance(12);
    hx.pool->tick();
    size_t asked = 0;
    for (auto* p : live)
        asked += p->getheaders.size();
    EXPECT_EQ(asked, 1u);

    // A tick with progress (headers arrived): nobody.
    clear_asks(hx);
    live[0]->send_headers(make_chain(hx.root, 5, 21));
    hx.advance(12);
    hx.pool->tick();
    asked = 0;
    for (auto* p : live)
        asked += p->getheaders.size();
    EXPECT_EQ(asked, 0u);

    // No progress for kNoProgressFailoverSec: the peer whose last headers
    // message is oldest is dropped (a disconnect) and replaced.
    const std::string answered = live[0]->key;
    hx.advance(kNoProgressFailoverSec);
    hx.pool->tick();
    EXPECT_EQ(hx.reported_disconnected.size(), 1u);
    EXPECT_EQ(hx.reported_disconnected.count(answered), 0u);
    EXPECT_EQ(hx.pool->slot_count(), 8u);
    EXPECT_EQ(hx.pool->live_count(), 2u);

    // Caught up: quiet within the refresh window churns nothing; at the
    // refresh every live peer is asked; at the failover one is replaced.
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
    cu.advance(kCaughtUpFailoverSec - kCaughtUpRefreshSec);
    cu.pool->tick();
    EXPECT_EQ(cu.reported_disconnected.size(), 1u);

    // An empty answer to our locator from a peer at or above our height:
    // header sync is caught up (a batch of 0 < 2000). From a lower peer: not.
    Harness eh;
    eh.pool->tick();
    handshake(eh, 2);
    auto ep = handshaked_peers(eh);
    ep[0]->height = eh.height;
    ep[0]->send_headers({});
    EXPECT_EQ(eh.empty_hints, 1);
    ep[1]->height = eh.height - 1;
    ep[1]->send_headers({});
    EXPECT_EQ(eh.empty_hints, 1);
}

// ── Bodies and transactions: fetched once ──────────────────────────────────
TEST(BtcCoinPeerPool, BodiesAndTransactionsAreFetchedOnce)
{
    Harness hx;
    hx.caught_up = true;   // no header-source failover inside the windows below
    hx.pool->tick();
    handshake(hx, 3);
    auto live = handshaked_peers(hx);
    FakePeer* a = live[0];
    FakePeer* b = live[1];

    // The first announcer of a block body or a transaction fetches it.
    const auto blk = make_header(hx.root, 31);
    const uint256 bh = pool_header_hash(blk);
    EXPECT_TRUE(a->hooks.fetch(bh, true));
    EXPECT_FALSE(b->hooks.fetch(bh, true));
    const uint256 tx = some_hash(32);
    EXPECT_TRUE(b->hooks.fetch(tx, false));
    EXPECT_FALSE(a->hooks.fetch(tx, false));

    // The body reaches the coin node once, whoever sends it.
    BlockType body;
    static_cast<BlockHeaderType&>(body) = blk;
    a->hooks.full_block(body);
    b->hooks.full_block(body);
    ASSERT_EQ(hx.forwarded_blocks.size(), 1u);
    EXPECT_EQ(hx.forwarded_blocks[0], bh);
    EXPECT_FALSE(b->hooks.fetch(bh, true));

    // A body that does not arrive is asked of another peer after
    // kCoinPoolBodyRetrySec, at most kCoinPoolBodyMaxAsks times in all.
    const uint256 missing = pool_header_hash(make_header(hx.root, 33));
    EXPECT_TRUE(a->hooks.fetch(missing, true));
    hx.advance(kCoinPoolBodyRetrySec - 1);
    hx.pool->tick();
    size_t asks = 0;
    for (auto* p : live)
        for (const auto& r : p->requested)
            if (r == missing)
                ++asks;
    EXPECT_EQ(asks, 0u);
    hx.advance(1);
    hx.pool->tick();
    asks = 0;
    for (auto* p : live)
        for (const auto& r : p->requested)
            if (r == missing)
                ++asks;
    EXPECT_EQ(asks, 1u);
    EXPECT_TRUE(a->requested.empty());   // not the peer that did not deliver
    for (int i = 0; i < 4; ++i) {
        hx.advance(kCoinPoolBodyRetrySec);
        hx.pool->tick();
    }
    asks = 0;
    for (auto* p : live)
        for (const auto& r : p->requested)
            if (r == missing)
                ++asks;
    EXPECT_EQ(asks, static_cast<size_t>(kCoinPoolBodyMaxAsks - 1));
    // Given up: a later announcement may fetch it again.
    EXPECT_TRUE(b->hooks.fetch(missing, true));

    // Transactions reach the coin node.
    MutableTransaction mtx;
    Transaction tx_in(mtx);
    a->hooks.tx(tx_in);
    EXPECT_EQ(hx.forwarded_txs, 1);
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
    // One connection failing does not stop the others.
    handshaked_peers(hx).front()->relay_throws = true;
    EXPECT_EQ(hx.pool->broadcast_block(block), 5u);
    size_t twice = 0;
    for (auto& [key, p] : hx.peers)
        if (p->relayed.size() == 2)
            ++twice;
    EXPECT_EQ(twice, 5u);
    // ask_all: getheaders to every connected peer (the tip-reconcile poll).
    clear_asks(hx);
    EXPECT_EQ(hx.pool->ask_all(hx.locator()), 6u);

    Harness empty;
    EXPECT_EQ(empty.pool->broadcast_block(block), 0u);
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
    BlockType body;
    static_cast<BlockHeaderType&>(body) = make_header(hx.root, 43);
    saved.full_block(body);
    EXPECT_TRUE(hx.forwarded_blocks.empty());
}
