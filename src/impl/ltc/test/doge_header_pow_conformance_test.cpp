// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// DOGE header-chain conformance to Dogecoin Core 1.14.9 validation
// (CheckAuxPowProofOfWork, CAuxPow::check), through the real P2P paths
// (rides share_test):
//   - a compact block on an AuxPoW chain is fetched whole, not reconstructed,
//     so its header reaches the chain only through the checked block parser:
//     a flagged header with no verified proof never enters via cmpctblock;
//   - the same through getblocktxn/blocktxn;
//   - control: the checked headers/block parser refuses such a header;
//   - real mainnet AuxPoW headers pass the check, mutations of them fail;
//   - Core's late-legacy rule: a legacy header after the activation height is
//     refused;
//   - the peer-reported height never lowers what is verified.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include <impl/ltc/coin/node_interface.hpp>
#include <impl/ltc/coin/p2p_node.hpp>
#include <impl/ltc/config_coin.hpp>
#include <impl/ltc/coin/compact_blocks.hpp>
#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/test/ltc_mined_headers.hpp>

#include <impl/doge/coin/auxpow_check.hpp>
#include <impl/doge/coin/auxpow_header.hpp>
#include <impl/doge/coin/chain_params.hpp>
#include <impl/doge/coin/header_chain.hpp>
#include <impl/doge/coin/utxo_lane.hpp>

#include "doge_headers_witness_fixtures.hpp"

namespace {

using ltc::coin::BlockHeaderType;
using ltc::coin::BlockType;
using ltc::coin::MutableTransaction;

constexpr uint32_t kEasy = 0x207fffff;
// The DOGE chains under test: DigiShield's retarget multiplies the target by
// up to 90 before dividing (calculate_doge_next_work); at 0x207fffff that
// overflows uint256, so the DOGE chains use a limit with headroom (~128
// scrypt tries per header).
constexpr uint32_t kDoge = 0x2001ffff;

uint256 easy_limit()
{
    uint256 l;
    l.SetCompact(kEasy);
    return l;
}

uint256 sha256d(const BlockHeaderType& h) { return Hash(pack(h).get_span()); }

std::vector<uint8_t> hex_bytes(const std::string& h)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
    };
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<uint8_t>((nib(h[i]) << 4) | nib(h[i + 1])));
    return out;
}

MutableTransaction a_coinbase(uint8_t tag)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    ltc::coin::TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.scriptSig.m_data = {0x03, tag, 0x01, 0x02};
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    ltc::coin::TxOut out;
    out.value = 1000000000000LL;
    out.scriptPubKey.m_data = {0x76, 0xa9, 0x14};
    out.scriptPubKey.m_data.insert(out.scriptPubKey.m_data.end(), 20, tag);
    out.scriptPubKey.m_data.push_back(0x88);
    out.scriptPubKey.m_data.push_back(0xac);
    tx.vout.push_back(out);
    return tx;
}

MutableTransaction a_spend(uint8_t tag)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    ltc::coin::TxIn in;
    in.prevout.hash.SetHex(std::to_string(77000 + tag));
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    ltc::coin::TxOut out;
    out.value = 5000;
    out.scriptPubKey.m_data = {0x51};
    tx.vout.push_back(out);
    return tx;
}

// ─── DOGE: an embedded node as main_ltc.cpp wires it ────────────────────────

class TestConfig {
public:
    struct CoinPart {
        ltc::config::P2PData m_p2p;
        ltc::config::RPCData m_rpc;
    };
    CoinPart* coin() { return &m_coin; }
    const CoinPart* coin() const { return &m_coin; }

private:
    CoinPart m_coin;
};

struct TempDb {
    std::filesystem::path dir;
    std::unique_ptr<core::coin::UTXOViewDB> db;
    std::unique_ptr<core::coin::UTXOViewCache> cache;
    TempDb()
    {
        std::mt19937_64 rng(std::random_device{}());
        dir = std::filesystem::temp_directory_path() / ("hdrpow_adv_" + std::to_string(rng()));
        std::filesystem::create_directories(dir);
        db = std::make_unique<core::coin::UTXOViewDB>(dir.string());
        EXPECT_TRUE(db->open());
        cache = std::make_unique<core::coin::UTXOViewCache>(db.get());
    }
    ~TempDb()
    {
        cache.reset();
        db.reset();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

/// A DOGE chain (testnet4alpha rules, easiest PoW limit, AuxPoW from height
/// 1, strict chain id) with `n` mined unflagged headers above genesis
/// (n >= 250: past the chain's difficulty-skip window, DigiShield active).
struct DogeChainUnderTest {
    doge::coin::DOGEChainParams params = doge::coin::DOGEChainParams::testnet4alpha();
    BlockHeaderType genesis;
    std::unique_ptr<doge::coin::HeaderChain> chain;
    uint256 tip;
    uint32_t height = 0;
    BlockHeaderType last;  // the header at `height`

    explicit DogeChainUnderTest(uint32_t n)
    {
        params.pow_limit.SetCompact(kDoge);
        params.auxpow_height = 1;
        params.strict_chain_id = true;
        genesis.m_version = 1;
        genesis.m_previous_block.SetNull();
        genesis.m_merkle_root.SetHex("5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69");
        genesis.m_timestamp = 1391503289;
        genesis.m_bits = kDoge;
        genesis.m_nonce = 0;
        params.genesis_hash = sha256d(genesis);
        chain = std::make_unique<doge::coin::HeaderChain>(params);
        EXPECT_TRUE(chain->init());
        EXPECT_TRUE(chain->add_header(genesis));
        tip = sha256d(genesis);
        for (uint32_t h = 1; h <= n; ++h) {
            BlockHeaderType x = child(tip, h, 0x00620004);
            mine(x);
            EXPECT_TRUE(chain->add_header(x)) << "mined unflagged header h=" << h;
            tip = sha256d(x);
            height = h;
            last = x;
        }
    }
    BlockHeaderType child(const uint256& prev, uint32_t h, int32_t version) const
    {
        BlockHeaderType x;
        x.m_version = version;
        x.m_previous_block = prev;
        x.m_merkle_root.SetHex(std::to_string(7000 + h));
        x.m_timestamp = genesis.m_timestamp + 600 * h;
        x.m_bits = kDoge;
        x.m_nonce = h << 8;
        return x;
    }
    void mine(BlockHeaderType& h) const
    {
        while (!doge::coin::check_pow(doge::coin::scrypt_hash(h), h.m_bits, params.pow_limit))
            ++h.m_nonce;
    }
    void unmine(BlockHeaderType& h) const
    {
        while (doge::coin::check_pow(doge::coin::scrypt_hash(h), h.m_bits, params.pow_limit))
            ++h.m_nonce;
    }
    /// A forged next header: the AuxPoW flag, NO proof anywhere, its own
    /// scrypt failing its bits, committing to `txs`.
    BlockHeaderType forged_next(const std::vector<MutableTransaction>& txs) const
    {
        BlockHeaderType f = child(tip, height + 1, 0x00620104);
        f.m_merkle_root = ltc::coin::ComputeTxMerkleRoot(txs);
        unmine(f);
        return f;
    }
};

/// NodeP2P labelled DOGE with the CHECKED parsers (as main_ltc.cpp:7585),
/// its full_block handled as main_ltc.cpp:8431 does for the accrual lane
/// (height from the parent; UtxoLane::on_block; the lane's add_header is
/// main_ltc.cpp:7940's lambda), its new_headers fed to add_headers.
struct DogeNode {
    DogeChainUnderTest& dc;
    boost::asio::io_context ioc;
    TestConfig config;
    ltc::interfaces::Node coin;
    ltc::coin::p2p::NodeP2P<TestConfig> node{&ioc, &coin, &config, "DOGE"};
    doge::coin::AuxPowRules rules;
    TempDb tdb;
    std::unique_ptr<doge::coin::UtxoLane> lane;
    int full_blocks = 0;
    int header_batches = 0;

    explicit DogeNode(DogeChainUnderTest& c) : dc(c)
    {
        rules.pow_limit = dc.params.pow_limit;
        rules.strict_chain_id = true;
        auto r = rules;
        node.set_raw_headers_parser([r](const uint8_t* d, size_t n) {
            return doge::coin::parse_doge_headers_message(d, n, &r);
        });
        node.set_raw_block_parser([r](const uint8_t* d, size_t n) {
            return doge::coin::parse_doge_block(d, n, &r);
        });
        auto* chain = dc.chain.get();
        doge::coin::UtxoLaneHost host;
        host.stopping = []() { return false; };
        host.chain_height = [chain]() { return chain->height(); };
        host.chain_hash_at = [chain](uint32_t h) {
            auto e = chain->get_header_by_height(h);
            return e ? e->block_hash : uint256();
        };
        host.prev_of = [chain](const uint256& hh) -> std::optional<uint256> {
            auto e = chain->get_header(hh);
            if (!e)
                return std::nullopt;
            return e->prev_hash;
        };
        host.clean_before_header = [](const BlockType&, uint32_t) {};
        // main_ltc.cpp:7940-7947, verbatim apart from the capture.
        host.add_header = [chain](const BlockType& b) {
            const auto& hdr = static_cast<const BlockHeaderType&>(b);
            if (!chain->has_header(b.m_previous_block))
                return false;
            if (chain->has_header(Hash(pack(hdr).get_span())))
                return false;
            return chain->add_header(hdr);
        };
        host.headers_needed = []() {};
        host.request = [](uint32_t, doge::coin::UtxoAsk) {};
        host.connected = [](const BlockType&, const uint256&, uint32_t, bool) {};
        host.wiped = []() {};
        host.completed = []() {};
        host.fill_started = [](doge::coin::UtxoLaneHost::Fill&) {};
        host.fill_stopped = [](doge::coin::UtxoLaneHost::Fill&) {};
        host.download_peers = []() { return std::vector<std::string>{}; };
        host.request_from = [](const std::string&, uint32_t) { return false; };
        host.now = []() { return std::chrono::steady_clock::now(); };
        host.bodies_wait = []() { return false; };
        host.chase_tip = []() { return false; };
        host.chain_synced = []() { return true; };
        host.tip_age_s = []() -> int64_t { return 0; };
        host.body_size = [](const BlockType&) -> size_t { return 0; };
        lane = std::make_unique<doge::coin::UtxoLane>(*tdb.cache, *tdb.db, std::move(host));

        coin.full_block.subscribe([this, chain](const BlockType& block) {
            ++full_blocks;
            const uint256 block_hash = Hash(pack(static_cast<const BlockHeaderType&>(block)).get_span());
            uint32_t height = 0;
            auto entry = chain->get_header(block_hash);
            if (entry)
                height = entry->height;
            else if (auto prev = chain->get_header(block.m_previous_block))
                height = prev->height + 1;
            lane->on_block(block, block_hash, height);
        });
        coin.new_headers.subscribe([this, chain](const std::vector<BlockHeaderType>& v) {
            ++header_batches;
            chain->add_headers(v);
        });
        // A connection without a socket: writes are dropped, the reply
        // matchers are unarmed (Connection::get_block is a no-op).
        node.connected(nullptr);
    }
    void deliver(std::unique_ptr<RawMessage> m) { node.handle(std::move(m), NetService()); }
};

// Dogecoin mainnet block #371337 (the first AuxPoW block) as a 'headers'
// entry, from test/test_doge_chain.cpp (provenance there).
const char* const DOGE_371337_EXTHEADER =
    "020162000d6f03470d329026cd1fc720c0609cd378ca8691a117bd1aa46f01fb"
    "09b1a8468a15bf6f0b0e83f2e5036684169eafb9406468d4f075c999fb5b2a78"
    "fbb827ee41fb11548441361b0000000001000000010000000000000000000000"
    "000000000000000000000000000000000000000000ffffffff380345bf09fabe"
    "6d6d980ba42120410de0554d42a5b5ee58167bcd86bf7591f429005f24da45fb"
    "51cf0800000000000000cdb1f1ff0e000000ffffffff01800c0c2a0100000019"
    "76a914aa3750aa18b8a0f3f0590731e1fab934856680cf88ac00000000a90e29"
    "0fd02fe65a6cea22aad85439ef021c2a20d18bd0032a5bba0ae441df4503a979"
    "a636db2450363972d211aee67b71387a3daaa3051be0fd260c5acd4739cd52a4"
    "18d29d8a0e56c8714c95a0dc24e1c9624480ec497fe2441941f3fee8f9481a33"
    "70c334178415c83d1d0c2deeec727c2330617a47691fc5e79203669312d10000"
    "0000036fa40307b3a439538195245b0de56a2c1db6ba3a64f8bdd2071d00bc48"
    "c841b5e77b98e5c7d6f06f92dec5cf6d61277ecb9a0342406f49f34c51ee8ce4"
    "abd678038129485de14238bd1ca12cd2de12ff0e383aee542d90437cd664ce13"
    "9446a00000000002000000d2ec7dfeb7e8f43fe77aba3368df95ac2088034420"
    "402730ee0492a2084217083411b3fc91033bfdeea339bc11b9efc986e161c703"
    "e07a9045338c165673f09940fb11548b54021b58cc9ae500";

struct Fixture {
    const char* name;
    const unsigned char* data;
    size_t len;
};

std::vector<Fixture> mainnet_fixtures()
{
    return {
        {"h5641397..9", doge::test::DOGE_HEADERS_WIT_5641398, sizeof(doge::test::DOGE_HEADERS_WIT_5641398)},
        {"h5080795..7", doge::test::DOGE_HEADERS_WIT_5080796, sizeof(doge::test::DOGE_HEADERS_WIT_5080796)},
        {"h4715978..80", doge::test::DOGE_HEADERS_WIT_4715979, sizeof(doge::test::DOGE_HEADERS_WIT_4715979)},
        {"h6101856..8", doge::test::DOGE_HEADERS_WIT_6101857, sizeof(doge::test::DOGE_HEADERS_WIT_6101857)},
    };
}

/// Every entry of a 'headers' payload with its AuxPoW proof.
std::vector<std::pair<BlockHeaderType, doge::coin::CAuxPow<>>> entries_of(const uint8_t* d, size_t n)
{
    std::vector<std::pair<BlockHeaderType, doge::coin::CAuxPow<>>> out;
    PackStream ps(std::span<const std::byte>(reinterpret_cast<const std::byte*>(d), n));
    const uint64_t count = ReadCompactSize(ps);
    for (uint64_t i = 0; i < count; ++i) {
        doge::coin::CAuxPow<> aux;
        bool has = false;
        BlockHeaderType h = doge::coin::parse_aux_header(ps, aux, has);
        if (ps.cursor_size() > 0)
            (void)ReadCompactSize(ps);
        EXPECT_TRUE(has);
        out.emplace_back(h, aux);
    }
    return out;
}

} // namespace

// ═══ M1: DOGE compact block → full_block → UTXO lane → header chain ════════

TEST(DogeHeaderPowConformance, DogeCmpctBlockHeaderNeverReachesTheChainUnchecked)
{
    DogeChainUnderTest dc(260);
    ASSERT_EQ(dc.chain->height(), 260u);
    DogeNode n(dc);

    const MutableTransaction cb_tx = a_coinbase(0x41);
    const BlockHeaderType forged = dc.forged_next({cb_tx});
    const uint256 forged_hash = sha256d(forged);
    // The base header's own PoW fails its bits, and it carries no AuxPoW proof.
    ASSERT_FALSE(doge::coin::check_pow(doge::coin::scrypt_hash(forged), forged.m_bits, dc.params.pow_limit));

    ltc::coin::CompactBlock cb;
    cb.header = forged;
    cb.nonce = 0x1122334455667788ULL;
    ltc::coin::PrefilledTransaction pt;
    pt.index = 0;
    pt.tx = cb_tx;
    cb.prefilled_txns.push_back(pt);
    n.deliver(ltc::coin::p2p::message_cmpctblock::make_raw(cb));

    std::cout << "[hdrpow-adv] cmpctblock: full_block events=" << n.full_blocks
              << " chain height=" << dc.chain->height()
              << " forged accepted=" << dc.chain->has_header(forged_hash) << std::endl;
    EXPECT_FALSE(dc.chain->has_header(forged_hash))
        << "an AuxPoW-flagged header with no proof and failing PoW entered the DOGE header chain via cmpctblock";
    EXPECT_EQ(dc.chain->height(), 260u) << "the DOGE tip moved onto a forged header";

    // Escalation, when the first one got in: forged headers whose timestamps
    // do not advance raise DigiShield's difficulty ~4/3 per block (the chain
    // checks no timestamp rule); their claimed work soon exceeds what an
    // honest chain can add, and nothing has to be mined.
    if (dc.chain->has_header(forged_hash)) {
        const uint256 honest_tip = dc.tip;
        const BlockHeaderType honest_last = dc.last;
        BlockHeaderType gp = dc.last, prev = forged;
        uint256 prev_hash = forged_hash;
        uint32_t h = dc.height + 1;
        int taken = 0;
        for (int i = 0; i < 60; ++i) {
            ++h;
            const MutableTransaction cbi = a_coinbase(static_cast<uint8_t>(i));
            BlockHeaderType f;
            f.m_version = 0x00620104;
            f.m_previous_block = prev_hash;
            f.m_timestamp = prev.m_timestamp;
            f.m_bits = doge::coin::calculate_doge_next_work(prev.m_bits, prev.m_timestamp, gp.m_timestamp, h, dc.params);
            f.m_merkle_root = ltc::coin::ComputeTxMerkleRoot({cbi});
            f.m_nonce = 0;
            ltc::coin::CompactBlock ci;
            ci.header = f;
            ci.nonce = 1000 + i;
            ltc::coin::PrefilledTransaction pi;
            pi.index = 0;
            pi.tx = cbi;
            ci.prefilled_txns.push_back(pi);
            n.deliver(ltc::coin::p2p::message_cmpctblock::make_raw(ci));
            if (!dc.chain->has_header(sha256d(f)))
                break;
            ++taken;
            gp = prev;
            prev = f;
            prev_hash = sha256d(f);
        }
        const uint256 forged_work = dc.chain->cumulative_work();
        // An honest, mined branch of 150 headers on the honest tip.
        DogeChainUnderTest& d = dc;
        uint256 t = honest_tip;
        BlockHeaderType hl = honest_last;
        int honest_added = 0;
        for (uint32_t k = 1; k <= 150; ++k) {
            BlockHeaderType x = d.child(t, 260 + k, 0x00620004);
            x.m_merkle_root.SetHex(std::to_string(990000 + k));
            d.mine(x);
            if (d.chain->add_header(x))
                ++honest_added;
            t = sha256d(x);
            hl = x;
        }
        const bool honest_tip_now = d.chain->tip()->block_hash == t;
        std::cout << "[hdrpow-adv] escalation: " << taken << " more forged cmpct headers taken, tip bits 0x" << std::hex
                  << prev.m_bits << std::dec << ", chain work " << forged_work.GetHex().substr(40)
                  << "; honest mined branch +" << honest_added << " headers retakes the tip: " << honest_tip_now
                  << std::endl;
        EXPECT_TRUE(honest_tip_now) << "the forged branch outweighs an honest mined branch";
    }
}

TEST(DogeHeaderPowConformance, DogeBlocktxnHeaderNeverReachesTheChainUnchecked)
{
    DogeChainUnderTest dc(260);
    DogeNode n(dc);

    const MutableTransaction cb_tx = a_coinbase(0x51);
    const MutableTransaction tx1 = a_spend(0x52);
    const BlockHeaderType forged = dc.forged_next({cb_tx, tx1});
    const uint256 forged_hash = sha256d(forged);

    ltc::coin::CompactBlock cb;
    cb.header = forged;
    cb.nonce = 99;
    ltc::coin::PrefilledTransaction pt;
    pt.index = 0;
    pt.tx = cb_tx;
    cb.prefilled_txns.push_back(pt);
    cb.short_ids.push_back(ltc::coin::ShortTxID(0x0000a1b2c3d4ULL));  // unknown: getblocktxn
    n.deliver(ltc::coin::p2p::message_cmpctblock::make_raw(cb));
    EXPECT_EQ(n.full_blocks, 0);

    ltc::coin::BlockTransactionsResponse resp;
    resp.blockhash = forged_hash;
    resp.txs.push_back(tx1);
    n.deliver(ltc::coin::p2p::message_blocktxn::make_raw(resp));

    std::cout << "[hdrpow-adv] blocktxn: full_block events=" << n.full_blocks
              << " chain height=" << dc.chain->height()
              << " forged accepted=" << dc.chain->has_header(forged_hash) << std::endl;
    EXPECT_FALSE(dc.chain->has_header(forged_hash))
        << "an AuxPoW-flagged header with no proof entered the DOGE header chain via blocktxn";
}

// Control: the checked parsers refuse the same header ('headers', 'block').
TEST(DogeHeaderPowConformance, DogeHeadersParserRefusesTheSameHeader)
{
    DogeChainUnderTest dc(260);
    DogeNode n(dc);
    const MutableTransaction cb_tx = a_coinbase(0x61);
    const BlockHeaderType forged = dc.forged_next({cb_tx});

    // 'headers': the flag announces a proof that is not there.
    std::vector<BlockType> hb(1);
    static_cast<BlockHeaderType&>(hb[0]) = forged;
    n.deliver(ltc::coin::p2p::message_headers::make_raw(hb, {}));
    EXPECT_FALSE(dc.chain->has_header(sha256d(forged)));

    // 'headers' with a junk proof (a valid-looking AuxPoW whose parent is unmined).
    {
        doge::coin::CAuxPow<> aux;
        aux.m_merkle_tx.m_tx = cb_tx;
        aux.m_parent_block_header.m_version = 0x20000000;
        aux.m_parent_block_header.m_bits = 0x1a01d2c3;
        PackStream ps;
        WriteCompactSize(ps, 1);
        ps << forged << aux;
        WriteCompactSize(ps, 0);
        auto sp = ps.get_span();
        auto r = doge::coin::parse_doge_headers(reinterpret_cast<const uint8_t*>(sp.data()), sp.size(), &n.rules);
        EXPECT_TRUE(r.headers.empty()) << "a junk proof passed the parser";
        std::cout << "[hdrpow-adv] parser refuses junk proof: " << r.error << std::endl;
    }

    // 'block': same.
    BlockType b;
    static_cast<BlockHeaderType&>(b) = forged;
    b.m_txs.push_back(cb_tx);
    n.deliver(ltc::coin::p2p::message_block::make_raw(b, {}));
    EXPECT_EQ(n.full_blocks, 0);
    EXPECT_FALSE(dc.chain->has_header(sha256d(forged)));
}

// ═══ No false rejects: real mainnet AuxPoW headers ══════════════════════════

TEST(DogeHeaderPowConformance, DogeMainnetAuxPowHeadersPassTheCheck)
{
    const auto rules = doge::coin::auxpow_rules(doge::coin::DOGEChainParams::mainnet());
    size_t total = 0;
    for (const auto& f : mainnet_fixtures()) {
        const auto r = doge::coin::parse_doge_headers(f.data, f.len, &rules);
        EXPECT_EQ(r.headers.size(), 3u) << f.name << ": " << r.error;
        EXPECT_FALSE(r.truncated_at.has_value()) << f.name << ": " << r.error;
        for (const auto& [h, aux] : entries_of(f.data, f.len)) {
            EXPECT_EQ(doge::coin::check_auxpow_header(h, &aux, rules), std::nullopt) << f.name;
            ++total;
        }
    }
    // The activation block itself.
    const auto blob = hex_bytes(DOGE_371337_EXTHEADER);
    {
        PackStream ps(std::span<const std::byte>(reinterpret_cast<const std::byte*>(blob.data()), blob.size()));
        doge::coin::CAuxPow<> aux;
        bool has = false;
        BlockHeaderType h = doge::coin::parse_aux_header(ps, aux, has);
        ASSERT_TRUE(has);
        EXPECT_EQ(sha256d(h).GetHex(), "60323982f9c5ff1b5a954eac9dc1269352835f47c2c5222691d80f0d50dcf053");
        EXPECT_EQ(doge::coin::check_auxpow_header(h, &aux, rules), std::nullopt) << "block 371337";
        ++total;

        // Mutations: each must be refused.
        auto h2 = h;
        h2.m_version = 0x00630102;  // another chain id
        EXPECT_NE(doge::coin::check_auxpow_header(h2, &aux, rules), std::nullopt);
        auto a2 = aux;
        a2.m_parent_block_header.m_nonce ^= 1;  // the parent's PoW
        EXPECT_NE(doge::coin::check_auxpow_header(h, &a2, rules), std::nullopt);
        auto h3 = h;
        h3.m_timestamp += 1;  // the commitment (the child hash changes)
        EXPECT_NE(doge::coin::check_auxpow_header(h3, &aux, rules), std::nullopt);
        auto h4 = h;
        h4.m_bits = 0x1b000001;  // harder bits than the parent met
        EXPECT_NE(doge::coin::check_auxpow_header(h4, &aux, rules), std::nullopt);
        auto a3 = aux;
        a3.m_merkle_tx.m_merkle_link.m_index = 1;  // not a generate
        EXPECT_NE(doge::coin::check_auxpow_header(h, &a3, rules), std::nullopt);
        auto a4 = aux;
        a4.m_parent_block_header.m_version = 0x00620002;  // parent with our chain id
        EXPECT_NE(doge::coin::check_auxpow_header(h, &a4, rules), std::nullopt);
    }
    std::cout << "[hdrpow-adv] mainnet AuxPoW headers checked: " << total << std::endl;

    // Cost per real header through the checked parser vs the unchecked one.
    constexpr int ROUNDS = 200;
    size_t parsed = 0;
    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < ROUNDS; ++i)
        for (const auto& f : mainnet_fixtures())
            parsed += doge::coin::parse_doge_headers(f.data, f.len, &rules).headers.size();
    const double checked_us = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - t0).count() / parsed;
    size_t parsed2 = 0;
    t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < ROUNDS; ++i)
        for (const auto& f : mainnet_fixtures())
            parsed2 += doge::coin::parse_doge_headers(f.data, f.len, nullptr).headers.size();
    const double plain_us = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - t0).count() / parsed2;
    std::cout << "[hdrpow-adv] DOGE 'headers' parse per real header: checked " << checked_us << " us, unchecked "
              << plain_us << " us; a 2,000-header message " << checked_us * 2000 / 1e3
              << " ms on the parsing (io) thread; 5.79 M AuxPoW headers below the 6.16 M checkpoint "
              << checked_us * 5.79e6 / 1e6 << " s" << std::endl;
}

// ═══ Parity: Dogecoin Core ContextualCheckBlockHeader 'late-legacy-block' ═══

TEST(DogeHeaderPowConformance, DogeLegacyAfterActivationIsRefusedLikeCore)
{
    DogeChainUnderTest dc(260);
    BlockHeaderType legacy = dc.child(dc.tip, dc.height + 1, 2);  // version 2, chain id 0: IsLegacy()
    dc.mine(legacy);
    const bool accepted = dc.chain->add_header(legacy);
    std::cout << "[hdrpow-adv] legacy (v2) header after AuxPoW start accepted=" << accepted << std::endl;
    EXPECT_FALSE(accepted) << "Core: legacy block after auxpow start (late-legacy-block)";
}

// ═══ LTC: bits are not checked in the first retarget window after the root ═══



// The gate at a fresh start: the root has no timestamp, the bound is open.
TEST(DogeHeaderPowConformance, LtcPeerHeightGateAtFreshStart)
{
    auto p = ltc::coin::make_ltc_chain_params_mainnet();
    p.pow_limit.SetCompact(kEasy);
    ltc::coin::HeaderChain chain(p);
    ASSERT_TRUE(chain.init());
    uint256 root;
    root.SetHex("00000000000000000000000000000000000000000000000000000000000beef2");
    chain.set_dynamic_checkpoint(3088000, root);
    for (int i = 0; i < 5; ++i)
        chain.set_peer_tip_height(4'000'000'000u);
    for (int i = 0; i < 3; ++i)
        chain.set_peer_tip_height(3'200'000u);
    const uint32_t seen = chain.peer_tip_height();
    std::cout << "[hdrpow-adv] fresh start: 5 of 8 peers claim 4e9, bounded peer height = " << seen
              << " (tip 3088000)" << std::endl;
    // Whatever it says, a header that fails its PoW is refused.
    BlockHeaderType x;
    x.m_version = 0x20000000;
    x.m_previous_block = root;
    x.m_merkle_root.SetHex("abcd");
    x.m_timestamp = 1700000000;
    x.m_bits = kEasy;
    x.m_nonce = 0;
    ltc_test::unmine(x, p);
    EXPECT_FALSE(chain.add_header(x));
    EXPECT_EQ(chain.height(), 3088000u);
}

// ═══ Real-store replays (copies only) ═══════════════════════════════════════




