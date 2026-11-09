// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// Merged mining with several aux chains under one Litecoin parent: what a
// chain's daemon does must not stop the others (rides share_test).
//
//  - payout address: each chain's createauxblock gets an address of ITS
//    chain and network (the daemons refuse any other: -8 / -5 "Invalid
//    coinbase payout address"); the built-in PEP address failed base58check
//    and the other chains were given the LTC address, so they never got work.
//  - poll: the chains are fetched in parallel without the manager lock; a
//    chain that hangs, fails or is slow drops out of that round's commitment
//    and the others keep committing; the commitment is the smallest tree over
//    the chains in it (what a V36 peer checks against the share's
//    merged_coinbase_info).
//  - AuxChainRPC: every call has a deadline; a connection the daemon closed
//    (restart, idle timeout) is replaced, after failures with a backoff.
//  - submit: the daemon's submitblock answer is kept (inconclusive is not a
//    win); a non-DOGE found block is judged by its daemon's best chain, not by
//    the daemon answering; each chain's own block size limit; one slow or
//    throwing backend neither delays nor aborts the others' submits.
//  - the chain merkle tree is capped (a colliding chain id is refused).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <fstream>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <nlohmann/json.hpp>

#include <btclibs/base58.h>
#include <btclibs/bech32.h>
#include <btclibs/util/strencodings.h>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <c2pool/merged/aux_chain_params.hpp>
#include <c2pool/merged/aux_commitment_rule.hpp>
#include <core/merged_chain_addr.hpp>
#include <c2pool/merged/aux_found_verdict.hpp>
#include <c2pool/merged/merged_mining.hpp>
#include <impl/doge/coin/auxpow.hpp>
#include <impl/doge/coin/auxpow_check.hpp>

namespace {

using namespace std::chrono_literals;
using c2pool::merged::AuxChainConfig;
using c2pool::merged::AuxNetwork;
using c2pool::merged::AuxPowTree;
using c2pool::merged::MergedMiningManager;
using c2pool::merged::SubmitVerdict;
using Clock = std::chrono::steady_clock;

constexpr const char* EASY_TARGET =
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

long ms_since(Clock::time_point t0)
{
    return static_cast<long>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count());
}

/// A daemon-shaped backend (multiaddress: the block is built from its
/// template) whose answers the test controls: down (throws), hung (blocks
/// until released), slow or throwing submit, a submit verdict, a best chain.
struct Backend : c2pool::merged::IAuxChainBackend {
    AuxChainConfig cfg;
    std::string tip;
    int height;
    uint32_t base_version;
    std::vector<std::string> tx_data;   // template transactions (raw hex)

    std::mutex mu;
    std::vector<std::string> blocks;
    std::vector<Clock::time_point> submit_times;
    std::atomic<bool> down{false};
    std::atomic<bool> submit_throws{false};
    std::atomic<int> submit_sleep_ms{0};
    std::optional<SubmitVerdict> verdict;

    // hang: get_best_block_hash blocks while `hung` (released by release()).
    std::mutex gate_mu;
    std::condition_variable gate_cv;
    bool hung{false};
    std::atomic<int> waiting{0};

    // best chain (for found-block verdicts)
    std::optional<uint32_t> count;
    std::map<uint32_t, uint256> chain_at;

    Backend(std::string symbol, uint32_t chain_id, int start_height)
        : tip(std::string(60, '0') + "a" + std::to_string(1000 + chain_id % 1000).substr(1)),
          height(start_height), base_version((chain_id << 16) | 4u)
    {
        cfg.symbol = std::move(symbol);
        cfg.chain_id = chain_id;
        cfg.multiaddress = true;
    }
    void hang() { std::lock_guard<std::mutex> l(gate_mu); hung = true; }
    void release()
    {
        { std::lock_guard<std::mutex> l(gate_mu); hung = false; }
        gate_cv.notify_all();
    }
    void advance(const std::string& t) { tip = std::string(64 - t.size(), '0') + t; ++height; }

    c2pool::merged::AuxWork get_work_template() override
    {
        if (down) throw std::runtime_error("connect 127.0.0.1: Connection refused");
        c2pool::merged::AuxWork w;
        w.chain_id = cfg.chain_id;
        w.height = height;
        w.coinbase_value = 1'000'000'000'000ULL + static_cast<uint64_t>(height);
        w.block_hash.SetHex(tip);
        w.target.SetHex(EASY_TARGET);
        w.prev_block_hash = tip;
        nlohmann::json txs = nlohmann::json::array();
        for (const auto& d : tx_data) {
            const auto raw = ParseHex(d);
            txs.push_back({{"data", d}, {"txid", Hash(std::span<const unsigned char>(raw.data(), raw.size())).GetHex()}});
        }
        w.block_template = {
            {"previousblockhash", tip}, {"height", height}, {"bits", "207fffff"},
            {"curtime", 1793210000 + height}, {"version", base_version},
            {"coinbasevalue", 1'000'000'000'000LL + height}, {"transactions", txs},
        };
        return w;
    }
    c2pool::merged::AuxWork create_aux_block(const std::string&) override { return get_work_template(); }
    bool connect() override { return true; }
    bool submit_block(const std::string& hex) override
    {
        {
            std::lock_guard<std::mutex> l(mu);
            submit_times.push_back(Clock::now());
        }
        if (submit_sleep_ms) std::this_thread::sleep_for(std::chrono::milliseconds(submit_sleep_ms.load()));
        if (submit_throws) throw std::runtime_error("backend threw in submit_block");
        std::lock_guard<std::mutex> l(mu);
        blocks.push_back(hex);
        return true;
    }
    SubmitVerdict submit_block_verdict(const std::string& hex) override
    {
        const bool ok = submit_block(hex);
        if (verdict) return *verdict;
        return ok ? SubmitVerdict::of(SubmitVerdict::Kind::accepted)
                  : SubmitVerdict::of(SubmitVerdict::Kind::rejected, "rejected");
    }
    bool submit_aux_block(const uint256&, const std::string&) override { return true; }
    std::string get_block_hex(const std::string&) override { return {}; }
    std::string get_best_block_hash() override
    {
        std::unique_lock<std::mutex> l(gate_mu);
        if (hung) {
            ++waiting;
            gate_cv.wait(l, [this] { return !hung; });
            --waiting;
        }
        if (down) throw std::runtime_error("connect 127.0.0.1: Connection refused");
        return tip;
    }
    std::vector<NetService> getpeerinfo() override { return {}; }
    const AuxChainConfig& config() const override { return cfg; }
    std::optional<uint32_t> get_block_count() override { return count; }
    std::optional<uint256> get_block_hash_at(uint32_t h) override
    {
        auto it = chain_at.find(h);
        if (it == chain_at.end()) return std::nullopt;
        return it->second;
    }
    std::optional<uint32_t> get_block_height(const uint256& hash) override
    {
        for (const auto& [h, x] : chain_at)
            if (x == hash) return h;
        return std::nullopt;
    }
    size_t submitted()
    {
        std::lock_guard<std::mutex> l(mu);
        return blocks.size();
    }
};

MergedMiningManager::PayoutProvider payout_provider()
{
    return [](uint32_t chain_id, uint64_t value) {
        std::vector<unsigned char> script{0x76, 0xa9, 0x14};
        script.insert(script.end(), 20, static_cast<unsigned char>(chain_id & 0xff));
        script.push_back(0x88);
        script.push_back(0xac);
        return std::vector<std::pair<std::vector<unsigned char>, uint64_t>>{{script, value}};
    };
}

std::string hex_of(const std::vector<uint8_t>& b)
{
    return HexStr(std::span<const unsigned char>(b.data(), b.size()));
}

std::string parent_coinbase_hex(const std::vector<uint8_t>& commitment, uint8_t salt = 0x11)
{
    std::vector<uint8_t> script{0x03, 0x01, 0x02, 0x03, salt};
    script.insert(script.end(), commitment.begin(), commitment.end());
    script.insert(script.end(), 8, salt);
    std::vector<uint8_t> tx{0x01, 0x00, 0x00, 0x00, 0x01};
    tx.insert(tx.end(), 32, 0x00);
    tx.insert(tx.end(), 4, 0xff);
    tx.push_back(static_cast<uint8_t>(script.size()));
    tx.insert(tx.end(), script.begin(), script.end());
    tx.insert(tx.end(), 4, 0xff);
    tx.push_back(0x01);
    for (int i = 0; i < 8; ++i) tx.push_back(0x01);
    tx.push_back(0x00);
    tx.insert(tx.end(), 4, 0x00);
    return hex_of(tx);
}

std::string parent_header_hex(const std::string& coinbase_hex)
{
    const auto cb = ParseHex(coinbase_hex);
    const uint256 cbid = Hash(std::span<const unsigned char>(cb.data(), cb.size()));
    std::vector<uint8_t> hdr;
    for (int i = 0; i < 4; ++i) hdr.push_back(static_cast<uint8_t>(0x20000000u >> (8 * i)));
    hdr.insert(hdr.end(), 32, 0x22);
    hdr.insert(hdr.end(), cbid.data(), cbid.data() + 32);
    for (int i = 0; i < 4; ++i) hdr.push_back(static_cast<uint8_t>(1793210000u >> (8 * i)));
    for (int i = 0; i < 4; ++i) hdr.push_back(static_cast<uint8_t>(0x1e0fffffu >> (8 * i)));
    for (int i = 0; i < 4; ++i) hdr.push_back(static_cast<uint8_t>(7u >> (8 * i)));
    return hex_of(hdr);
}

void submit_share(MergedMiningManager& mm, const std::vector<uint8_t>& commitment, uint8_t salt = 0x11)
{
    const auto cb = parent_coinbase_hex(commitment, salt);
    uint256 parent_hash;
    parent_hash.SetHex("01");
    mm.try_submit_merged_blocks(parent_header_hex(cb), cb, {}, 0, parent_hash);
}

struct Parsed {
    uint256 hash;
    doge::coin::CAuxPow<> aux;
};

Parsed parse_block(const std::string& block_hex)
{
    const auto bytes = ParseHex(block_hex);
    PackStream ps(std::span<const std::byte>(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()));
    Parsed p;
    bool has_aux = false;
    doge::coin::parse_aux_header(ps, p.aux, has_aux);
    EXPECT_TRUE(has_aux);
    p.hash = Hash(std::span<const unsigned char>(bytes.data(), 80));
    return p;
}

std::optional<std::string> core_check(const Parsed& p, uint32_t chain_id)
{
    return doge::coin::check_auxpow(p.aux, p.hash, static_cast<int32_t>(chain_id), true);
}

struct Rig {
    boost::asio::io_context ioc;
    MergedMiningManager mm{ioc};
    std::vector<Backend*> chains;
    int64_t clock{1000};
    explicit Rig(std::vector<std::pair<std::string, uint32_t>> ids, int start_height = 5'000'001)
    {
        mm.set_clock_for_test([this] { return clock; });
        mm.set_payout_provider(payout_provider());
        for (const auto& [sym, cid] : ids) {
            auto b = std::make_unique<Backend>(sym, cid, start_height);
            Backend* raw = b.get();
            auto cfg = b->cfg;
            const size_t before = mm.chain_count();
            mm.add_chain(cfg, std::move(b));
            if (mm.chain_count() > before)   // a refused chain's backend is gone
                chains.push_back(raw);
        }
    }
    ~Rig()
    {
        for (auto* b : chains) b->release();
        mm.stop();
    }
    Backend& chain(size_t i) { return *chains.at(i); }
    uint32_t tree_size()
    {
        const auto c = mm.get_auxpow_commitment();
        return c.size() == 44 ? c[36] | (c[37] << 8) : 0;
    }
    uint256 root()
    {
        const auto c = mm.get_auxpow_commitment();
        uint256 r;
        for (int i = 0; i < 32 && c.size() == 44; ++i)
            r.data()[i] = c[4 + 31 - i];
        return r;
    }
    std::set<uint32_t> carried()
    {
        std::set<uint32_t> out;
        for (const auto& hi : mm.get_cached_header_infos_and_commitment().first)
            out.insert(hi.chain_id);
        return out;
    }
    bool responsive(const std::string& sym)
    {
        for (const auto& ci : mm.get_chain_infos())
            if (ci.symbol == sym) return ci.responsive;
        return false;
    }
};

// p2pool make_auxpow_tree (bitcoin/data.py): the smallest power of two at
// which the chain ids have distinct (1103515245 * id + 1103515245 * 12345 +
// 12345) % size slots — what a V36 peer expects the share's tree size to be.
uint32_t p2pool_tree_size(const std::set<uint32_t>& ids)
{
    for (uint64_t size = 1; size <= (1ull << 30); size <<= 1) {
        if (size < ids.size()) continue;
        std::set<uint64_t> used;
        bool ok = true;
        for (uint32_t id : ids)
            ok = ok && used.insert((1103515245ull * id + 1103515245ull * 12345 + 12345) % size).second;
        if (ok) return static_cast<uint32_t>(size);
    }
    return 0;
}

std::string b58(uint8_t version, uint8_t fill)
{
    std::vector<unsigned char> v{version};
    v.insert(v.end(), 20, fill);
    return EncodeBase58Check(v);
}

} // namespace

// ---- B: createauxblock payout address ---------------------------------------

// The address c2pool shipped for PEP is not base58check (pepecoind -8). Every
// chain's address must be of its own chain and network.
TEST(MergedAuxAddress, ShippedPepAddressIsNotAnAddress)
{
    const auto r = c2pool::merged::resolve_aux_payout_address("PEP", AuxNetwork::mainnet,
                                                              "PSimbaxxxxxxxxxxxxxxxxxxxxUMbTDw");
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("not a valid address"), std::string::npos) << r.error;
    EXPECT_NE(r.error.find("--merged-payout-address PEP:"), std::string::npos) << r.error;
}

TEST(MergedAuxAddress, EveryChainButDogeNeedsAConfiguredOne)
{
    for (const char* sym : {"PEP", "BELLS", "LKY", "JKC", "SHIC", "DINGO", "NMC"})
        for (auto net : {AuxNetwork::mainnet, AuxNetwork::testnet}) {
            const auto r = c2pool::merged::resolve_aux_payout_address(sym, net, "");
            EXPECT_FALSE(r.ok) << sym;
            EXPECT_NE(r.error.find(std::string("--merged-payout-address ") + sym), std::string::npos) << r.error;
        }
    const auto main = c2pool::merged::resolve_aux_payout_address("DOGE", AuxNetwork::mainnet, "");
    ASSERT_TRUE(main.ok) << main.error;
    EXPECT_EQ(main.address, "DDogepartyxxxxxxxxxxxxxxxxxxw1dfzr");
    EXPECT_EQ(main.source, "built-in");
    const auto test = c2pool::merged::resolve_aux_payout_address("doge", AuxNetwork::testnet, "");
    ASSERT_TRUE(test.ok) << test.error;
    EXPECT_EQ(test.address, "nUCAGGgZEPN1QyknmQe1oAku817bQAFKFt");
}

// An address of the chain and network is taken; one of another coin (the LTC
// payout address the other chains were given), of another network, or with a
// bad checksum is refused with the option to set.
TEST(MergedAuxAddress, OwnChainAndNetworkOnly)
{
    using c2pool::merged::resolve_aux_payout_address;
    // PEP: main 56, testnet 113, regtest 111 (pepecoin chainparams.cpp).
    EXPECT_TRUE(resolve_aux_payout_address("PEP", AuxNetwork::mainnet, b58(56, 0x11)).ok);
    EXPECT_FALSE(resolve_aux_payout_address("PEP", AuxNetwork::testnet, b58(56, 0x11)).ok);
    EXPECT_TRUE(resolve_aux_payout_address("PEP", AuxNetwork::testnet, b58(113, 0x11)).ok);
    EXPECT_TRUE(resolve_aux_payout_address("PEP", AuxNetwork::testnet, b58(111, 0x11)).ok) << "regtest";
    EXPECT_TRUE(resolve_aux_payout_address("PEP", AuxNetwork::mainnet, b58(22, 0x11)).ok) << "P2SH";
    const auto ltc = resolve_aux_payout_address("PEP", AuxNetwork::mainnet, b58(48, 0x11));   // L...
    EXPECT_FALSE(ltc.ok);
    EXPECT_NE(ltc.error.find("not a PEP address"), std::string::npos) << ltc.error;
    auto broken = b58(56, 0x11);
    broken[10] = broken[10] == 'a' ? 'b' : 'a';
    EXPECT_FALSE(resolve_aux_payout_address("PEP", AuxNetwork::mainnet, broken).ok);
    // The configured one wins over the built-in one.
    const auto doge = resolve_aux_payout_address("DOGE", AuxNetwork::mainnet, b58(30, 0x22));
    ASSERT_TRUE(doge.ok);
    EXPECT_EQ(doge.address, b58(30, 0x22));
    EXPECT_EQ(doge.source, "configured");
    EXPECT_FALSE(resolve_aux_payout_address("DOGE", AuxNetwork::mainnet, "PSimbaxxxxxxxxxxxxxxxxxxxxUMbTDw").ok);
    // BELLS (segwit): bech32 "bel"; LKY 47; SHIC 63; JKC 16; DINGO 30.
    std::vector<uint8_t> prog(20, 0x33);
    EXPECT_TRUE(resolve_aux_payout_address("BELLS", AuxNetwork::mainnet, bech32::encode_segwit("bel", 0, prog)).ok);
    EXPECT_FALSE(resolve_aux_payout_address("BELLS", AuxNetwork::mainnet, bech32::encode_segwit("ltc", 0, prog)).ok);
    EXPECT_TRUE(resolve_aux_payout_address("BELLS", AuxNetwork::mainnet, b58(25, 0x11)).ok);
    EXPECT_TRUE(resolve_aux_payout_address("LKY", AuxNetwork::mainnet, b58(47, 0x11)).ok);
    EXPECT_TRUE(resolve_aux_payout_address("SHIC", AuxNetwork::mainnet, b58(63, 0x11)).ok);
    EXPECT_TRUE(resolve_aux_payout_address("JKC", AuxNetwork::mainnet, b58(16, 0x11)).ok);
    EXPECT_TRUE(resolve_aux_payout_address("DINGO", AuxNetwork::mainnet, b58(30, 0x11)).ok);
    // A chain c2pool has no parameters for: the daemon judges.
    EXPECT_TRUE(resolve_aux_payout_address("XYZ", AuxNetwork::mainnet, "anything").ok);
    EXPECT_FALSE(resolve_aux_payout_address("XYZ", AuxNetwork::mainnet, "").ok);
}

// The versions are the coins' chainparams base58Prefixes (main / testnet /
// regtest P2PKH, P2SH).
TEST(MergedAuxAddress, VersionTableIsTheCoinsChainparams)
{
    struct Row { const char* sym; uint32_t id; uint8_t m1, m2, t1, t2, r1, r2; };
    const Row rows[] = {
        {"DOGE", 98, 30, 22, 113, 196, 111, 196},  {"PEP", 63, 56, 22, 113, 196, 111, 196},
        {"BELLS", 16, 25, 30, 33, 22, 111, 196},   {"LKY", 8211, 47, 5, 113, 196, 113, 196},
        {"JKC", 8224, 16, 5, 111, 5, 47, 5},       {"SHIC", 74, 63, 22, 113, 196, 111, 196},
        {"DINGO", 50, 30, 22, 113, 196, 111, 196}, {"NMC", 1, 52, 13, 111, 196, 111, 196},
    };
    for (const auto& r : rows) {
        const auto* p = c2pool::merged::find_aux_chain_params(r.sym);
        ASSERT_NE(p, nullptr) << r.sym;
        EXPECT_EQ(p->chain_id, r.id) << r.sym;
        EXPECT_EQ(p->main.p2pkh, std::vector<uint8_t>{r.m1}) << r.sym;
        EXPECT_EQ(p->main.p2sh, std::vector<uint8_t>{r.m2}) << r.sym;
        EXPECT_EQ(p->test.p2pkh, std::vector<uint8_t>{r.t1}) << r.sym;
        EXPECT_EQ(p->test.p2sh, std::vector<uint8_t>{r.t2}) << r.sym;
        EXPECT_EQ(p->regtest.p2pkh, std::vector<uint8_t>{r.r1}) << r.sym;
        EXPECT_EQ(p->regtest.p2sh, std::vector<uint8_t>{r.r2}) << r.sym;
    }
}

// ---- M1: a hung, failing or slow chain does not stop the others -------------

// PEP's daemon accepts and never answers: the poll returns within its
// deadline with DOGE's new work committed alone (the smallest tree, size 1),
// the manager is not locked while PEP hangs, later polls do not wait for it,
// a share on that work submits a DOGE block Core accepts, and PEP comes back
// when it answers.
TEST(MergedAuxPoll, HungChainDropsOutTheOthersKeepCommitting)
{
    Rig r({{"DOGE", 98}, {"PEP", 63}});
    r.mm.set_refresh_round_deadline(300ms);
    r.mm.set_unresponsive_after(200ms);
    r.mm.refresh_aux_work();
    ASSERT_EQ(r.tree_size(), 2u);
    EXPECT_EQ(r.carried(), (std::set<uint32_t>{98, 63}));

    r.chain(1).hang();
    r.chain(1).advance("bb");
    r.chain(0).advance("d1");
    auto t0 = Clock::now();
    std::thread poll([&] { r.mm.refresh_aux_work(); });
    // While PEP's fetch hangs the manager answers (no lock held over I/O).
    while (r.chain(1).waiting.load() == 0 && ms_since(t0) < 5000)
        std::this_thread::sleep_for(1ms);
    const bool hung_seen = r.chain(1).waiting.load() == 1;
    const auto t1 = Clock::now();
    (void)r.mm.get_auxpow_commitment();
    (void)r.mm.get_chain_infos();
    (void)r.mm.get_cached_header_infos_and_commitment();
    EXPECT_LT(ms_since(t1), 100) << "a reader waited for the hung fetch";
    poll.join();
    ASSERT_TRUE(hung_seen);
    EXPECT_LT(ms_since(t0), 2000) << "the poll waited past its deadline";

    EXPECT_FALSE(r.responsive("PEP"));
    EXPECT_TRUE(r.responsive("DOGE"));
    ASSERT_EQ(r.tree_size(), 1u) << "PEP out: the tree of DOGE alone";
    EXPECT_EQ(r.root(), r.mm.get_current_work().at(98).block_hash);
    EXPECT_EQ(r.carried(), std::set<uint32_t>{98});

    // The next poll does not wait for PEP (still hanging).
    r.chain(0).advance("d2");
    t0 = Clock::now();
    r.mm.refresh_aux_work();
    EXPECT_LT(ms_since(t0), 250) << "a poll waited again for the hung chain";
    EXPECT_EQ(r.root(), r.mm.get_current_work().at(98).block_hash);

    // A share on this work: DOGE's block, a proof Core accepts; PEP not in it.
    submit_share(r.mm, r.mm.get_auxpow_commitment());
    ASSERT_EQ(r.chain(0).submitted(), 1u);
    EXPECT_FALSE(core_check(parse_block(r.chain(0).blocks[0]), 98).has_value());
    EXPECT_EQ(r.chain(1).submitted(), 0u);
    EXPECT_EQ(r.mm.get_block_refusals_json().value("PEP:not_committed", 0), 1);

    // PEP answers: applied when it comes, back in at the next poll.
    r.chain(1).release();
    t0 = Clock::now();
    while (!r.responsive("PEP") && ms_since(t0) < 5000)
        std::this_thread::sleep_for(5ms);
    ASSERT_TRUE(r.responsive("PEP"));
    r.mm.refresh_aux_work();
    EXPECT_EQ(r.tree_size(), 2u);
    EXPECT_EQ(r.carried(), (std::set<uint32_t>{98, 63}));
}

// A daemon that refuses connections (down, restarting): out of the
// commitment while down, back when it answers. The tree is always the
// smallest over the chains the shares carry (a V36 peer's rule).
TEST(MergedAuxPoll, FailingChainDropsOutAndComesBack)
{
    Rig r({{"DOGE", 98}, {"PEP", 63}, {"NMC", 1}});
    r.mm.refresh_aux_work();
    ASSERT_EQ(r.carried(), (std::set<uint32_t>{98, 63, 1}));
    EXPECT_EQ(r.tree_size(), p2pool_tree_size({98, 63, 1}));

    r.chain(1).down = true;
    r.chain(1).advance("c3");
    r.mm.refresh_aux_work();
    EXPECT_FALSE(r.responsive("PEP"));
    EXPECT_EQ(r.carried(), (std::set<uint32_t>{98, 1}));
    EXPECT_EQ(r.tree_size(), p2pool_tree_size({98, 1}));
    EXPECT_EQ(r.tree_size(), AuxPowTree::build({98, 1}).size);

    // A share on it: DOGE and NMC both get a block Core accepts.
    submit_share(r.mm, r.mm.get_auxpow_commitment());
    ASSERT_EQ(r.chain(0).submitted(), 1u);
    ASSERT_EQ(r.chain(2).submitted(), 1u);
    EXPECT_FALSE(core_check(parse_block(r.chain(0).blocks[0]), 98).has_value());
    EXPECT_FALSE(core_check(parse_block(r.chain(2).blocks[0]), 1).has_value());
    EXPECT_EQ(r.chain(1).submitted(), 0u);

    r.chain(1).down = false;
    r.mm.refresh_aux_work();
    EXPECT_TRUE(r.responsive("PEP"));
    EXPECT_EQ(r.carried(), (std::set<uint32_t>{98, 63, 1}));
    EXPECT_EQ(r.tree_size(), p2pool_tree_size({98, 63, 1}));
}

// A chain slower than the round deadline but answering (a daemon whose calls
// take seconds) is not waited for and stays committed with its last work;
// its answer is applied when it comes. One still hanging past the hang
// threshold drops out.
TEST(MergedAuxPoll, SlowChainStaysCommittedHungChainDropsOut)
{
    Rig r({{"DOGE", 98}, {"PEP", 63}});
    r.mm.set_refresh_round_deadline(150ms);
    r.mm.set_unresponsive_after(2'000ms);
    r.mm.refresh_aux_work();
    ASSERT_EQ(r.tree_size(), 2u);

    // slow: PEP's fetch takes ~600 ms
    r.chain(1).hang();
    r.chain(1).advance("ee");
    auto t0 = Clock::now();
    r.mm.refresh_aux_work();
    EXPECT_LT(ms_since(t0), 500) << "the round waited for the slow chain";
    EXPECT_TRUE(r.responsive("PEP"));
    EXPECT_EQ(r.tree_size(), 2u) << "PEP stays committed with its last work";
    std::this_thread::sleep_for(450ms);
    r.chain(1).release();
    t0 = Clock::now();
    while (r.mm.get_current_work().at(63).height != r.chain(1).height && ms_since(t0) < 5000)
        std::this_thread::sleep_for(5ms);
    r.mm.refresh_aux_work();
    EXPECT_EQ(r.mm.get_current_work().at(63).height, r.chain(1).height) << "its answer applied";
    EXPECT_EQ(r.tree_size(), 2u);

    // hung past the threshold: out until it answers
    r.mm.set_unresponsive_after(300ms);
    r.chain(1).hang();
    r.chain(1).advance("ef");
    r.mm.refresh_aux_work();
    std::this_thread::sleep_for(350ms);
    r.mm.refresh_aux_work();
    EXPECT_FALSE(r.responsive("PEP"));
    EXPECT_EQ(r.tree_size(), 1u);
    r.chain(1).release();
    t0 = Clock::now();
    while (!r.responsive("PEP") && ms_since(t0) < 5000)
        std::this_thread::sleep_for(5ms);
    r.mm.refresh_aux_work();
    EXPECT_TRUE(r.responsive("PEP"));
    EXPECT_EQ(r.tree_size(), 2u);
}

// One chain: nothing to protect, its last work stays committed while its
// daemon fails (as before).
TEST(MergedAuxPoll, SingleChainKeepsItsLastWorkWhenItFails)
{
    Rig r({{"DOGE", 98}});
    r.mm.refresh_aux_work();
    const auto before = r.mm.get_auxpow_commitment();
    ASSERT_EQ(before.size(), 44u);
    r.chain(0).down = true;
    r.chain(0).advance("f4");
    r.mm.refresh_aux_work();
    EXPECT_EQ(r.mm.get_auxpow_commitment(), before);
    EXPECT_EQ(r.carried(), std::set<uint32_t>{98});
}

// ---- AuxChainRPC against a socket -------------------------------------------

namespace {

namespace net = boost::asio;
namespace http = boost::beast::http;
using tcp = net::ip::tcp;

/// A JSON-RPC-over-HTTP/1.1 daemon on 127.0.0.1: keep-alive, answers from
/// `handler` (method, params) -> result; a thrown RpcError is an "error"
/// object (HTTP 500, as bitcoind). close_after_response: the connection is
/// closed after each answer (a daemon's idle timeout). silent: accepts and
/// never answers. Four threads, like bitcoind's -rpcthreads: a slow call on
/// one connection does not hold the others.
struct FakeDaemon {
    struct RpcError { int code; std::string message; };
    net::io_context io;
    tcp::acceptor acc{net::make_strand(io)};   // each socket on its own strand too
    std::vector<std::thread> th;
    std::mutex socks_mu;
    std::vector<std::shared_ptr<tcp::socket>> socks;
    std::atomic<int> requests{0};
    std::atomic<int> accepts{0};
    bool close_after_response{false};
    bool silent{false};
    std::function<nlohmann::json(const std::string&, const nlohmann::json&)> handler;
    uint16_t port{0};
    net::executor_work_guard<net::io_context::executor_type> guard{io.get_executor()};

    explicit FakeDaemon(uint16_t p = 0)
    {
        acc.open(tcp::v4());
        acc.set_option(tcp::acceptor::reuse_address(true));
        acc.bind({net::ip::make_address("127.0.0.1"), p});
        acc.listen();
        port = acc.local_endpoint().port();
        accept();
        for (int i = 0; i < 4; ++i)
            th.emplace_back([this] { io.run(); });
    }
    ~FakeDaemon()
    {
        stop();
        guard.reset();
        io.stop();
        for (auto& t : th)
            t.join();
    }
    void accept()
    {
        auto s = std::make_shared<tcp::socket>(net::make_strand(io));
        acc.async_accept(*s, [this, s](boost::system::error_code ec) {
            if (ec) return;
            ++accepts;
            {
                std::lock_guard<std::mutex> l(socks_mu);
                socks.push_back(s);
            }
            serve(s);
            accept();
        });
    }
    void serve(std::shared_ptr<tcp::socket> s)
    {
        auto buf = std::make_shared<boost::beast::flat_buffer>();
        auto req = std::make_shared<http::request<http::string_body>>();
        http::async_read(*s, *buf, *req, [this, s, buf, req](boost::system::error_code ec, size_t) {
            if (ec) return;
            ++requests;
            if (silent) { serve(s); return; }
            nlohmann::json in = nlohmann::json::parse(req->body(), nullptr, false);
            nlohmann::json out = {{"id", in.value("id", nlohmann::json(nullptr))}};
            auto status = http::status::ok;
            try {
                out["result"] = handler(in.value("method", ""), in.value("params", nlohmann::json::array()));
                out["error"] = nullptr;
            } catch (const RpcError& e) {
                out["result"] = nullptr;
                out["error"] = {{"code", e.code}, {"message", e.message}};
                status = http::status::internal_server_error;
            }
            auto res = std::make_shared<http::response<http::string_body>>(status, 11);
            res->set(http::field::content_type, "application/json");
            res->keep_alive(true);
            res->body() = out.dump();
            res->prepare_payload();
            http::async_write(*s, *res, [this, s, res](boost::system::error_code ec2, size_t) {
                if (ec2) return;
                if (close_after_response) {
                    boost::system::error_code ig;
                    s->shutdown(tcp::socket::shutdown_both, ig);
                    s->close(ig);
                    return;
                }
                serve(s);
            });
        });
    }
    void stop()
    {
        std::promise<void> done;
        net::post(acc.get_executor(), [this, &done] {
            boost::system::error_code ig;
            acc.close(ig);
            std::lock_guard<std::mutex> l(socks_mu);
            for (auto& s : socks)
                net::post(s->get_executor(), [s] {
                    boost::system::error_code e;
                    s->shutdown(tcp::socket::shutdown_both, e);
                    s->close(e);
                });
            socks.clear();
            done.set_value();
        });
        done.get_future().wait();
    }
};

AuxChainConfig rpc_cfg(uint16_t port, uint32_t timeout_ms = 1'000)
{
    AuxChainConfig c;
    c.symbol = "PEP";
    c.chain_id = 63;
    c.rpc_host = "127.0.0.1";
    c.rpc_port = port;
    c.rpc_userpass = "u:p";
    c.rpc_connect_timeout_ms = timeout_ms;
    c.rpc_timeout_ms = timeout_ms;
    c.rpc_reconnect_max_ms = 4'000;
    return c;
}

} // namespace

// A daemon that accepts and never answers: the call ends at its deadline, the
// connection is dropped, and the next call within the backoff fails at once.
TEST(MergedAuxRpc, NoAnswerEndsAtTheDeadline)
{
    FakeDaemon d;
    d.silent = true;
    net::io_context unused;
    c2pool::merged::AuxChainRPC rpc(unused, rpc_cfg(d.port, 300));
    auto t0 = Clock::now();
    EXPECT_EQ(rpc.get_best_block_hash(), "");
    EXPECT_GE(ms_since(t0), 250);
    EXPECT_LT(ms_since(t0), 2'000);
    EXPECT_FALSE(rpc.connected());
    t0 = Clock::now();
    EXPECT_THROW(rpc.create_aux_block("x"), std::exception);
    EXPECT_LT(ms_since(t0), 100) << "within the backoff: no new connection";
    EXPECT_EQ(d.requests.load(), 1);
    // cancel_io: a call blocked on the daemon returns now.
    std::this_thread::sleep_for(1'100ms);
    c2pool::merged::AuxChainRPC rpc2(unused, rpc_cfg(d.port, 5'000));
    std::thread canceller([&] { std::this_thread::sleep_for(200ms); rpc2.cancel_io(); });
    t0 = Clock::now();
    EXPECT_EQ(rpc2.get_best_block_hash(), "");
    EXPECT_LT(ms_since(t0), 2'000);
    canceller.join();
}

// A keep-alive connection the daemon closes (its idle timeout) is replaced on
// the next call, transparently.
TEST(MergedAuxRpc, ReconnectsWhenTheDaemonClosesTheConnection)
{
    FakeDaemon d;
    d.close_after_response = true;
    d.handler = [](const std::string& m, const nlohmann::json&) -> nlohmann::json {
        if (m == "getbestblockhash") return std::string(64, 'a');
        return nullptr;
    };
    net::io_context unused;
    c2pool::merged::AuxChainRPC rpc(unused, rpc_cfg(d.port));
    for (int i = 0; i < 4; ++i) {
        EXPECT_EQ(rpc.get_best_block_hash(), std::string(64, 'a')) << "call " << i;
        std::this_thread::sleep_for(20ms);
    }
    EXPECT_EQ(d.requests.load(), 4);
    EXPECT_GE(rpc.connects(), 4u);
}

// The daemon restarts: calls fail (fast, with a backoff) while it is down and
// succeed again once it listens.
TEST(MergedAuxRpc, ReconnectsAfterTheDaemonRestarts)
{
    auto d = std::make_unique<FakeDaemon>();
    const uint16_t port = d->port;
    auto handler = [](const std::string& m, const nlohmann::json&) -> nlohmann::json {
        if (m == "getblockcount") return 4242;
        return nullptr;
    };
    d->handler = handler;
    net::io_context unused;
    c2pool::merged::AuxChainRPC rpc(unused, rpc_cfg(port));
    EXPECT_EQ(rpc.get_block_count(), std::optional<uint32_t>(4242));
    d.reset();   // daemon stopped
    EXPECT_EQ(rpc.get_block_count(), std::nullopt);
    const auto t0 = Clock::now();
    EXPECT_EQ(rpc.get_block_count(), std::nullopt);
    EXPECT_LT(ms_since(t0), 100) << "backoff: not hammering a dead daemon";
    d = std::make_unique<FakeDaemon>(port);
    d->handler = handler;
    std::optional<uint32_t> got;
    const auto t1 = Clock::now();
    while (!got && ms_since(t1) < 8'000) {
        got = rpc.get_block_count();
        if (!got) std::this_thread::sleep_for(50ms);
    }
    EXPECT_EQ(got, std::optional<uint32_t>(4242));
    EXPECT_TRUE(rpc.connected());
}

// ---- L1: the daemon's submitblock answer, and the found-block verdict -------

TEST(MergedAuxVerdict, SubmitblockAnswers)
{
    using K = SubmitVerdict::Kind;
    using c2pool::merged::classify_submitblock_result;
    struct Case { nlohmann::json in; K kind; bool accepted; bool held; };
    const Case cases[] = {
        {nullptr, K::accepted, true, true},
        {"duplicate", K::duplicate, true, true},
        {"inconclusive", K::inconclusive, false, true},
        {"duplicate-inconclusive", K::inconclusive, false, true},
        {"duplicate-invalid", K::rejected, false, false},
        {"high-hash", K::rejected, false, false},
        {"bad-txnmrklroot", K::rejected, false, false},
        {"", K::rejected, false, false},
        {true, K::rejected, false, false},
    };
    for (const auto& c : cases) {
        const auto v = classify_submitblock_result(c.in);
        EXPECT_EQ(v.kind, c.kind) << c.in.dump();
        EXPECT_EQ(v.accepted(), c.accepted) << c.in.dump();
        EXPECT_EQ(v.held(), c.held) << c.in.dump();
    }
    EXPECT_EQ(classify_submitblock_result("high-hash").label(), "rejected: high-hash");
    EXPECT_EQ(classify_submitblock_result("inconclusive").label(), "inconclusive");
}

// AuxChainRPC keeps what the daemon said: "inconclusive" is not a win; an
// RPC error (a block that does not decode) is an error; a refused payout
// address names the option to set.
TEST(MergedAuxVerdict, RpcKeepsTheDaemonsAnswer)
{
    FakeDaemon d;
    // 0 inconclusive, 1 duplicate, 2 null, 3 decode error
    std::atomic<int> next{0};
    d.handler = [&next](const std::string& m, const nlohmann::json&) -> nlohmann::json {
        if (m == "submitblock") {
            switch (next.load()) {
            case 0: return "inconclusive";
            case 1: return "duplicate";
            case 2: return nullptr;
            default: throw FakeDaemon::RpcError{-22, "Block decode failed"};
            }
        }
        if (m == "createauxblock") throw FakeDaemon::RpcError{-8, "Invalid coinbase payout address"};
        return nullptr;
    };
    net::io_context unused;
    c2pool::merged::AuxChainRPC rpc(unused, rpc_cfg(d.port));
    auto v = rpc.submit_block_verdict("00");
    EXPECT_EQ(v.kind, SubmitVerdict::Kind::inconclusive);
    EXPECT_FALSE(rpc.submit_block("00")) << "inconclusive is not accepted";
    next = 1;
    EXPECT_TRUE(rpc.submit_block("00"));
    next = 2;
    EXPECT_EQ(rpc.submit_block_verdict("00").kind, SubmitVerdict::Kind::accepted);
    next = 3;
    v = rpc.submit_block_verdict("00");
    EXPECT_EQ(v.kind, SubmitVerdict::Kind::error);
    EXPECT_NE(v.reason.find("Block decode failed"), std::string::npos) << v.reason;
    try {
        rpc.create_aux_block("PSimbaxxxxxxxxxxxxxxxxxxxxUMbTDw");
        ADD_FAILURE() << "createauxblock did not throw";
    } catch (const std::exception& e) {
        EXPECT_NE(std::string(e.what()).find("--merged-payout-address PEP:"), std::string::npos) << e.what();
    }
}

// The manager records the verdict: an inconclusive block is not accepted
// (the found-block check decides it), a rejected one is not held.
TEST(MergedAuxVerdict, FoundRecordFollowsTheVerdict)
{
    Rig r({{"DOGE", 98}, {"PEP", 63}});
    std::vector<std::pair<std::string, bool>> calls;
    r.mm.set_on_merged_block_found([&calls](const std::string& sym, int, const std::string&, bool held, uint64_t) {
        calls.emplace_back(sym, held);
    });
    r.chain(0).verdict = SubmitVerdict::of(SubmitVerdict::Kind::rejected, "bad-cb-amount");
    r.chain(1).verdict = SubmitVerdict::of(SubmitVerdict::Kind::inconclusive, "inconclusive");
    r.mm.refresh_aux_work();
    submit_share(r.mm, r.mm.get_auxpow_commitment());
    const auto rec = r.mm.get_discovered_blocks();
    ASSERT_EQ(rec.size(), 2u);
    for (const auto& b : rec) {
        EXPECT_FALSE(b.accepted) << b.symbol;
        EXPECT_EQ(b.verdict, b.symbol == "PEP" ? "inconclusive" : "rejected: bad-cb-amount");
    }
    ASSERT_EQ(calls.size(), 2u);
    for (const auto& [sym, held] : calls)
        EXPECT_EQ(held, sym == "PEP") << sym;
}

// A non-DOGE found block follows the daemon's best chain: an answering
// daemon is not a confirmation (it was: verdict 1 whenever
// getbestblockhash answered).
TEST(MergedAuxVerdict, NonDogeBlockFollowsTheDaemonsChain)
{
    Backend b("PEP", 63, 1);
    uint256 ours, theirs;
    ours.SetHex("aa");
    theirs.SetHex("bb");
    using c2pool::merged::aux_backend_verdict;
    EXPECT_EQ(aux_backend_verdict(b, ours, 500u), 0) << "a daemon that cannot tell: pending";
    b.count = 499;
    EXPECT_EQ(aux_backend_verdict(b, ours, 500u), 0) << "the chain has not reached it";
    b.count = 502;
    b.chain_at[500] = ours;
    EXPECT_EQ(aux_backend_verdict(b, ours, 500u), 0) << "3 deep: pending";
    b.count = 505;
    EXPECT_EQ(aux_backend_verdict(b, ours, 500u), 6) << "6 deep: confirmed";
    b.chain_at[500] = theirs;
    EXPECT_EQ(aux_backend_verdict(b, ours, 500u), -1) << "another block won 500: orphaned";
    b.count = 502;
    EXPECT_EQ(aux_backend_verdict(b, ours, 500u), 0) << "a race still open: pending";
    b.chain_at[500] = ours;
    b.count = 506;
    EXPECT_EQ(aux_backend_verdict(b, ours, std::nullopt), 7) << "height from the daemon's header";
}

// ---- L2: each chain's own block size limit ---------------------------------

TEST(MergedAuxBlockSize, EachChainItsOwnLimit)
{
    using c2pool::merged::aux_block_limit;
    struct Row { uint32_t id; uint32_t stripped; uint32_t weight; };
    const Row rows[] = {
        {98, 1'000'000, 0}, {63, 1'000'000, 0}, {8211, 1'000'000, 0}, {74, 1'000'000, 0},   // MAX_BLOCK_BASE_SIZE
        {50, 10'000'000, 0},                                                                    // DINGO after v18
        {16, 1'000'000, 4'000'000}, {8224, 1'000'000, 4'000'000}, {8225, 1'000'000, 4'000'000},
        {1, 1'000'000, 4'000'000},                                                              // segwit: weight
    };
    for (const auto& r : rows) {
        const auto l = aux_block_limit(r.id);
        EXPECT_EQ(l.max_stripped, r.stripped) << r.id;
        EXPECT_EQ(l.max_weight, r.weight) << r.id;
    }
    EXPECT_FALSE(aux_block_limit(12345u).known()) << "unknown: no guard";
    AuxChainConfig c;
    c.chain_id = 63;
    c.max_block_bytes = 2'000'000;
    EXPECT_EQ(aux_block_limit(c).max_stripped, 2'000'000u);
    // Namecoin CheckBlock: stripped * 4 <= 4,000,000 and weight <= 4,000,000.
    const auto nmc = aux_block_limit(1u);
    EXPECT_TRUE(nmc.check(1'000'000, 1'000'000).empty());
    EXPECT_FALSE(nmc.check(1'000'001, 1'000'001).empty()) << "stripped over 1,000,000";
    EXPECT_TRUE(nmc.check(900'000, 1'300'000).empty()) << "weight 4,000,000";
    EXPECT_FALSE(nmc.check(900'000, 1'300'001).empty()) << "weight over 4,000,000";
    EXPECT_FALSE(aux_block_limit(98u).check(1'000'001, 1'000'001).empty());
}

// The stripped size of a transaction: BIP144 marker, flag and witness
// stacks removed; a legacy one whole; one that does not parse: nullopt.
TEST(MergedAuxBlockSize, StrippedTransactionSize)
{
    using c2pool::merged::tx_stripped_size;
    // version | vin 1: prevout 36, script 0, sequence | vout 1: value 8, script 1 (OP_TRUE) | locktime
    std::vector<uint8_t> legacy{0x02, 0, 0, 0, 0x01};
    legacy.insert(legacy.end(), 36, 0x11);
    legacy.push_back(0x00);
    legacy.insert(legacy.end(), 4, 0xff);
    legacy.push_back(0x01);
    legacy.insert(legacy.end(), 8, 0x01);
    legacy.push_back(0x01);
    legacy.push_back(0x51);
    legacy.insert(legacy.end(), 4, 0x00);
    EXPECT_EQ(tx_stripped_size(legacy), std::optional<size_t>(legacy.size()));
    // The same with a witness of two items (72 and 33 bytes).
    std::vector<uint8_t> sw(legacy.begin(), legacy.begin() + 4);
    sw.push_back(0x00);
    sw.push_back(0x01);
    sw.insert(sw.end(), legacy.begin() + 4, legacy.end() - 4);
    sw.push_back(0x02);
    sw.push_back(72);
    sw.insert(sw.end(), 72, 0x30);
    sw.push_back(33);
    sw.insert(sw.end(), 33, 0x02);
    sw.insert(sw.end(), 4, 0x00);
    EXPECT_EQ(tx_stripped_size(sw), std::optional<size_t>(legacy.size()));
    std::vector<uint8_t> cut(sw.begin(), sw.end() - 5);
    EXPECT_EQ(tx_stripped_size(cut), std::nullopt);
}

// A segwit chain (NMC): a block whose transactions carry 1.2 MB of witness
// is under its limits (stripped < 1,000,000, weight <= 4,000,000) and goes
// out, though its full size is over 1,000,000; one whose weight is over
// 4,000,000 is refused and neither submitted nor relayed.
TEST(MergedAuxBlockSize, SegwitChainCountsTheStrippedSizeAndTheWeight)
{
    // One input whose witness holds 1,200,000 bytes.
    std::vector<uint8_t> tx{0x02, 0, 0, 0, 0x00, 0x01, 0x01};
    tx.insert(tx.end(), 36, 0x22);
    tx.push_back(0x00);
    tx.insert(tx.end(), 4, 0xff);
    tx.push_back(0x01);
    tx.insert(tx.end(), 8, 0x01);
    tx.push_back(0x01);
    tx.push_back(0x51);
    tx.push_back(0x01);                               // one witness item
    tx.push_back(0xfe);                               // compact size, 4 bytes
    for (uint32_t v = 1'200'000, k = 0; k < 4; ++k, v >>= 8) tx.push_back(static_cast<uint8_t>(v & 0xff));
    tx.insert(tx.end(), 1'200'000, 0x42);
    tx.insert(tx.end(), 4, 0x00);
    ASSERT_TRUE(c2pool::merged::tx_stripped_size(tx).has_value());
    const std::string hex = hex_of(tx);
    {
        Rig r({{"DOGE", 98}, {"NMC", 1}});
        r.chain(1).tx_data = {hex};
        r.mm.refresh_aux_work();
        submit_share(r.mm, r.mm.get_auxpow_commitment());
        EXPECT_EQ(r.chain(1).submitted(), 1u) << "NMC: stripped and weight within limits";
        EXPECT_EQ(r.mm.get_block_refusals_json().value("NMC:oversize", 0), 0);
    }
    {
        // 4,000,001 witness bytes: weight over 4,000,000.
        std::vector<uint8_t> heavy(tx.begin(), tx.begin() + 7 + 36 + 1 + 4 + 1 + 8 + 2 + 1);
        heavy.push_back(0xfe);
        for (uint32_t v = 4'000'001, k = 0; k < 4; ++k, v >>= 8) heavy.push_back(static_cast<uint8_t>(v & 0xff));
        heavy.insert(heavy.end(), 4'000'001, 0x42);
        heavy.insert(heavy.end(), 4, 0x00);
        ASSERT_TRUE(c2pool::merged::tx_stripped_size(heavy).has_value());
        Rig r({{"DOGE", 98}, {"NMC", 1}});
        std::vector<std::string> relayed;
        r.mm.set_block_relay_fn([&relayed](uint32_t cid, const std::string&) { relayed.push_back(std::to_string(cid)); });
        r.chain(1).tx_data = {hex_of(heavy)};
        r.mm.refresh_aux_work();
        submit_share(r.mm, r.mm.get_auxpow_commitment());
        EXPECT_EQ(r.chain(1).submitted(), 0u);
        EXPECT_EQ(r.mm.get_block_refusals_json().value("NMC:oversize", 0), 1);
        EXPECT_EQ(relayed, std::vector<std::string>{"98"}) << "the refused block is not relayed";
    }
}

// PEP's block over 1,000,000 bytes is refused (pepecoind's bad-blk-length):
// counted, not submitted, nothing recorded; DOGE's block is not affected.
TEST(MergedAuxBlockSize, OversizePepBlockIsRefused)
{
    Rig r({{"DOGE", 98}, {"PEP", 63}});
    std::string big = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff";
    // One transaction of ~1,000,100 bytes (its bytes are never parsed here).
    big += std::string(2 * 1'000'100, '7');
    r.chain(1).tx_data = {big};
    r.mm.refresh_aux_work();
    submit_share(r.mm, r.mm.get_auxpow_commitment());
    EXPECT_EQ(r.chain(1).submitted(), 0u);
    EXPECT_EQ(r.mm.get_block_refusals_json().value("PEP:oversize", 0), 1);
    EXPECT_EQ(r.chain(0).submitted(), 1u);
    for (const auto& b : r.mm.get_discovered_blocks())
        EXPECT_EQ(b.symbol, "DOGE");
}

// ---- submit: per-chain isolation ---------------------------------------------

// PEP's backend throws in submitblock: DOGE's block still goes out, nothing
// escapes, PEP's find is recorded with the error.
TEST(MergedAuxSubmit, ThrowingBackendDoesNotStopTheOthers)
{
    Rig r({{"PEP", 63}, {"DOGE", 98}});
    r.chain(0).submit_throws = true;
    r.mm.refresh_aux_work();
    EXPECT_NO_THROW(submit_share(r.mm, r.mm.get_auxpow_commitment()));
    EXPECT_EQ(r.chain(1).submitted(), 1u);
    bool pep_error = false;
    for (const auto& b : r.mm.get_discovered_blocks())
        if (b.symbol == "PEP")
            pep_error = b.verdict.rfind("unknown: the backend threw", 0) == 0 && !b.accepted;
    EXPECT_TRUE(pep_error);
}

// PEP's daemon takes 1.5 s to answer: DOGE's block reaches its daemon at once
// and is recorded first.
TEST(MergedAuxSubmit, SlowBackendDoesNotDelayTheOthers)
{
    Rig r({{"PEP", 63}, {"DOGE", 98}});
    std::vector<std::string> order;
    r.mm.set_on_merged_block_found([&order](const std::string& sym, int, const std::string&, bool, uint64_t) {
        order.push_back(sym);
    });
    r.chain(0).submit_sleep_ms = 1'500;
    r.mm.refresh_aux_work();
    const auto t0 = Clock::now();
    submit_share(r.mm, r.mm.get_auxpow_commitment());
    ASSERT_EQ(r.chain(1).submit_times.size(), 1u);
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(r.chain(1).submit_times[0] - t0).count(), 500)
        << "DOGE waited for PEP";
    EXPECT_EQ(order, (std::vector<std::string>{"DOGE", "PEP"}));
    EXPECT_EQ(r.chain(0).submitted(), 1u);
}

// The /tmp copy of a found block is named by the block's height (the
// snapshot's), not by the current work's.
TEST(MergedAuxSubmit, TmpCopyNamedByTheBlocksHeight)
{
    const std::string at_job = "/tmp/c2pool_aux63_block_7712301.hex";
    const std::string at_now = "/tmp/c2pool_aux63_block_7712302.hex";
    std::remove(at_job.c_str());
    std::remove(at_now.c_str());
    Rig r({{"PEP", 63}}, 7'712'301);
    r.mm.refresh_aux_work();
    const auto job = r.mm.get_auxpow_commitment();
    r.chain(0).advance("77");
    r.mm.refresh_aux_work();
    ASSERT_NE(r.mm.get_auxpow_commitment(), job);
    submit_share(r.mm, job);
    ASSERT_EQ(r.chain(0).submitted(), 1u);
    EXPECT_TRUE(std::ifstream(at_job).good());
    EXPECT_FALSE(std::ifstream(at_now).good());
    std::remove(at_job.c_str());
    std::remove(at_now.c_str());
}

// ---- the chain merkle tree cap ----------------------------------------------

TEST(MergedAuxTree, HeightIsCapped)
{
    EXPECT_EQ(AuxPowTree::kMaxHeight, 12u);
    // Equal mod 2^11: distinct only at height 12 (4096 slots).
    EXPECT_EQ(AuxPowTree::build({5, 5u + (1u << 11)}).size, 4096u);
    // Equal mod 2^12 (or mod 2^30): no tree, instead of 2^13.. 2^30 leaves.
    EXPECT_EQ(AuxPowTree::build({5, 5u + (1u << 12)}).size, 0u);
    EXPECT_EQ(AuxPowTree::build({5, 5u + (1u << 30)}).size, 0u);
    // Every chain set of the merged chain table fits in height 5.
    EXPECT_EQ(AuxPowTree::build({98, 63, 16, 8211, 8224, 74, 1}).size, 32u);

    // The manager refuses the chain that would need a taller tree; the
    // chains registered before keep merged mining.
    Rig r({{"DOGE", 98}, {"BAD", 98u + (1u << 12)}, {"PEP", 63}});
    EXPECT_EQ(r.mm.chain_count(), 2u);
    r.mm.refresh_aux_work();
    EXPECT_EQ(r.tree_size(), 2u);
}

// ---- Finds are never lost to the poll: own submit connection, no backoff,
// ---- no answer = unknown (verified against the chain), relay first ------------

namespace {

using c2pool::merged::AuxChainRPC;
using MHI = MergedMiningManager::MergedHeaderInfo;

uint32_t le32_at(const std::vector<uint8_t>& c, size_t o)
{
    return c[o] | (c[o + 1] << 8) | (c[o + 2] << 16) | (uint32_t(c[o + 3]) << 24);
}

uint32_t get_expected_index(uint32_t nonce, uint32_t chain_id, unsigned h)
{
    uint32_t r = nonce;
    r = r * 1103515245u + 12345u;
    r += chain_id;
    r = r * 1103515245u + 12345u;
    return r % (1u << h);
}

/// The (header infos, commitment) pair stratum puts in one job: the tree size
/// is p2pool's make_auxpow_tree over the carried chain ids and the root is
/// the tree over exactly the carried blocks (what a V36 peer checks). "" when
/// consistent.
std::string pair_problem(const std::vector<MHI>& infos, const std::vector<uint8_t>& c)
{
    if (c.empty())
        return infos.empty() ? "" : "infos without a commitment";
    if (c.size() != 44)
        return "commitment of " + std::to_string(c.size()) + " bytes";
    const uint32_t size = le32_at(c, 36), nonce = le32_at(c, 40);
    if (nonce != 0)
        return "nonce " + std::to_string(nonce);
    std::set<uint32_t> ids;
    for (const auto& i : infos) ids.insert(i.chain_id);
    if (ids.size() != infos.size())
        return "a chain carried twice";
    if (infos.empty())
        return "commitment without infos";
    if (size != p2pool_tree_size(ids))
        return "tree size " + std::to_string(size) + " != p2pool " + std::to_string(p2pool_tree_size(ids));
    unsigned h = 0;
    while ((1u << h) < size) ++h;
    std::vector<uint256> layer(size);
    for (const auto& i : infos) {
        if (i.block_header.size() != 80) return "header not 80 bytes";
        layer[get_expected_index(0, i.chain_id, h)] = Hash(std::span<const unsigned char>(i.block_header.data(), 80));
    }
    while (layer.size() > 1) {
        std::vector<uint256> next(layer.size() / 2);
        for (size_t k = 0; k < next.size(); ++k) next[k] = Hash(layer[2 * k], layer[2 * k + 1]);
        layer = std::move(next);
    }
    uint256 root;
    for (int i = 0; i < 32; ++i) root.data()[i] = c[4 + 31 - i];
    if (root != layer[0])
        return "root is not the tree over the carried blocks";
    // the c2pool share check accepts it too
    std::vector<std::pair<uint32_t, std::vector<unsigned char>>> carried;
    for (const auto& i : infos) carried.emplace_back(i.chain_id, i.block_header);
    return c2pool::merged::check_merged_aux_commitment(carried, root, size);
}

/// A thread-safe daemon-shaped backend for the stress test.
struct StressBackend : c2pool::merged::IAuxChainBackend {
    AuxChainConfig cfg;
    mutable std::mutex mu;
    std::string tip;
    int height;
    bool down{false};
    int hang_ms{0};
    bool throw_int{false};
    std::vector<std::string> blocks;
    StressBackend(std::string sym, uint32_t id, int h) : height(h)
    {
        cfg.symbol = std::move(sym);
        cfg.chain_id = id;
        cfg.multiaddress = true;
        tip = std::string(56, '0') + "0000" + std::to_string(1000 + id % 1000).substr(1) + "0";
    }
    void set(bool d, int hang, bool ti)
    {
        std::lock_guard<std::mutex> l(mu);
        down = d; hang_ms = hang; throw_int = ti;
    }
    void advance()
    {
        std::lock_guard<std::mutex> l(mu);
        ++height;
        char buf[17];
        std::snprintf(buf, sizeof buf, "%016x", static_cast<unsigned>(height * 7919u + cfg.chain_id));
        tip = std::string(48, '0') + buf;
    }
    void maybe_fail()
    {
        int hang;
        bool d, ti;
        { std::lock_guard<std::mutex> l(mu); hang = hang_ms; d = down; ti = throw_int; }
        if (hang) std::this_thread::sleep_for(std::chrono::milliseconds(hang));
        if (ti) throw 42;   // not a std::exception
        if (d) throw std::runtime_error("down");
    }
    c2pool::merged::AuxWork get_work_template() override
    {
        maybe_fail();
        std::lock_guard<std::mutex> l(mu);
        c2pool::merged::AuxWork w;
        w.chain_id = cfg.chain_id;
        w.height = height;
        w.coinbase_value = 1'000'000'000'000ULL + static_cast<uint64_t>(height);
        w.block_hash.SetHex(tip);
        w.target.SetHex(EASY_TARGET);
        w.prev_block_hash = tip;
        w.block_template = {
            {"previousblockhash", tip}, {"height", height}, {"bits", "207fffff"},
            {"curtime", 1793210000 + height}, {"version", (cfg.chain_id << 16) | 4u},
            {"coinbasevalue", 1'000'000'000'000LL + height}, {"transactions", nlohmann::json::array()},
        };
        return w;
    }
    c2pool::merged::AuxWork create_aux_block(const std::string&) override { return get_work_template(); }
    bool connect() override { return true; }
    bool submit_block(const std::string& hex) override
    {
        maybe_fail();
        std::lock_guard<std::mutex> l(mu);
        blocks.push_back(hex);
        return true;
    }
    bool submit_aux_block(const uint256&, const std::string&) override { return true; }
    std::string get_block_hex(const std::string&) override { return {}; }
    std::string get_best_block_hash() override
    {
        maybe_fail();
        std::lock_guard<std::mutex> l(mu);
        return tip;
    }
    std::vector<NetService> getpeerinfo() override { return {}; }
    const AuxChainConfig& config() const override { return cfg; }
    std::vector<std::string> blocks_copy()
    {
        std::lock_guard<std::mutex> l(mu);
        return blocks;
    }
};

/// A pepecoind-shaped JSON-RPC daemon on a socket, with per-call delays.
struct FakeAux {
    std::atomic<int> fetch_delay_ms{0};
    std::atomic<int> submit_delay_ms{0};
    std::atomic<int> submits{0};
    std::atomic<int> height{100};
    std::atomic<int> chainid{63};
    std::mutex mu;
    std::string tip = std::string(63, '0') + "1";
    std::string chain_name = "regtest";
    FakeDaemon d;   // last: its thread runs the handler, which reads the above
    FakeAux()
    {
        d.handler = [this](const std::string& m, const nlohmann::json&) -> nlohmann::json {
            if (m == "submitblock") {
                if (int s = submit_delay_ms.load()) std::this_thread::sleep_for(std::chrono::milliseconds(s));
                ++submits;   // the daemon took the block (as pepecoind: null = accepted)
                return nullptr;
            }
            if (m == "getbestblockhash" || m == "createauxblock" || m == "getblocktemplate")
                if (int s = fetch_delay_ms.load()) std::this_thread::sleep_for(std::chrono::milliseconds(s));
            std::string t, cn;
            { std::lock_guard<std::mutex> l(mu); t = tip; cn = chain_name; }
            const int h = height.load();
            if (m == "getblockchaininfo") return {{"chain", cn}, {"blocks", h}};
            if (m == "getbestblockhash") return t;
            if (m == "createauxblock")
                return {{"hash", t}, {"chainid", chainid.load()}, {"height", h},
                        {"coinbasevalue", 1'000'000'000'000LL}, {"bits", "207fffff"}};
            if (m == "getblocktemplate")
                return {{"previousblockhash", t}, {"height", h}, {"bits", "207fffff"},
                        {"curtime", 1793210000 + h}, {"version", (63 << 16) | 4},
                        {"coinbasevalue", 1'000'000'000'000LL}, {"transactions", nlohmann::json::array()}};
            if (m == "getblockcount") return h;
            return nullptr;
        };
    }
    void new_tip(const std::string& t)
    {
        std::lock_guard<std::mutex> l(mu);
        tip = std::string(64 - t.size(), '0') + t;
        ++height;
    }
};

AuxChainConfig pep_cfg(uint16_t port, uint32_t connect_ms, uint32_t timeout_ms, uint32_t submit_ms = 15'000)
{
    AuxChainConfig c;
    c.symbol = "PEP";
    c.chain_id = 63;
    c.rpc_host = "127.0.0.1";
    c.rpc_port = port;
    c.rpc_userpass = "u:p";
    c.multiaddress = true;
    c.aux_payout_address = "nPEPaddr";
    c.rpc_connect_timeout_ms = connect_ms;
    c.rpc_timeout_ms = timeout_ms;
    c.rpc_submit_timeout_ms = submit_ms;
    c.rpc_reconnect_max_ms = 4'000;
    return c;
}

} // namespace

// A block found right after a poll timed out (the poll connection in its
// reconnect backoff) is sent at once on the submit connection.
TEST(MergedAuxFind, SubmitDuringThePollBackoffIsSent)
{
    FakeAux f;
    net::io_context unused;
    AuxChainRPC rpc(unused, pep_cfg(f.d.port, 500, 500));
    f.fetch_delay_ms = 800;   // one slow answer: the poll call times out
    EXPECT_EQ(rpc.get_best_block_hash(), "");
    f.fetch_delay_ms = 0;
    std::this_thread::sleep_for(350ms);
    const int before = f.submits.load();
    const auto v = rpc.submit_block_verdict("00");
    EXPECT_EQ(v.kind, SubmitVerdict::Kind::accepted) << v.label();
    EXPECT_EQ(f.submits.load(), before + 1) << "the block did not reach the daemon";
    // the poll connection is still in its backoff
    EXPECT_EQ(rpc.get_block_count(), std::nullopt);
}

// A daemon that takes the block but answers after the deadline: unknown,
// held (the found-block check follows the chain), never "not held".
TEST(MergedAuxFind, SubmitAnsweredAfterTheDeadlineIsUnknownAndHeld)
{
    FakeAux f;
    net::io_context unused;
    AuxChainRPC rpc(unused, pep_cfg(f.d.port, 1'000, 1'000, 1'000));
    f.submit_delay_ms = 1'500;
    const auto v = rpc.submit_block_verdict("00");
    std::this_thread::sleep_for(800ms);
    EXPECT_EQ(f.submits.load(), 1) << "the daemon took it";
    EXPECT_EQ(v.kind, SubmitVerdict::Kind::unknown) << v.label();
    EXPECT_TRUE(v.held());
    // and a refused connection: unknown too (the P2P relay sent the block)
    net::io_context unused2;
    AuxChainRPC dead(unused2, pep_cfg(1, 300, 300));
    const auto v2 = dead.submit_block_verdict("00");
    EXPECT_EQ(v2.kind, SubmitVerdict::Kind::unknown) << v2.label();
}

// Through the manager: the record says unknown and the found-block callback
// is told the daemon may hold it (its verification is scheduled).
TEST(MergedAuxFind, SlowAcceptedSubmitIsVerifiedAgainstTheChain)
{
    FakeAux f;
    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    mm.set_payout_provider(payout_provider());
    mm.add_chain(pep_cfg(f.d.port, 1'000, 1'000, 1'000));
    std::vector<bool> held;
    mm.set_on_merged_block_found([&held](const std::string&, int, const std::string&, bool h, uint64_t) {
        held.push_back(h);
    });
    mm.refresh_aux_work();
    ASSERT_EQ(mm.get_auxpow_commitment().size(), 44u);
    f.submit_delay_ms = 1'500;
    submit_share(mm, mm.get_auxpow_commitment());
    std::this_thread::sleep_for(800ms);
    EXPECT_EQ(f.submits.load(), 1);
    const auto d = mm.get_discovered_blocks();
    ASSERT_EQ(d.size(), 1u);
    EXPECT_FALSE(d[0].accepted);
    EXPECT_EQ(d[0].verdict.rfind("unknown: ", 0), 0u) << d[0].verdict;
    ASSERT_EQ(held.size(), 1u);
    EXPECT_TRUE(held[0]) << "an accepted block must be verified against the chain";
    mm.stop();
}

// The daemon answers every poll call in 5 s: a find meanwhile reaches it at
// once (its own connection), not after the poll.
TEST(MergedAuxFind, SubmitDoesNotWaitForASlowPoll)
{
    FakeAux f;
    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    mm.set_payout_provider(payout_provider());
    mm.add_chain(pep_cfg(f.d.port, 1'000, 6'000));
    mm.refresh_aux_work();
    const auto job = mm.get_auxpow_commitment();
    ASSERT_EQ(job.size(), 44u);
    f.fetch_delay_ms = 5'000;
    f.new_tip("abcd");
    std::thread poll([&] { mm.refresh_aux_work(); });   // 3 calls x 5 s
    std::this_thread::sleep_for(400ms);
    const auto t0 = Clock::now();
    submit_share(mm, job);
    const long took = ms_since(t0);
    EXPECT_EQ(f.submits.load(), 1) << "the block did not reach the daemon";
    EXPECT_LT(took, 1'500) << "the find waited for the poll";
    const auto d = mm.get_discovered_blocks();
    ASSERT_FALSE(d.empty());
    EXPECT_EQ(d.back().verdict, "accepted");
    poll.join();
    f.fetch_delay_ms = 0;
    mm.stop();
}

// The P2P relay (ARM A) goes before the daemon's submitblock.
TEST(MergedAuxFind, RelayGoesBeforeTheSubmit)
{
    Rig r({{"DOGE", 98}, {"PEP", 63}});
    std::mutex mu;
    std::vector<std::string> events;
    r.mm.set_block_relay_fn([&](uint32_t cid, const std::string&) {
        std::lock_guard<std::mutex> l(mu);
        events.push_back("relay " + std::to_string(cid) + " submitted=" +
                         std::to_string(r.chain(cid == 98 ? 0 : 1).submitted()));
    });
    r.mm.refresh_aux_work();
    submit_share(r.mm, r.mm.get_auxpow_commitment());
    ASSERT_EQ(events.size(), 2u);
    for (const auto& e : events)
        EXPECT_NE(e.find("submitted=0"), std::string::npos) << e;
    EXPECT_EQ(r.chain(0).submitted(), 1u);
    EXPECT_EQ(r.chain(1).submitted(), 1u);
}

// stop() while a poll and while a find are blocked on a daemon: both return.
TEST(MergedAuxFind, StopDuringHungPollAndHungSubmit)
{
    {
        FakeAux f;
        boost::asio::io_context ioc;
        auto mm = std::make_unique<MergedMiningManager>(ioc);
        mm->set_payout_provider(payout_provider());
        mm->add_chain(pep_cfg(f.d.port, 3'000, 10'000));
        f.fetch_delay_ms = 8'000;
        mm->start();
        std::this_thread::sleep_for(600ms);
        const auto t0 = Clock::now();
        mm->stop();
        EXPECT_LT(ms_since(t0), 3'000);
        mm.reset();
        f.fetch_delay_ms = 0;
    }
    {
        FakeAux f;
        boost::asio::io_context ioc;
        auto mm = std::make_unique<MergedMiningManager>(ioc);
        mm->set_payout_provider(payout_provider());
        mm->add_chain(pep_cfg(f.d.port, 3'000, 10'000));
        mm->refresh_aux_work();
        const auto job = mm->get_auxpow_commitment();
        ASSERT_EQ(job.size(), 44u);
        f.submit_delay_ms = 8'000;
        long took_submit = -1;
        std::thread sub([&] {
            const auto t0 = Clock::now();
            submit_share(*mm, job);
            took_submit = ms_since(t0);
        });
        std::this_thread::sleep_for(400ms);
        mm->stop();
        sub.join();
        EXPECT_LT(took_submit, 3'000);
        const auto d = mm->get_discovered_blocks();
        ASSERT_EQ(d.size(), 1u);
        EXPECT_EQ(d[0].verdict.rfind("unknown: ", 0), 0u) << d[0].verdict;
        mm.reset();
    }
}

// A backend throwing something that is not a std::exception, in a poll and
// in a submit: nothing escapes, the other chain is unaffected.
TEST(MergedAuxFind, NonStdExceptionsDoNotEscape)
{
    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    mm.set_payout_provider(payout_provider());
    auto a = std::make_unique<StressBackend>("DOGE", 98, 10);
    auto b = std::make_unique<StressBackend>("PEP", 63, 10);
    auto* pa = a.get();
    auto* pb = b.get();
    mm.add_chain(pa->cfg, std::move(a));
    mm.add_chain(pb->cfg, std::move(b));
    mm.refresh_aux_work();
    const auto job = mm.get_auxpow_commitment();
    ASSERT_EQ(job.size(), 44u);
    pb->set(false, 0, true);
    pb->advance();
    EXPECT_NO_THROW(mm.refresh_aux_work());
    EXPECT_NO_THROW(submit_share(mm, job));
    EXPECT_EQ(pa->blocks_copy().size(), 1u);
    bool pep_unknown = false;
    for (const auto& x : mm.get_discovered_blocks())
        if (x.symbol == "PEP") pep_unknown = x.verdict.rfind("unknown: ", 0) == 0;
    EXPECT_TRUE(pep_unknown);
    mm.stop();
}

// ---- configuration errors found at run time ---------------------------------

// A daemon whose createauxblock chain id is not the configured one (DINGO is
// 50, not 98, since height 265,000): the chain is disabled, the others keep
// mining.
TEST(MergedAuxConfig, ChainIdMismatchDisablesTheChain)
{
    FakeAux f;
    f.chainid = 50;
    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    mm.set_payout_provider(payout_provider());
    auto doge = std::make_unique<StressBackend>("DOGE", 98, 10);
    auto* pd = doge.get();
    mm.add_chain(pd->cfg, std::move(doge));
    auto cfg = pep_cfg(f.d.port, 1'000, 1'000);
    mm.add_chain(cfg);
    mm.refresh_aux_work();
    mm.refresh_aux_work();
    std::string why;
    for (const auto& ci : mm.get_chain_infos())
        if (ci.symbol == "PEP") why = ci.config_error;
    EXPECT_NE(why.find("chain id is 50, configured 63"), std::string::npos) << why;
    const auto c = mm.get_auxpow_commitment();
    ASSERT_EQ(c.size(), 44u);
    EXPECT_EQ(c[36], 1u) << "DOGE alone";
    const int fetches_before = f.d.requests.load();
    mm.refresh_aux_work();
    EXPECT_EQ(f.d.requests.load(), fetches_before) << "a disabled chain is not polled";
    mm.stop();
}

// The payout address against the daemon's own network (L4): a regtest
// daemon refuses a testnet address; the chain is disabled with the option
// to set, at its first answer.
TEST(MergedAuxConfig, PayoutAddressOfAnotherNetworkDisablesTheChain)
{
    FakeAux f;   // says "regtest"
    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    mm.set_payout_provider(payout_provider());
    auto cfg = pep_cfg(f.d.port, 1'000, 1'000);
    cfg.aux_payout_address = b58(113, 0x11);   // a PEP testnet address
    cfg.check_payout_address = [addr = cfg.aux_payout_address](const std::string& chain) {
        return c2pool::merged::check_aux_address_on_chain("PEP", chain, addr);
    };
    mm.add_chain(cfg);
    mm.refresh_aux_work();
    std::string why;
    for (const auto& ci : mm.get_chain_infos())
        why = ci.config_error;
    EXPECT_NE(why.find("not a PEP address of the daemon's regtest network"), std::string::npos) << why;
    EXPECT_TRUE(mm.get_auxpow_commitment().empty());
    mm.stop();
    // its own network: fine
    EXPECT_TRUE(c2pool::merged::check_aux_address_on_chain("PEP", "regtest", b58(111, 0x11)).empty());
    EXPECT_TRUE(c2pool::merged::check_aux_address_on_chain("PEP", "test", b58(113, 0x11)).empty());
    EXPECT_FALSE(c2pool::merged::check_aux_address_on_chain("PEP", "main", b58(113, 0x11)).empty());
    EXPECT_TRUE(c2pool::merged::check_aux_address_on_chain("PEP", "signet", b58(113, 0x11)).empty()) << "not judged";
}

// ---- the commitment rule, shared with p2pool --------------------------------

namespace {
std::vector<unsigned char> kat_header(uint32_t cid)
{
    std::vector<unsigned char> h(80);
    for (size_t i = 0; i < 80; ++i) h[i] = static_cast<unsigned char>((cid * 7 + i) & 0xff);
    return h;
}
std::vector<std::pair<uint32_t, std::vector<unsigned char>>> kat_carried(const std::vector<uint32_t>& ids)
{
    std::vector<std::pair<uint32_t, std::vector<unsigned char>>> out;
    for (auto id : ids) out.emplace_back(id, kat_header(id));
    return out;
}
} // namespace

// The vectors pinned in p2pool test_v36_merged_multi_aux_tree.py (CROSS):
// both implementations accept these and refuse the same variants.
TEST(MergedAuxCommitment, CrossImplementationVectors)
{
    using c2pool::merged::check_merged_aux_commitment;
    struct V { std::vector<uint32_t> ids; uint32_t size; const char* root; };
    const V vs[] = {
        {{98, 63}, 2, "ff2edbdd2355c879e4cee6ef4014c9c060d04ca42ca3970c989826a7ef7f7990"},
        {{98, 63, 1}, 4, "1e38a42508658108f37c3eb2b7dfcddae24d9ebbbcf724da7f200088fd36e401"},
        {{98, 74}, 16, "528fe2cd8a23303a26e5b6b1c46d2dd3543d89a74edba2a8192c6c4013ff2db7"},
        {{98, 63, 16, 8211, 8224, 74, 1}, 32, "bb58ff2387da0d494ff1bb509a3158341f161896c43c3e3ccda775ea7341c462"},
    };
    for (const auto& v : vs) {
        uint256 root;
        root.SetHex(v.root);
        EXPECT_EQ(check_merged_aux_commitment(kat_carried(v.ids), root, v.size), "") << v.root;
        std::vector<uint32_t> rev(v.ids.rbegin(), v.ids.rend());
        EXPECT_EQ(check_merged_aux_commitment(kat_carried(rev), root, v.size), "");
        EXPECT_NE(check_merged_aux_commitment(kat_carried(v.ids), root, v.size * 2), "") << "size";
        uint256 other = root;
        other.data()[0] ^= 1;
        EXPECT_NE(check_merged_aux_commitment(kat_carried(v.ids), other, v.size), "") << "root";
        std::vector<uint32_t> fewer(v.ids.begin(), v.ids.end() - 1);
        EXPECT_NE(check_merged_aux_commitment(kat_carried(fewer), root, v.size), "") << "a chain missing";
        auto dup = kat_carried(v.ids);
        dup.push_back(dup.front());
        EXPECT_NE(check_merged_aux_commitment(dup, root, v.size), "") << "a chain twice";
        auto swapped = kat_carried(v.ids);
        swapped[0].second = kat_header(5);
        EXPECT_NE(check_merged_aux_commitment(swapped, root, v.size), "") << "another block";
    }
    uint256 any;
    any.SetHex("3039");
    EXPECT_EQ(check_merged_aux_commitment(kat_carried({98}), any, 1), "") << "one chain: the per-chain check";
    EXPECT_NE(check_merged_aux_commitment(kat_carried({98}), any, 2), "");
    EXPECT_NE(check_merged_aux_commitment(kat_carried({5, 5u + (1u << 12)}), any, 8192), "") << "too large";
    EXPECT_NE(check_merged_aux_commitment(kat_carried({5, 5u + (1u << 30)}), any, 2), "") << "no tree";
}

// p2pool's make_auxpow_tree and AuxPowTree::build give the same tree for
// every subset of the chain table and 20,000 random sets.
TEST(MergedAuxCommitment, TreeIsP2poolsForEverySubset)
{
    const std::vector<uint32_t> table{98, 63, 16, 8211, 8224, 74, 50, 1, 8225};
    for (uint32_t mask = 1; mask < (1u << table.size()); ++mask) {
        std::vector<uint32_t> ids;
        std::set<uint32_t> s;
        for (size_t k = 0; k < table.size(); ++k)
            if (mask & (1u << k)) { ids.push_back(table[k]); s.insert(table[k]); }
        const auto t = AuxPowTree::build(ids);
        std::map<uint32_t, uint32_t> slots;
        EXPECT_EQ(t.size, c2pool::merged::p2pool_aux_tree(ids, &slots)) << mask;
        EXPECT_EQ(t.size, p2pool_tree_size(s)) << mask;
        EXPECT_EQ(t.slot_map, slots) << mask;
    }
    std::mt19937 rng(7);
    for (int i = 0; i < 20000; ++i) {
        const size_t n = 1 + rng() % 9;
        std::set<uint32_t> s;
        while (s.size() < n) s.insert(rng() % 70000);
        std::vector<uint32_t> ids(s.begin(), s.end());
        const auto t = AuxPowTree::build(ids);
        const uint32_t p = c2pool::merged::p2pool_aux_tree(ids);
        if (t.size == 0) EXPECT_GT(p, 4096u);
        else EXPECT_EQ(t.size, p);
    }
}

// A chain whose block c2pool does not build (createauxblock mode) is not in
// the tree once a chain is carried: the tree is the carried chains' alone.
TEST(MergedAuxCommitment, UncarriedChainIsNotCommittedBesideCarriedOnes)
{
    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    mm.set_payout_provider(payout_provider());
    auto d = std::make_unique<Backend>("DOGE", 98, 7);
    auto p = std::make_unique<Backend>("PEP", 63, 7);
    auto pcfg = p->cfg;
    pcfg.multiaddress = false;
    const auto dcfg = d->cfg;
    mm.add_chain(dcfg, std::move(d));
    mm.add_chain(pcfg, std::move(p));
    mm.refresh_aux_work();
    auto [infos, c] = mm.get_cached_header_infos_and_commitment();
    ASSERT_EQ(infos.size(), 1u);
    EXPECT_EQ(infos[0].chain_id, 98u);
    ASSERT_EQ(c.size(), 44u);
    EXPECT_EQ(pair_problem(infos, c), "");
    EXPECT_EQ(c[36], 1u);
    mm.stop();
}

// Chains going down, hanging past the deadline, throwing non-std exceptions
// and moving at random while jobs are read and shares found on recent jobs:
// every (header infos, commitment) pair a job reads passes the peers' rule,
// every block a find sends passes the daemon's CAuxPow::check for its chain,
// and a chain not in a job's commitment gets nothing.
TEST(MergedAuxStress, FlappingChainsConcurrentJobsAndFinds)
{
    boost::asio::io_context ioc;
    auto guard = boost::asio::make_work_guard(ioc);
    std::thread io([&] { ioc.run(); });
    MergedMiningManager mm(ioc);
    mm.set_payout_provider(payout_provider());
    mm.set_refresh_round_deadline(60ms);
    std::vector<StressBackend*> chains;
    for (auto [sym, id] : std::vector<std::pair<std::string, uint32_t>>{{"DOGE", 98}, {"PEP", 63}, {"NMC", 1}, {"BELLS", 16}}) {
        auto b = std::make_unique<StressBackend>(sym, id, 1000);
        chains.push_back(b.get());
        auto cfg = b->cfg;
        mm.add_chain(cfg, std::move(b));
    }
    std::atomic<bool> done{false};
    std::atomic<long> reads{0}, bad_pairs{0}, finds{0}, bad_blocks{0}, wrong_chain{0};
    std::mutex jobs_mu;
    std::vector<std::pair<std::vector<uint8_t>, std::set<uint32_t>>> jobs;
    std::string first_bad;

    std::thread flapper([&] {
        std::mt19937 rng(11);
        const auto end = Clock::now() + std::chrono::seconds(6);
        while (Clock::now() < end) {
            for (auto* c : chains) {
                const int r = rng() % 20;
                if (r == 0) c->set(true, 0, false);
                else if (r == 1) c->set(false, 120, false);   // slower than the round deadline
                else if (r == 2) c->set(false, 0, true);
                else if (r < 8) c->set(false, 0, false);
                if (rng() % 4 == 0) c->advance();
            }
            mm.request_refresh();
            mm.mark_pplns_dirty();
            std::this_thread::sleep_for(std::chrono::milliseconds(15 + rng() % 30));
        }
        for (auto* c : chains) c->set(false, 0, false);
        done = true;
    });
    std::thread reader([&] {
        while (!done) {
            auto [infos, c] = mm.get_cached_header_infos_and_commitment();
            ++reads;
            const auto why = pair_problem(infos, c);
            if (!why.empty()) {
                if (bad_pairs++ == 0) { std::lock_guard<std::mutex> l(jobs_mu); first_bad = why; }
            } else if (!c.empty()) {
                std::set<uint32_t> ids;
                for (const auto& i : infos) ids.insert(i.chain_id);
                std::lock_guard<std::mutex> l(jobs_mu);
                if (jobs.empty() || jobs.back().first != c) {
                    jobs.emplace_back(c, ids);
                    if (jobs.size() > 40) jobs.erase(jobs.begin());
                }
            }
            (void)mm.get_chain_infos();
            (void)mm.get_rebuild_stats_json();
            std::this_thread::sleep_for(2ms);
        }
    });
    std::thread finder([&] {
        std::mt19937 rng(5);
        uint8_t salt = 1;
        while (!done) {
            std::pair<std::vector<uint8_t>, std::set<uint32_t>> job;
            bool have = false;
            {
                std::lock_guard<std::mutex> l(jobs_mu);
                if (!jobs.empty()) {
                    job = jobs[jobs.size() - 1 - rng() % std::min<size_t>(jobs.size(), 8)];
                    have = true;
                }
            }
            if (have) {
                std::map<uint32_t, size_t> before;
                for (auto* c : chains) before[c->cfg.chain_id] = c->blocks_copy().size();
                submit_share(mm, job.first, salt++);
                ++finds;
                for (auto* c : chains) {
                    const auto b = c->blocks_copy();
                    const size_t added = b.size() - before[c->cfg.chain_id];
                    if (added && !job.second.count(c->cfg.chain_id)) ++wrong_chain;
                    for (size_t k = before[c->cfg.chain_id]; k < b.size(); ++k)
                        if (core_check(parse_block(b[k]), c->cfg.chain_id).has_value()) ++bad_blocks;
                }
            }
            std::this_thread::sleep_for(10ms);
        }
    });
    flapper.join();
    reader.join();
    finder.join();
    EXPECT_EQ(bad_pairs.load(), 0) << first_bad;
    EXPECT_EQ(bad_blocks.load(), 0);
    EXPECT_EQ(wrong_chain.load(), 0);
    EXPECT_GT(finds.load(), 10);
    EXPECT_GT(reads.load(), 100);
    mm.stop();
    guard.reset();
    ioc.stop();
    io.join();
}

// ---- stratum: merged addresses by each chain's own versions (no guessing) ----

TEST(MergedAuxStratumAddress, AmbiguousAddressesAreNotAssigned)
{
    using core::merged_addr::chains_of;
    using core::merged_addr::merged_chain_info;
    using core::merged_addr::script_on_chain;
    const auto configured = [](std::set<uint32_t> s) {
        return [s](uint32_t id) { return s.count(id) > 0; };
    };
    // Bellscoin's P2SH version (30) is DOGE's P2PKH version.
    const std::string bells_p2sh = b58(30, 0x44);
    auto m = chains_of(bells_p2sh, false, configured({98, 16}));
    EXPECT_EQ(m.size(), 2u) << "DOGE and BELLS: ambiguous, never assigned";
    m = chains_of(bells_p2sh, false, configured({16}));
    ASSERT_EQ(m.size(), 1u);
    EXPECT_EQ(m[0]->chain_id, 16u);
    // paid as P2SH on BELLS, P2PKH on DOGE: never a P2PKH to a script hash
    const auto s_bells = script_on_chain(*merged_chain_info(false, 16), bells_p2sh);
    ASSERT_EQ(s_bells.size(), 23u);
    EXPECT_EQ(s_bells[0], 0xa9);
    const auto s_doge = script_on_chain(*merged_chain_info(false, 98), bells_p2sh);
    ASSERT_EQ(s_doge.size(), 25u);
    EXPECT_EQ(s_doge[0], 0x76);
    // P2SH 22 is DOGE's, PEP's and SHIC's
    EXPECT_EQ(chains_of(b58(22, 0x55), false, configured({98, 63, 74})).size(), 3u);
    // testnet 113 / regtest 111: the whole Dogecoin family
    EXPECT_EQ(chains_of(b58(113, 0x66), true, configured({98, 63})).size(), 2u);
    // a PEP address with DOGE + PEP configured: PEP alone
    m = chains_of(b58(56, 0x77), false, configured({98, 63}));
    ASSERT_EQ(m.size(), 1u);
    EXPECT_EQ(m[0]->chain_id, 63u);
    // Junkcoin bech32 (jc) and its testnet chain id 8225
    std::vector<uint8_t> prog(20, 0x31);
    m = chains_of(bech32::encode_segwit("jc", 0, prog), false, configured({8224}));
    ASSERT_EQ(m.size(), 1u);
    EXPECT_EQ(m[0]->chain_id, 8224u);
    m = chains_of(bech32::encode_segwit("tjc", 0, prog), true, configured({8225}));
    ASSERT_EQ(m.size(), 1u);
    EXPECT_EQ(m[0]->chain_id, 8225u);
    // an LTC address is no merged chain's
    EXPECT_TRUE(chains_of(b58(48, 0x11), false, configured({98, 63, 16, 8211, 8224, 74, 50, 1})).empty());
}
