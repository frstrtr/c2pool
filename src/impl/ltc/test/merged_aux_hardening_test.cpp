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
#include <cstring>
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
#include <btclibs/crypto/sha256.h>
#include <btclibs/bech32.h>
#include <btclibs/util/strencodings.h>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <c2pool/merged/aux_chain_params.hpp>
#include <c2pool/merged/aux_commitment_rule.hpp>
#include <core/merged_chain_addr.hpp>
#include <core/stratum_server.hpp>
#include <core/web_server.hpp>
#include <impl/ltc/redistribute.hpp>
#include <impl/ltc/share_check.hpp>
#include <shared_mutex>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <core/address_utils.hpp>
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

/// The same pair as a share carries it (its coinbase scriptSig holds the
/// commitment, its merged_coinbase_info the header infos): "" when a 3601
/// share built on it passes the enforced share check
/// (ltc::merged_aux_commitment_problem).
std::string v3601_share_problem(const std::vector<MHI>& infos, const std::vector<uint8_t>& c)
{
    ltc::MergedMiningShareV3601 s;
    s.m_coinbase.m_data = {0x03, 0x01, 0x02, 0x03};
    s.m_coinbase.m_data.insert(s.m_coinbase.m_data.end(), c.begin(), c.end());
    for (const auto& i : infos) {
        ltc::MergedCoinbaseEntry e;
        e.m_chain_id = i.chain_id;
        e.m_coinbase_value = i.coinbase_value;
        e.m_block_height = i.block_height;
        e.m_block_header.m_data = i.block_header;
        s.m_merged_coinbase_info.push_back(e);
    }
    return ltc::merged_aux_commitment_problem(s);
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
    EXPECT_EQ(v3601_share_problem(infos, c), "");
    EXPECT_EQ(c[36], 1u);
    mm.stop();
}

// Our own 3601 shares are never non-compliant (the AuxPoW commitment rule is
// enforced for them): for every set of the six chains, with chains down, the
// job's (header infos, commitment) pair passes the peers' rule and the 3601
// share check.
TEST(MergedAuxCommitment, Our3601SharesAreCompliantForEveryChainSet)
{
    const std::vector<std::pair<std::string, uint32_t>> all = {
        {"DOGE", 98}, {"PEP", 63}, {"BELLS", 16}, {"LKY", 8211}, {"JKC", 8224}, {"SHIC", 74}};
    int checked = 0;
    for (uint32_t mask = 1; mask < (1u << all.size()); ++mask) {
        std::vector<std::pair<std::string, uint32_t>> ids;
        for (size_t k = 0; k < all.size(); ++k)
            if (mask & (1u << k)) ids.push_back(all[k]);
        Rig r(ids);
        std::vector<std::vector<bool>> downs = {std::vector<bool>(r.chains.size(), false)};
        for (size_t k = 0; k < r.chains.size(); ++k) {
            std::vector<bool> d(r.chains.size(), false);
            d[k] = true;
            downs.push_back(d);
            std::vector<bool> rest(r.chains.size(), true);
            rest[k] = false;
            downs.push_back(rest);
        }
        for (const auto& d : downs) {
            for (size_t k = 0; k < r.chains.size(); ++k) r.chain(k).down = d[k];
            r.mm.refresh_aux_work();
            auto [infos, c] = r.mm.get_cached_header_infos_and_commitment();
            EXPECT_EQ(pair_problem(infos, c), "") << "chains " << mask;
            EXPECT_EQ(v3601_share_problem(infos, c), "") << "chains " << mask;
            ++checked;
        }
    }
    EXPECT_GT(checked, 300);
}

// Chains going down, hanging past the deadline, throwing non-std exceptions
// and moving at random while jobs are read and shares found on recent jobs:
// every (header infos, commitment) pair a job reads passes the peers' rule
// (and the 3601 share check, which enforces it),
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
            auto why = pair_problem(infos, c);
            if (why.empty())
                why = v3601_share_problem(infos, c);   // our 3601 shares: never non-compliant
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

// ---- stratum: which chain each login address is for, and what it pays -----

namespace {

const std::vector<std::string> kLtcHrps = {"ltc", "tltc", "rltc"};
std::vector<uint8_t> ltc_versions(bool tn) { return tn ? std::vector<uint8_t>{111, 196, 58} : std::vector<uint8_t>{48, 50, 5}; }
const std::vector<uint8_t> kLtcAllNetworks = {48, 50, 5, 111, 196, 58};   // main_ltc's merged_parent_versions

// The pre-change server (master handle_authorize + the job's merged scripts),
// transcribed for a DOGE-only node: table {98, {}, {0x1e, 0x16, 0x71}},
// scripts by the chain-agnostic hash160 type.
std::vector<unsigned char> master_doge_script(std::string username, std::string merged_raw, bool tn,
                                              std::map<uint32_t, std::string> explicit_addrs,
                                              std::string* final_username = nullptr)
{
    const std::vector<uint8_t> DOGE_V = {0x1e, 0x16, 0x71};
    std::map<uint32_t, std::string> m = explicit_addrs;
    if (!merged_raw.empty()) {
        bool resolved = false;
        if (core::is_address_for_chain(merged_raw, {}, DOGE_V)) { m[98] = merged_raw; resolved = true; }
        if (!resolved && core::is_address_for_chain(username, {}, DOGE_V)
            && core::is_address_for_chain(merged_raw, kLtcHrps, ltc_versions(tn))) {
            m[98] = username; username = merged_raw; resolved = true;
        }
        if (!resolved) {
            std::string t;
            if (core::address_to_hash160(merged_raw, t).size() == 40) { m[98] = merged_raw; resolved = true; }
        }
    }
    if (merged_raw.empty() && !username.empty()) {
        if (!core::is_address_for_chain(username, kLtcHrps, ltc_versions(tn))
            && core::is_address_for_chain(username, {}, DOGE_V))
            m[98] = username;
    }
    std::string atype;
    auto h = core::address_to_hash160(username, atype);
    if (h.size() == 40 && (atype == "p2pkh" || atype == "p2wpkh" || atype == "p2sh") && !m.count(98))
        m[98] = username;
    if (final_username) *final_username = username;
    if (!m.count(98)) return {};
    std::string t2;
    auto h2 = core::address_to_hash160(m[98], t2);
    return h2.size() == 40 ? core::hash160_to_merged_script(h2, t2) : std::vector<unsigned char>{};
}

struct Login { std::vector<unsigned char> script; std::string primary; bool usable{false}; std::vector<std::string> warnings; };

Login branch_login(const std::string& username, const std::string& merged_raw, bool tn,
                   std::map<uint32_t, std::string> explicit_addrs, std::set<uint32_t> configured, uint32_t chain)
{
    using namespace core::merged_addr;
    const auto table = merged_chain_table(tn, kLtcAllNetworks);
    auto lr = resolve_merged_login(username, merged_raw, explicit_addrs, table,
                                   [&configured](uint32_t id) { return configured.count(id) > 0; },
                                   ltc_versions(tn), kLtcHrps);
    Login out;
    out.usable = lr.usable_primary;
    out.warnings = lr.warnings;
    out.primary = lr.primary;
    if (lr.addresses.count(chain))
        out.script = merged_payout_script(find_chain(table, chain), lr.addresses.at(chain));
    return out;
}

} // namespace

// A DOGE-only node: for every login shape (primary address types, comma
// second addresses of every kind, swapped order, the slash form, other
// coins' and other networks' addresses), mainnet and testnet, the DOGE payout
// script is byte-identical to the pre-change one. Except, on purpose, a
// second address that is not an address at all (bad checksum, junk, in the
// comma or the slash form): the pre-change server wrote no DOGE address for
// it (the share's DOGE weight then followed Tier 1.5); now, as p2pool does,
// the chain gets the primary's hash160 (a P2SH primary's as P2SH, as before;
// the login is warned when it may be segwit-wrapped). A login whose payout
// address the pre-change server refused at the door is now accepted and
// redistributed.
TEST(MergedAuxStratumLogin, DogeOnlyPaysWhatItPaidForEveryLoginShape)
{
    std::vector<unsigned char> p20(20, 0x42), p32(32, 0x43);
    for (bool tn : {false, true}) {
        const uint8_t L = tn ? 111 : 48, M = tn ? 58 : 50, S3 = tn ? 196 : 5;
        const uint8_t D = tn ? 113 : 30, DA = tn ? 196 : 22;
        const std::string ltc_hrp = tn ? "tltc" : "ltc";
        auto bad_ck = [](std::string a) { a[a.size() - 1] = a[a.size() - 1] == 'z' ? 'y' : 'z'; return a; };
        struct U {
            std::string name, primary, merged;
            std::map<uint32_t, std::string> expl;
            bool as_p2pool = false;   // not an address: resolved as if none were given
        };
        const std::string doge = b58(D, 0x21), doge_p2sh = b58(DA, 0x22);
        const std::vector<U> us = {
            {"LTC P2PKH alone", b58(L, 0x01), ""},
            {"LTC P2SH alone", b58(M, 0x02), ""},
            {"LTC legacy-3 P2SH alone", b58(S3, 0x03), ""},
            {"ltc1q alone", bech32::encode_segwit(ltc_hrp, 0, p20), ""},
            {"ltc1 P2WSH alone", bech32::encode_segwit(ltc_hrp, 0, p32), ""},
            {"LTC,DOGE", b58(L, 0x01), doge},
            {"LTC,DOGE-P2SH", b58(L, 0x01), doge_p2sh},
            {"LTC-P2SH,DOGE", b58(M, 0x02), doge},
            {"ltc1q,DOGE", bech32::encode_segwit(ltc_hrp, 0, p20), doge},
            {"LTC,DOGE(bad checksum)", b58(L, 0x01), bad_ck(doge), {}, true},
            {"LTC-P2SH,DOGE(bad checksum)", b58(M, 0x02), bad_ck(doge), {}, true},
            {"LTC,junk", b58(L, 0x01), "notanaddress"},
            {"LTC/98:junk", b58(L, 0x01), "", {{98, "notanaddress"}}, true},
            {"LTC/98:DOGE(bad checksum)", b58(L, 0x01), "", {{98, bad_ck(doge)}}, true},
            {"DOGE,LTC (swapped)", doge, b58(L, 0x01)},
            {"DOGE(bad checksum),LTC (swapped)", bad_ck(doge), b58(L, 0x01), {}, true},
            {"DOGE(bad checksum),LTC-P2SH (swapped)", bad_ck(doge), b58(M, 0x02), {}, true},
            {"DOGE alone (case 5)", doge, ""},
            {"DOGE-P2SH alone (case 5)", doge_p2sh, ""},
            {"LTC,LTC2", b58(L, 0x01), b58(L, 0x09)},
            {"LTC,LTC2-P2SH", b58(L, 0x01), b58(M, 0x0a)},
            {"LTC-P2SH,LTC2", b58(M, 0x02), b58(L, 0x09)},
            {"LTC,ltc1q2", b58(L, 0x01), bech32::encode_segwit(ltc_hrp, 0, std::vector<unsigned char>(20, 0x0b))},
            {"LTC,BTC 1...", b58(L, 0x01), b58(0, 0x0c)},
            {"LTC,PEP P...", b58(L, 0x01), b58(56, 0x0d)},
            {"LTC,DOGE-other-net", b58(L, 0x01), b58(tn ? 30 : 113, 0x0e)},
            {"DOGE-other-net,LTC (swapped)", b58(tn ? 30 : 113, 0x0e), b58(L, 0x01)},
            {"LTC,DOGE-regtest", b58(L, 0x01), b58(111, 0x0f)},
            {"DOGE-testnet-P2SH,LTC", b58(196, 0x10), b58(L, 0x01)},
            {"LTC/98:DOGE", b58(L, 0x01), "", {{98, doge}}},
            {"LTC/98:LTC2", b58(L, 0x01), "", {{98, b58(L, 0x09)}}},
            {"LTC-P2SH/98:LTC2", b58(M, 0x02), "", {{98, b58(L, 0x09)}}},
            {"DOGE/98:DOGE2 (case 5 overrides)", doge, "", {{98, b58(D, 0x31)}}},
        };
        for (const auto& u : us) {
            // as_p2pool: the first or second address is not an address at
            // all; resolved as if absent (a swapped pair: the parent address).
            std::string p2pool_primary = u.primary;
            if (u.as_p2pool && !u.merged.empty() && u.primary == bad_ck(doge))
                p2pool_primary = u.merged;
            const auto want = u.as_p2pool ? master_doge_script(p2pool_primary, "", tn, {})
                                          : master_doge_script(u.primary, u.merged, tn, u.expl);
            const auto got = branch_login(u.primary, u.merged, tn, u.expl, {98}, 98);
            // The pre-change server refused at the door a login whose payout
            // address was neither LTC's nor DOGE's (#961); it is now accepted
            // and redistributed (no DOGE address from its key).
            std::string master_user;
            master_doge_script(u.primary, u.merged, tn, u.expl, &master_user);
            const core::CoinAddressAcceptance own{{ltc_versions(tn)[0]}, {ltc_versions(tn)[1], ltc_versions(tn)[2]},
                                                  {tn ? "tltc" : "ltc"}};
            const bool master_refused = core::decide_payout_address(master_user, own, {{{}, {0x1e, 0x16, 0x71}}})
                                        == core::PayoutAddressDecision::Reject;
            if (master_refused) {
                EXPECT_FALSE(got.usable) << (tn ? "testnet " : "mainnet ") << u.name;
                EXPECT_TRUE(got.script.empty()) << (tn ? "testnet " : "mainnet ") << u.name;
                continue;
            }
            EXPECT_TRUE(got.usable) << u.name;
            EXPECT_EQ(hex_of(std::vector<uint8_t>(got.script.begin(), got.script.end())),
                      hex_of(std::vector<uint8_t>(want.begin(), want.end())))
                << (tn ? "testnet " : "mainnet ") << u.name;
        }
    }
}

// DOGE's identification versions are the server's pre-change list exactly.
TEST(MergedAuxStratumLogin, DogeIdentificationIsUnchanged)
{
    for (bool tn : {false, true}) {
        const auto t = core::merged_addr::merged_chain_table(tn, kLtcAllNetworks);
        const auto* d = core::merged_addr::find_chain(t, 98);
        ASSERT_NE(d, nullptr);
        EXPECT_EQ(std::set<uint8_t>(d->versions.begin(), d->versions.end()), (std::set<uint8_t>{0x1e, 0x16, 0x71}));
        EXPECT_TRUE(d->hrps.empty());
    }
}

// Several merged chains: an address two configured chains could take, a
// second address no chain identifies, an ambiguous primary — never given to
// one chain by guessing and never refused: ignored with a warning naming
// PRIMARY/CHAIN_ID:ADDR, the chains get the primary's key (the miner's own;
// no cross-pay). An address of one chain goes to it.
TEST(MergedAuxStratumLogin, MultiAuxNeverGuessesNorRefuses)
{
    const std::string ltc = b58(48, 0x01);
    const auto key = [&](const std::string& a) { return core::merged_addr::merged_payout_script(nullptr, a); };
    // BELLS P2SH (30) is DOGE's P2PKH version
    auto r = branch_login(ltc, b58(30, 0x44), false, {}, {98, 16}, 98);
    EXPECT_TRUE(r.usable);
    EXPECT_EQ(r.script, key(ltc));
    ASSERT_EQ(r.warnings.size(), 1u);
    EXPECT_NE(r.warnings[0].find("98 and 16"), std::string::npos) << r.warnings[0];
    EXPECT_NE(r.warnings[0].find("PRIMARY/CHAIN_ID:ADDRESS"), std::string::npos) << r.warnings[0];
    EXPECT_EQ(branch_login(ltc, b58(30, 0x44), false, {}, {98, 16}, 16).script, key(ltc));
    // named explicitly: BELLS pays P2SH
    r = branch_login(ltc, "", false, {{16, b58(30, 0x44)}}, {98, 16}, 16);
    ASSERT_EQ(r.script.size(), 23u);
    EXPECT_EQ(r.script[0], 0xa9) << "a Bellscoin P2SH is paid as P2SH";
    // the same address on DOGE (named for it) pays DOGE P2PKH
    r = branch_login(ltc, "", false, {{98, b58(30, 0x44)}}, {98, 16}, 98);
    ASSERT_EQ(r.script.size(), 25u);
    EXPECT_EQ(r.script[0], 0x76);
    // P2SH 22: DOGE, PEP, SHIC
    r = branch_login(ltc, b58(22, 0x55), false, {}, {98, 63}, 98);
    EXPECT_EQ(r.script, key(ltc));
    EXPECT_FALSE(r.warnings.empty());
    // a PEP address with DOGE + PEP: PEP's; DOGE gets the primary's key
    r = branch_login(ltc, b58(56, 0x77), false, {}, {98, 63}, 63);
    EXPECT_EQ(r.script, key(b58(56, 0x77)));
    EXPECT_TRUE(r.warnings.empty());
    r = branch_login(ltc, b58(56, 0x77), false, {}, {98, 63}, 98);
    EXPECT_EQ(r.script, key(ltc));
    // a second address no chain identifies (another LTC address): with one
    // chain the pre-change fallback, with two ignored
    r = branch_login(ltc, b58(48, 0x09), false, {}, {98, 63}, 98);
    EXPECT_EQ(r.script, key(ltc));
    ASSERT_EQ(r.warnings.size(), 1u);
    EXPECT_NE(r.warnings[0].find("not an address of any configured merged chain"), std::string::npos);
    r = branch_login(ltc, b58(48, 0x09), false, {}, {98}, 98);
    EXPECT_EQ(r.script, key(b58(48, 0x09)));
    // an ambiguous primary (case 5): usable (the parent payout is its key),
    // every chain its key (a P2SH: on V36 jobs; dropped on 3601 jobs)
    r = branch_login(b58(22, 0x55), "", false, {}, {98, 63}, 98);
    EXPECT_TRUE(r.usable);
    EXPECT_EQ(r.script, key(b58(22, 0x55)));
    EXPECT_FALSE(r.warnings.empty());
    // swapped DOGE,LTC with DOGE + PEP: DOGE's alone
    r = branch_login(b58(30, 0x21), ltc, false, {}, {98, 63}, 98);
    EXPECT_EQ(r.primary, ltc);
    EXPECT_EQ(r.script, key(b58(30, 0x21)));
    // swapped with an ambiguous first address: the LTC address is the
    // primary, the chains its key
    r = branch_login(b58(22, 0x55), ltc, false, {}, {98, 63}, 63);
    EXPECT_EQ(r.primary, ltc);
    EXPECT_EQ(r.script, key(ltc));
    // a Junkcoin P2PKH "7..." (16) is paid P2PKH (the chain-agnostic type is P2SH)
    r = branch_login(ltc, b58(16, 0x66), false, {}, {8224}, 8224);
    ASSERT_EQ(r.script.size(), 25u);
    EXPECT_EQ(r.script[0], 0x76);
}

// Testnet: LTC testnet P2PKH 111 is DOGE regtest's; a swapped DOGE,LTC
// login neither pays DOGE to the LTC key nor LTC to the DOGE key. With PEP
// as well (whose testnet P2PKH 113 is DOGE's) the DOGE address cannot be
// told from a PEP one: ignored, both chains get the LTC address's key.
TEST(MergedAuxStratumLogin, TestnetSwappedLoginDoesNotCrossPay)
{
    const std::string doge = b58(113, 0x21), ltc = b58(111, 0x01);
    auto r = branch_login(doge, ltc, true, {}, {98}, 98);
    EXPECT_EQ(r.primary, ltc) << "the parent payout is the LTC address";
    EXPECT_EQ(r.script, core::merged_addr::merged_payout_script(nullptr, doge)) << "DOGE pays the DOGE address";
    r = branch_login(doge, ltc, true, {}, {98, 63}, 98);
    EXPECT_EQ(r.primary, ltc);
    EXPECT_EQ(r.script, core::merged_addr::merged_payout_script(nullptr, ltc));
    ASSERT_FALSE(r.warnings.empty());
    EXPECT_NE(r.warnings[0].find("98 and 63"), std::string::npos) << r.warnings[0];
    r = branch_login(ltc, "", true, {{98, doge}}, {98, 63}, 98);
    EXPECT_EQ(r.script, core::merged_addr::merged_payout_script(nullptr, doge));
}

// An empty, invalid or other-coin primary is not usable: no merged address is
// derived from it (p2pool never converts such a key), its shares are
// redistributed by the work source; with a valid DOGE address of the node's
// network as the comma second address, the parent payout is that address's
// key (p2pool's case 4).
TEST(MergedAuxStratumLogin, UnusablePrimaryIsRedistributedOrCase4)
{
    using namespace core::merged_addr;
    const auto table = merged_chain_table(false, kLtcAllNetworks);
    const auto login = [&](const std::string& p, const std::string& m, std::map<uint32_t, std::string> e,
                           std::set<uint32_t> conf) {
        return resolve_merged_login(p, m, std::move(e), table, [conf](uint32_t id) { return conf.count(id) > 0; },
                                    ltc_versions(false), kLtcHrps);
    };
    for (const std::string& u : {std::string(), std::string("rig1"), std::string("notanaddress"), b58(0, 0x61),
                                 b58(48, 0x01).substr(0, 30), b58(56, 0x31)}) {
        const auto r = login(u, "", {}, {98});
        EXPECT_FALSE(r.usable_primary) << "'" << u << "'";
        EXPECT_TRUE(r.addresses.empty()) << "'" << u << "'";
        EXPECT_TRUE(r.parent_script.empty());
    }
    // case 4: invalid primary, valid DOGE second (P2PKH and P2SH)
    auto r = login("notanaddress", b58(30, 0x21), {}, {98});
    EXPECT_FALSE(r.usable_primary);
    EXPECT_EQ(r.parent_script, core::address_to_script(b58(30, 0x21)));
    EXPECT_EQ(r.addresses.at(98), b58(30, 0x21));
    r = login(b58(0, 0x61), b58(22, 0x22), {}, {98});
    ASSERT_EQ(r.parent_script.size(), 23u) << "a DOGE P2SH gives an LTC P2SH";
    // not case 4: a DOGE address of another network, the slash form, a PEP address
    EXPECT_TRUE(login("notanaddress", b58(113, 0x21), {}, {98}).parent_script.empty());
    EXPECT_TRUE(login("notanaddress", "", {{98, b58(30, 0x21)}}, {98}).parent_script.empty());
    r = login("notanaddress", b58(56, 0x31), {}, {98, 63});
    EXPECT_TRUE(r.parent_script.empty());
    EXPECT_EQ(r.addresses.at(63), b58(56, 0x31));
    EXPECT_FALSE(r.addresses.count(98)) << "no DOGE address derived from an unusable primary";
    // a first address that is not an address before a valid LTC address: the
    // LTC address is the primary (as the pre-change server paid it)
    r = login(b58(30, 0x25).substr(1), b58(48, 0x01), {}, {98});
    EXPECT_TRUE(r.usable_primary);
    EXPECT_EQ(r.primary, b58(48, 0x01));
    // the fallback (a second address no chain identifies) needs a usable primary
    EXPECT_TRUE(login(b58(0, 0x61), b58(56, 0x31), {}, {98}).addresses.empty());
    // a P2WSH LTC address is usable (its key is the parent's) but has no hash160
    r = login(bech32::encode_segwit("ltc", 0, std::vector<unsigned char>(32, 0x43)), "", {}, {98});
    EXPECT_TRUE(r.usable_primary);
    EXPECT_TRUE(r.addresses.empty());
}

// ---- the stratum session over TCP ------------------------------------------

namespace {

// A work source that records the merged scripts each job is built with.
struct RecordingWorkSource : core::stratum::IWorkSource {
    core::stratum::StratumConfig cfg;
    std::set<uint32_t> chains;
    std::atomic<bool> ready{true};
    mutable std::mutex mu;
    mutable std::vector<std::map<uint32_t, std::vector<unsigned char>>> builds;
    mutable std::vector<std::vector<unsigned char>> payouts;
    std::vector<std::map<uint32_t, std::vector<unsigned char>>> submits;
    std::vector<std::vector<unsigned char>> submit_payouts;
    std::vector<uint32_t> submit_share_bits;   // the share bits each submit was handed
    // Node-fee and share-target knobs (set before a connection): every job
    // the operator's (decide_job_payout), the live share bits
    // (get_share_bits: the last job built), the jobs' frozen share bits, the
    // difficulty every submission has, the template's block bits.
    std::vector<unsigned char> fee_script;
    uint32_t live_bits{0x207fffff};
    uint32_t frozen_bits{0};
    double submit_difficulty{1e15};
    std::string block_bits{"207fffff"};
    mutable std::vector<core::stratum::PayoutKey> login_keys;   // build_connection_coinbase_for
    bool merged_ready() const override { return ready.load(); }
    void decide_job_payout(std::vector<unsigned char>& payout,
                           std::vector<std::pair<uint32_t, std::vector<unsigned char>>>&) const override
    {
        if (!fee_script.empty())
            payout = fee_script;
    }

    const core::stratum::StratumConfig& get_stratum_config() const override { return cfg; }
    std::function<uint256()> get_best_share_hash_fn() const override { return [] { return uint256(); }; }
    std::string get_current_gbt_prevhash() const override { return std::string(64, '1'); }
    uint64_t get_work_generation() const override { return 1; }
    bool has_merged_chain(uint32_t id) const override { return chains.count(id) > 0; }
    void register_stratum_worker(const std::string&, const core::stratum::WorkerInfo&) override {}
    void unregister_stratum_worker(const std::string&) override {}
    void update_stratum_worker(const std::string&, double, double, double, uint64_t, uint64_t, uint64_t) override {}
    nlohmann::json get_current_work_template() const override
    {
        return {{"bits", block_bits}, {"previousblockhash", std::string(64, '1')}, {"version", 0x20000000},
                {"curtime", 1793210000}, {"height", 100}};
    }
    std::vector<std::string> get_stratum_merkle_branches() const override { return {}; }
    std::pair<std::string, std::string> get_coinbase_parts() const override { return {"01000000", "00000000"}; }
    core::stratum::CoinbaseResult build_connection_coinbase(
        const uint256&, const std::string&, const std::vector<unsigned char>& payout,
        const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged) const override
    {
        std::lock_guard<std::mutex> l(mu);
        builds.emplace_back(merged.begin(), merged.end());
        payouts.push_back(payout);
        core::stratum::CoinbaseResult r;
        r.coinb1 = "01000000";
        r.coinb2 = "00000000";
        r.snapshot.frozen_ref.bits = frozen_bits;
        return r;
    }
    core::stratum::CoinbaseResult build_connection_coinbase_for(
        const core::stratum::PayoutKey& login_key, const uint256& prev, const std::string& en1,
        const std::vector<unsigned char>& payout,
        const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged) const override
    {
        {
            std::lock_guard<std::mutex> l(mu);
            login_keys.push_back(login_key);
        }
        return build_connection_coinbase(prev, en1, payout, merged);
    }
    nlohmann::json mining_submit(const std::string&, const std::string&, const std::string&, const std::string&,
                                 const std::string&, const std::string&, const std::string&,
                                 const std::map<uint32_t, std::vector<unsigned char>>& merged,
                                 const core::stratum::JobSnapshot* job) override
    {
        std::lock_guard<std::mutex> l(mu);
        submits.push_back(merged);
        submit_payouts.push_back(job && job->has_payout ? job->payout_script : std::vector<unsigned char>{0xff});
        submit_share_bits.push_back(job ? job->share_bits : 0);
        return {{"result", true}};
    }
    uint32_t get_share_bits() const override { return live_bits; }
    uint32_t get_share_max_bits() const override { return 0x207fffff; }
    double compute_share_difficulty(const std::string&, const std::string&, const std::string&, const std::string&,
                                    const std::string&, const std::string&, uint32_t, const std::string&,
                                    const std::string&, const std::vector<std::string>&) const override
    {
        return submit_difficulty;
    }
    size_t count() const
    {
        std::lock_guard<std::mutex> l(mu);
        return builds.size();
    }
    std::map<uint32_t, std::vector<unsigned char>> last() const
    {
        std::lock_guard<std::mutex> l(mu);
        return builds.empty() ? std::map<uint32_t, std::vector<unsigned char>>{} : builds.back();
    }
};

uint16_t free_port()
{
    boost::asio::io_context io;
    boost::asio::ip::tcp::acceptor a(io, {boost::asio::ip::make_address("127.0.0.1"), 0});
    return a.local_endpoint().port();
}

} // namespace

namespace {

// A stratum line client over a plain socket with a receive timeout.
struct LineClient {
    int fd = -1;
    std::string buf;
    std::string last_job;
    explicit LineClient(uint16_t port)
    {
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
            ::close(fd);
            fd = -1;
        }
        struct timeval tv{0, 50000};
        if (fd >= 0) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    }
    ~LineClient() { if (fd >= 0) ::close(fd); }
    void send(const nlohmann::json& j)
    {
        const std::string line = j.dump() + "\n";
        (void)::send(fd, line.data(), line.size(), MSG_NOSIGNAL);
    }
    // Reads until the response with `id` (also tracking mining.notify job ids).
    std::optional<nlohmann::json> wait_id(int id, int tries = 60)
    {
        for (int t = 0; t < tries; ++t) {
            size_t nl;
            while ((nl = buf.find('\n')) != std::string::npos) {
                const std::string line = buf.substr(0, nl);
                buf.erase(0, nl + 1);
                nlohmann::json j;
                try { j = nlohmann::json::parse(line); } catch (...) { continue; }
                if (j.contains("method") && j["method"] == "mining.notify" && j["params"].is_array())
                    last_job = j["params"][0].get<std::string>();
                if (j.contains("id") && j["id"].is_number() && j["id"].get<int>() == id)
                    return j;
            }
            char tmp[16384];
            const ssize_t n = ::recv(fd, tmp, sizeof tmp, 0);
            if (n > 0) buf.append(tmp, static_cast<size_t>(n));
            if (n == 0) return std::nullopt;
        }
        return std::nullopt;
    }
};

struct SessionRig {
    std::shared_ptr<RecordingWorkSource> ws = std::make_shared<RecordingWorkSource>();
    boost::asio::io_context ioc;
    std::optional<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> guard;
    std::unique_ptr<core::StratumServer> srv;
    std::thread io;
    uint16_t port = 0;
    explicit SessionRig(std::set<uint32_t> chains, bool redistribute = false)
    {
        ws->chains = std::move(chains);
        ws->cfg.redistribute_unusable_logins = redistribute;
        ws->cfg.payout_p2pkh_versions = {48};
        ws->cfg.payout_p2sh_versions = {50, 5};
        ws->cfg.payout_bech32_hrps = {"ltc"};
        ws->cfg.merged_parent_versions = kLtcAllNetworks;
        port = free_port();
        guard.emplace(boost::asio::make_work_guard(ioc));
        srv = std::make_unique<core::StratumServer>(ioc, "127.0.0.1", port, ws);
        srv->start();
        io = std::thread([this] { ioc.run(); });
    }
    // stop() closes the acceptor and the session sockets: run it on the io
    // thread, as test_stratum_interim_hardening's harness does. Calling it
    // from the test thread while ioc.run() is live raced the reactor
    // (UBSan: epoll_reactor.ipp member access within null descriptor_state).
    ~SessionRig()
    {
        std::promise<void> done;
        boost::asio::post(ioc, [&] { srv->stop(); done.set_value(); });
        done.get_future().wait();
        guard.reset();
        ioc.stop();
        io.join();
    }
    // One step on `c`; returns the authorize verdict (or true) and waits for a
    // job build when one is expected.
    bool step(LineClient& c, int id, const std::string& method, const nlohmann::json& params)
    {
        const size_t nb = ws->count();
        c.send({{"id", id}, {"method", method}, {"params", params}});
        auto r = c.wait_id(id);
        for (int i = 0; i < 100 && ws->count() == nb; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        c.wait_id(-1, 2);   // collect the notify
        return r && (*r)["result"].is_boolean() && (*r)["result"].get<bool>();
    }
};

} // namespace

// Re-authorize (round-3 review): the same primary keeps the merged address
// the previous login gave (as the pre-change server did); another primary
// inherits nothing of it; a re-authorize to an empty login gets new work at
// once instead of mining on the previous identity's job.
TEST(MergedAuxStratumSession, ReauthorizeKeepsTheGivenAddressForTheSamePrimary)
{
    using namespace std::chrono_literals;
    const std::string ltc = b58(48, 0x01), ltc2 = b58(48, 0x09), doge = b58(30, 0x21), doge2 = b58(30, 0x29);
    const auto table = core::merged_addr::merged_chain_table(false, kLtcAllNetworks);
    const auto sc = [&](uint32_t id, const std::string& a) {
        return core::merged_addr::merged_payout_script(core::merged_addr::find_chain(table, id), a);
    };
    struct Seq { std::string name; std::vector<std::pair<std::string, nlohmann::json>> steps; std::vector<unsigned char> doge; };
    const std::vector<Seq> seqs = {
        {"auth(LTC,DOGE) auth(LTC)", {{"mining.authorize", {ltc + "," + doge, "x"}}, {"mining.authorize", {ltc, "x"}}}, sc(98, doge)},
        {"auth(LTC/98:DOGE) auth(LTC)", {{"mining.authorize", {ltc + "/98:" + doge, "x"}}, {"mining.authorize", {ltc, "x"}}}, sc(98, doge)},
        {"auth(DOGE,LTC) auth(LTC)", {{"mining.authorize", {doge + "," + ltc, "x"}}, {"mining.authorize", {ltc, "x"}}}, sc(98, doge)},
        {"auth(LTC,DOGE) auth(LTC) auth(LTC)", {{"mining.authorize", {ltc + "," + doge, "x"}}, {"mining.authorize", {ltc, "x"}}, {"mining.authorize", {ltc + ".rig2", "x"}}}, sc(98, doge)},
        {"auth(LTC,DOGE) auth(LTC,DOGE2)", {{"mining.authorize", {ltc + "," + doge, "x"}}, {"mining.authorize", {ltc + "," + doge2, "x"}}}, sc(98, doge2)},
        {"auth(LTC,DOGE) auth(LTC2)", {{"mining.authorize", {ltc + "," + doge, "x"}}, {"mining.authorize", {ltc2, "x"}}}, sc(98, ltc2)},
        {"auth(LTC) auth(LTC2)", {{"mining.authorize", {ltc, "x"}}, {"mining.authorize", {ltc2, "x"}}}, sc(98, ltc2)},
        {"auth(DOGE) auth(LTC)", {{"mining.authorize", {doge, "x"}}, {"mining.authorize", {ltc, "x"}}}, sc(98, ltc)},
        {"auth(LTC,DOGE) set(98:DOGE2) auth(LTC)", {{"mining.authorize", {ltc + "," + doge, "x"}}, {"mining.set_merged_addresses", {{{"98", doge2}}}}, {"mining.authorize", {ltc, "x"}}}, sc(98, doge2)},
        {"set(98:DOGE2) auth(LTC,DOGE) auth(LTC)", {{"mining.set_merged_addresses", {{{"98", doge2}}}}, {"mining.authorize", {ltc + "," + doge, "x"}}, {"mining.authorize", {ltc, "x"}}}, sc(98, doge)},
        {"auth(LTC) set(98:junk) auth(LTC)", {{"mining.authorize", {ltc, "x"}}, {"mining.set_merged_addresses", {{{"98", "notanaddress"}}}}, {"mining.authorize", {ltc, "x"}}}, sc(98, ltc)},
    };
    for (const auto& q : seqs) {
        SessionRig rig({98});
        LineClient c(rig.port);
        ASSERT_GE(c.fd, 0);
        rig.step(c, 1, "mining.subscribe", nlohmann::json::array());
        int id = 2;
        for (const auto& [m, p] : q.steps) {
            if (m == "mining.set_merged_addresses") {
                c.send({{"id", id}, {"method", m}, {"params", p}});
                c.wait_id(id);
            } else {
                EXPECT_TRUE(rig.step(c, id, m, p)) << q.name;
            }
            ++id;
        }
        const auto m = rig.ws->last();
        ASSERT_TRUE(m.count(98)) << q.name;
        EXPECT_EQ(m.at(98), q.doge) << q.name;
    }
    // auth(LTC,DOGE) auth(EMPTY): a new job for the new (empty) identity.
    SessionRig rig({98});
    LineClient c(rig.port);
    rig.step(c, 1, "mining.subscribe", nlohmann::json::array());
    EXPECT_TRUE(rig.step(c, 2, "mining.authorize", {ltc + "," + doge, "x"}));
    const size_t n = rig.ws->count();
    EXPECT_TRUE(rig.step(c, 3, "mining.authorize", {"", "x"}));
    ASSERT_GT(rig.ws->count(), n) << "the empty login got no new job: it would mine on the previous identity's";
    std::lock_guard<std::mutex> l(rig.ws->mu);
    EXPECT_TRUE(rig.ws->payouts.back().empty());
    EXPECT_TRUE(rig.ws->builds.back().empty());
}

// The share made from a job carries the payout and merged scripts that job
// committed to, even when mining.set_merged_addresses changed them since
// (the job's ref_hash committed to the old ones).
TEST(MergedAuxStratumSession, SubmitCarriesWhatTheJobCommittedTo)
{
    using namespace std::chrono_literals;
    const std::string ltc = b58(48, 0x01), doge2 = b58(30, 0x29);
    const auto table = core::merged_addr::merged_chain_table(false, kLtcAllNetworks);
    SessionRig rig({98});
    LineClient c(rig.port);
    rig.step(c, 1, "mining.subscribe", nlohmann::json::array());
    ASSERT_TRUE(rig.step(c, 2, "mining.authorize", {ltc, "x"}));
    ASSERT_FALSE(c.last_job.empty());
    const std::string job1 = c.last_job;
    c.send({{"id", 3}, {"method", "mining.set_merged_addresses"}, {"params", {{{"98", doge2}}}}});
    c.wait_id(3);
    c.send({{"id", 4}, {"method", "mining.submit"}, {"params", {"w", job1, "00000000", "6ae2a090", "00000000"}}});
    c.wait_id(4);
    const auto nsub = [&rig] {
        std::lock_guard<std::mutex> l(rig.ws->mu);
        return rig.ws->submits.size();
    };
    for (int i = 0; i < 100 && nsub() == 0; ++i) std::this_thread::sleep_for(5ms);
    {
        std::lock_guard<std::mutex> l(rig.ws->mu);
        ASSERT_EQ(rig.ws->submits.size(), 1u);
        EXPECT_EQ(rig.ws->submits[0].at(98),
                  core::merged_addr::merged_payout_script(core::merged_addr::find_chain(table, 98), ltc))
            << "the job committed to the LTC key's DOGE script";
        EXPECT_EQ(rig.ws->submit_payouts[0], core::address_to_script(ltc));
    }
}

// --fee at the stratum session: the work source gives every job to the
// operator (decide_job_payout); the session builds it for its login's key
// (build_connection_coinbase_for), the key its pseudoshares are recorded
// under, so a work source sizes the fee job's share target by the miner's
// local rate, not by the operator's key (which has none: the fee job was the
// easiest share, 1/30 of the weight). A re-authorize to a keyless login drops
// the previous login's key.
TEST(NodeFeeStratumSession, FeeJobIsBuiltForTheLoginsKey)
{
    const std::string ltc = b58(48, 0x01);
    const auto op = core::address_to_script(b58(48, 0x0e));
    SessionRig rig({98});
    rig.ws->fee_script = op;
    LineClient c(rig.port);
    rig.step(c, 1, "mining.subscribe", nlohmann::json::array());
    ASSERT_TRUE(rig.step(c, 2, "mining.authorize", {ltc, "x"}));
    core::stratum::PayoutKey miner;
    miner.fill(0x01);
    {
        std::lock_guard<std::mutex> l(rig.ws->mu);
        ASSERT_FALSE(rig.ws->login_keys.empty()) << "the session built its job without its login key";
        EXPECT_EQ(rig.ws->login_keys.back(), miner) << "the fee job is sized by the miner's key";
        EXPECT_EQ(rig.ws->payouts.back(), op) << "the job pays the operator";
    }
    ASSERT_TRUE(rig.step(c, 3, "mining.authorize", {"", "x"}));
    {
        std::lock_guard<std::mutex> l(rig.ws->mu);
        EXPECT_EQ(rig.ws->login_keys.back(), core::stratum::PayoutKey{})
            << "a keyless login after a keyed one is sized by the zero key its pseudoshares are recorded under";
    }
}

// A submission makes a share when its PoW meets its own job's share bits, the
// bits the share carries (p2pool got_response), and the work source gets those
// bits: not the live ones (get_share_bits: the last job built, for any
// connection). Field: a fee job's easy shares were dropped whenever the last
// job built was a normal (30x harder) one.
TEST(NodeFeeStratumSession, SubmitIsJudgedByItsJobsShareBits)
{
    using namespace std::chrono_literals;
    constexpr uint32_t easy = 0x1c0bc28d, hard = 0x1b6477da;   // field: diff ~21.8 and ~652
    SessionRig rig({98});
    rig.ws->frozen_bits = easy;          // this job's share bits
    rig.ws->live_bits = hard;            // the last job built
    rig.ws->submit_difficulty = 100.0;   // meets its job's bits, not the live ones
    rig.ws->block_bits = "1a0fffff";     // no block (difficulty ~1e6)
    LineClient c(rig.port);
    rig.step(c, 1, "mining.subscribe", nlohmann::json::array());
    ASSERT_TRUE(rig.step(c, 2, "mining.authorize", {b58(48, 0x01), "x"}));
    ASSERT_FALSE(c.last_job.empty());
    c.send({{"id", 3}, {"method", "mining.submit"}, {"params", {"w", c.last_job, "00000000", "6ae2a090", "00000000"}}});
    c.wait_id(3);
    const auto nsub = [&rig] {
        std::lock_guard<std::mutex> l(rig.ws->mu);
        return rig.ws->submits.size();
    };
    for (int i = 0; i < 100 && nsub() == 0; ++i) std::this_thread::sleep_for(5ms);
    std::lock_guard<std::mutex> l(rig.ws->mu);
    ASSERT_EQ(rig.ws->submits.size(), 1u) << "a share at its job's own bits was dropped (judged by the last job built)";
    EXPECT_EQ(rig.ws->submit_share_bits[0], easy) << "the work source classifies it against its job's bits";
}

// Merged chains configured but not attached yet: a login is refused (it would
// be resolved without them and its shares would carry no merged address).
TEST(MergedAuxStratumSession, LoginWaitsForTheMergedChains)
{
    SessionRig rig({98});
    rig.ws->ready = false;
    LineClient c(rig.port);
    rig.step(c, 1, "mining.subscribe", nlohmann::json::array());
    c.send({{"id", 2}, {"method", "mining.authorize"}, {"params", {b58(48, 0x01), "x"}}});
    const auto r = c.wait_id(2);
    ASSERT_TRUE(r.has_value());
    EXPECT_FALSE((*r)["result"].get<bool>());
    EXPECT_NE((*r)["error"][1].get<std::string>().find("merged mining not ready"), std::string::npos);
    rig.ws->ready = true;
    c.send({{"id", 3}, {"method", "mining.authorize"}, {"params", {b58(48, 0x01), "x"}}});
    const auto r2 = c.wait_id(3);
    ASSERT_TRUE(r2.has_value());
    EXPECT_TRUE((*r2)["result"].get<bool>());
}

// The node fee and the redistribution are decided when the job is built, as
// in p2pool's get_work: a fee job pays the operator's script with the
// operator's merged scripts (p2pool's --merged-operator-address cascade); a
// payout a share cannot carry (empty login, P2WSH) is redistributed and the
// LTC payout never comes from a merged chain's script.
namespace {
std::string h160_of(const std::string& a)
{
    std::string t;
    return core::address_to_hash160(a, t);
}
} // namespace

TEST(MergedAuxNodeFee, JobPayoutIsDecidedAtJobTime)
{
    using Merged = std::vector<std::pair<uint32_t, std::vector<unsigned char>>>;
    const auto op = core::address_to_script(b58(50, 0x0f));            // a P2SH operator
    ASSERT_EQ(op.size(), 23u);
    const auto miner = core::address_to_script(b58(48, 0x01));
    const auto miner_doge = core::hash160_to_merged_script(h160_of(b58(48, 0x01)), "p2pkh");
    const std::map<uint32_t, std::vector<unsigned char>> op_merged = {{98, core::address_to_script(b58(30, 0x0e))},
                                                                      {63, core::address_to_script(b58(56, 0x0d))}};
    core::MiningInterface mi(false, nullptr);
    mi.set_operator_merged_scripts(op_merged);
    // fee 100%: every job is the operator's
    mi.set_node_fee(100.0, op);
    auto payout = miner;
    Merged merged = {{98, miner_doge}};
    mi.decide_job_payout(payout, merged);
    EXPECT_EQ(payout, op);
    EXPECT_EQ(Merged(op_merged.begin(), op_merged.end()), merged);
    // fee 0: unchanged
    mi.set_node_fee(0.0, op);
    payout = miner;
    merged = {{98, miner_doge}};
    mi.decide_job_payout(payout, merged);
    EXPECT_EQ(payout, miner);
    EXPECT_EQ(merged, (Merged{{98, miner_doge}}));
    // empty login: redistributed (the recipient comes with its own type);
    // landing on the operator: its type and merged scripts
    std::pair<std::string, uint8_t> pick;
    mi.set_address_fallback_fn([&pick](const std::string&) { return pick; });
    pick = {h160_of(b58(50, 0x0f)), 2};
    payout.clear();
    merged.clear();
    mi.decide_job_payout(payout, merged);
    EXPECT_EQ(payout, op) << "the operator's P2SH, not a P2PKH of its hash";
    EXPECT_EQ(Merged(op_merged.begin(), op_merged.end()), merged);
    // landing on a miner: its key, no merged scripts written
    pick = {h160_of(b58(48, 0x07)), 0};
    payout.clear();
    merged.clear();
    mi.decide_job_payout(payout, merged);
    EXPECT_EQ(payout, core::address_to_script(b58(48, 0x07)));
    EXPECT_TRUE(merged.empty());
    // a P2WSH primary with a DOGE address: the LTC payout is redistributed,
    // never taken from the DOGE script; the DOGE address stays
    payout = core::address_to_script(bech32::encode_segwit("ltc", 0, std::vector<unsigned char>(32, 0x43)));
    ASSERT_EQ(payout.size(), 34u);
    merged = {{98, core::address_to_script(b58(30, 0x21))}};
    mi.decide_job_payout(payout, merged);
    EXPECT_EQ(payout, core::address_to_script(b58(48, 0x07)));
    EXPECT_EQ(merged, (Merged{{98, core::address_to_script(b58(30, 0x21))}}));
}

// The operator's merged script: p2pool's P1 / P2 / P3 cascade.
TEST(MergedAuxNodeFee, OperatorMergedScriptCascade)
{
    using c2pool::merged::AuxNetwork;
    using c2pool::merged::resolve_operator_merged_script;
    const std::vector<unsigned char> don = {0xa9, 0x14, 1, 2, 3};
    const std::string op_p2pkh = b58(48, 0x0a), op_p2sh = b58(50, 0x0b);
    // P1: --node-owner-merged-address for DOGE
    auto r = resolve_operator_merged_script("DOGE", AuxNetwork::mainnet, op_p2pkh, b58(30, 0x0c), "", don);
    EXPECT_EQ(r.script, core::address_to_script(b58(30, 0x0c)));
    EXPECT_TRUE(r.warning.empty());
    // P1 invalid (another chain's / network's address) -> P2 with a warning
    r = resolve_operator_merged_script("DOGE", AuxNetwork::mainnet, op_p2pkh, b58(113, 0x0c), "", don);
    EXPECT_EQ(r.script, core::hash160_to_merged_script(h160_of(op_p2pkh), "p2pkh"));
    EXPECT_FALSE(r.warning.empty());
    // P2: P2SH operator stays P2SH (as before), with the segwit-wrapped warning
    r = resolve_operator_merged_script("DOGE", AuxNetwork::mainnet, op_p2sh, "", "", don);
    EXPECT_EQ(r.script.size(), 23u);
    EXPECT_EQ(r.script[0], 0xa9);
    EXPECT_NE(r.warning.find("segwit-wrapped"), std::string::npos) << r.warning;
    // P3: a P2WSH operator -> the donation script
    r = resolve_operator_merged_script("DOGE", AuxNetwork::mainnet,
                                       bech32::encode_segwit("ltc", 0, std::vector<unsigned char>(32, 0x44)), "", "", don);
    EXPECT_EQ(r.script, don);
    // another chain: --merged-payout-address SYMBOL:, not --node-owner-merged-address
    r = resolve_operator_merged_script("PEP", AuxNetwork::mainnet, op_p2pkh, b58(30, 0x0c), b58(56, 0x0d), don);
    EXPECT_EQ(r.script, core::address_to_script(b58(56, 0x0d)));
    r = resolve_operator_merged_script("PEP", AuxNetwork::mainnet, op_p2pkh, b58(30, 0x0c), "", don);
    EXPECT_EQ(r.script, core::hash160_to_merged_script(h160_of(op_p2pkh), "p2pkh"));
}

// An empty, invalid or other-coin login: accepted and redistributed where the
// work source redistributes (the LTC pool), refused elsewhere (#961).
TEST(MergedAuxStratumSession, UnusableLoginIsAcceptedAndRedistributed)
{
    for (const bool redistribute : {true, false}) {
        SessionRig rig({98}, redistribute);
        int id = 1;
        for (const std::string& u : {std::string("notanaddress"), b58(0, 0x61), b58(48, 0x06).substr(1)}) {
            LineClient c(rig.port);
            rig.step(c, id++, "mining.subscribe", nlohmann::json::array());
            const size_t n = rig.ws->count();
            EXPECT_EQ(rig.step(c, id++, "mining.authorize", {u + ".rig", "x"}), redistribute) << u;
            if (!redistribute)
                continue;
            ASSERT_GT(rig.ws->count(), n) << u;
            std::lock_guard<std::mutex> l(rig.ws->mu);
            EXPECT_TRUE(rig.ws->payouts.back().empty()) << u << ": an empty payout, redistributed by the work source";
            EXPECT_TRUE(rig.ws->builds.back().empty()) << u << ": no merged address from an unusable key";
        }
        if (!redistribute)
            continue;
        // case 4: an invalid LTC address with a valid DOGE address
        LineClient c(rig.port);
        rig.step(c, id++, "mining.subscribe", nlohmann::json::array());
        // (the comma form needs a first address longer than 20 characters)
        EXPECT_TRUE(rig.step(c, id++, "mining.authorize", {b58(48, 0x06).substr(1) + "," + b58(30, 0x21), "x"}));
        std::lock_guard<std::mutex> l(rig.ws->mu);
        EXPECT_EQ(rig.ws->payouts.back(), core::address_to_script(b58(30, 0x21)));
        EXPECT_EQ(rig.ws->builds.back().at(98), core::address_to_script(b58(30, 0x21)));
    }
}

// A redistributed job carries, for every merged chain it names no address
// for, the recipient's key converted (p2pool's never-empty merged leg), in
// the recipient's own script type; addresses the login named are kept.
TEST(MergedAuxNodeFee, RedistributedJobCarriesTheRecipientsMergedAddresses)
{
    using Merged = std::vector<std::pair<uint32_t, std::vector<unsigned char>>>;
    Rig rig({{"DOGE", 98}, {"PEP", 63}});
    core::MiningInterface mi(false, nullptr);
    mi.set_merged_mining_manager(&rig.mm);
    std::string h = h160_of(b58(48, 0x2b));   // a P2PKH / P2WPKH recipient
    uint8_t type = 1;
    mi.set_redistribute_fn([&h, &type]() { return std::pair<std::string, uint8_t>{h, type}; });
    std::vector<unsigned char> payout;
    Merged merged;
    mi.decide_job_payout(payout, merged);
    ASSERT_EQ(payout.size(), 22u) << "the recipient's own type: P2WPKH";
    EXPECT_EQ(payout[0], 0x00);
    const auto floor = core::hash160_to_merged_script(h, "p2pkh");
    EXPECT_EQ(merged, (Merged{{63, floor}, {98, floor}}));
    // an address the login named stays
    payout.clear();
    merged = {{63, core::address_to_script(b58(56, 0x31))}};
    mi.decide_job_payout(payout, merged);
    EXPECT_EQ(merged, (Merged{{63, core::address_to_script(b58(56, 0x31))}, {98, floor}}));
    // a P2SH recipient: paid as P2SH on LTC and on the merged chains (as before)
    h = h160_of(b58(50, 0x2c));
    type = 2;
    payout.clear();
    merged.clear();
    mi.decide_job_payout(payout, merged);
    EXPECT_EQ(payout, core::hash160_to_merged_script(h, "p2sh"));
    const auto p2sh_floor = core::hash160_to_merged_script(h, "p2sh");
    EXPECT_EQ(merged, (Merged{{63, p2sh_floor}, {98, p2sh_floor}}));
    // a usable payout: nothing added
    payout = core::address_to_script(b58(48, 0x01));
    merged.clear();
    mi.decide_job_payout(payout, merged);
    EXPECT_EQ(payout, core::address_to_script(b58(48, 0x01)));
    EXPECT_TRUE(merged.empty());
}

// A P2SH primary: its merged chains are paid to the same P2SH script (as
// before) and the login is warned to give its DOGE address if the P2SH is
// segwit-wrapped (on DOGE such an output is anyone-can-spend once the redeem
// script is public); a mistyped first address before a valid parent address
// pays the parent address (as before); a merged chain's bech32 address as the
// whole login warns.
TEST(MergedAuxStratumLogin, P2shPrimaryNeedsAMergedAddress)
{
    using namespace core::merged_addr;
    const auto table = merged_chain_table(false, kLtcAllNetworks);
    const auto login = [&](const std::string& p, const std::string& m, std::map<uint32_t, std::string> e,
                           std::set<uint32_t> conf) {
        return resolve_merged_login(p, m, std::move(e), table, [conf](uint32_t id) { return conf.count(id) > 0; },
                                    ltc_versions(false), kLtcHrps);
    };
    const std::string p2sh = b58(50, 0x02), legacy3 = b58(5, 0x03), doge = b58(30, 0x21);
    for (const auto& primary : {p2sh, legacy3}) {
        auto r = login(primary, "", {}, {98, 63});
        EXPECT_TRUE(r.usable_primary);
        EXPECT_EQ(r.addresses.at(98), primary) << "auto-derived, as before";
        EXPECT_EQ(r.addresses.at(63), primary);
        EXPECT_TRUE(r.p2sh_derived);
        ASSERT_FALSE(r.warnings.empty());
        EXPECT_NE(r.warnings.back().find("P2SH"), std::string::npos);
        // with the addresses given: paid there, no warning
        r = login(primary, "", {{98, doge}, {63, b58(56, 0x31)}}, {98, 63});
        EXPECT_FALSE(r.p2sh_derived);
        EXPECT_EQ(r.addresses.at(98), doge);
    }
    {
        const auto w = login(p2sh, "", {}, {98}).warnings;
        ASSERT_FALSE(w.empty());
        EXPECT_NE(w.back().find("segwit-wrapped"), std::string::npos) << w.back();
        EXPECT_NE(w.back().find("LTC_ADDRESS,DOGE_ADDRESS"), std::string::npos) << w.back();
    }
    // a P2WPKH primary is still auto-derived (its key is a plain key hash)
    EXPECT_EQ(login(bech32::encode_segwit("ltc", 0, std::vector<unsigned char>(20, 0x42)), "", {}, {98}).addresses.size(),
              1u);
    // DOGE(bad checksum),LTC: the LTC address is paid, DOGE gets its key
    const std::string bad = doge.substr(0, doge.size() - 1) + (doge.back() == 'z' ? "y" : "z");
    auto r = login(bad, b58(48, 0x01), {}, {98});
    EXPECT_TRUE(r.usable_primary);
    EXPECT_EQ(r.primary, b58(48, 0x01));
    EXPECT_EQ(r.addresses.at(98), b58(48, 0x01));
    EXPECT_FALSE(r.warnings.empty());
    r = login(bad, b58(48, 0x01), {}, {98, 63});
    EXPECT_EQ(r.primary, b58(48, 0x01));
    // a Bellscoin bech32 address as the whole login: case 5, with a warning
    r = login(bech32::encode_segwit("bel", 0, std::vector<unsigned char>(20, 0x44)), "", {}, {16});
    EXPECT_TRUE(r.usable_primary);
    EXPECT_TRUE(r.addresses.count(16));
    ASSERT_FALSE(r.warnings.empty());
    EXPECT_NE(r.warnings.front().find("bech32"), std::string::npos);
}

// --no-embedded-doge: no DOGE networking of its own (no P2P, no DNS seeds),
// whatever P2P port a --merged DOGE spec gives; other chains keep theirs.
TEST(MergedAuxConfig, NoEmbeddedDogeHasNoDogeP2p)
{
    using c2pool::merged::merged_p2p_port;
    EXPECT_EQ(merged_p2p_port("DOGE", false, 22556), 0);
    EXPECT_EQ(merged_p2p_port("doge", false, 44556), 0);
    EXPECT_EQ(merged_p2p_port("DOGE", true, 22556), 22556);
    EXPECT_EQ(merged_p2p_port("PEP", false, 33874), 33874);
    EXPECT_EQ(merged_p2p_port("DINGO", false, 33117), 33117);
}

// The redistribution pick reads the tracker: from the stratum thread only
// under a try-acquired read lock (main_ltc.cpp: node.read_tracker()), else the
// operator / donation identity. A compute thread adds shares under the
// exclusive lock meanwhile (run under TSAN: merged_tsan_test).
TEST(MergedAuxRedistribute, PickTakesTheTrackerReadLock)
{
    ltc::ShareTracker tr;
    std::shared_mutex tracker_mutex;   // node.hpp m_tracker_mutex
    const auto hxid = [](uint64_t n) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%llx", static_cast<unsigned long long>(n));
        uint256 v;
        v.SetHex(std::string(64 - std::strlen(buf), '0') + buf);
        return v;
    };
    const auto add = [&](uint64_t id, const uint256& prev) {
        auto* sh = new ltc::MergedMiningShare();
        sh->m_hash = hxid(id);
        sh->m_prev_hash = prev;
        sh->m_desired_version = 36;
        sh->m_bits = 0x1e0fffff;
        sh->m_max_bits = 0x1e0fffff;
        sh->m_pubkey_hash.SetHex(std::string(38, '0') + std::to_string(id % 10) + "1");
        ltc::ShareType st;
        st = sh;
        tr.add(st);
        return sh->m_hash;
    };
    uint256 tip;
    for (int i = 0; i < 200; ++i) tip = add(0x100 + i, tip);
    std::atomic<uint64_t> best_id{0x100 + 199};
    std::atomic<bool> stop{false};
    std::thread compute([&] {
        uint256 prev = tip;
        for (int i = 200; i < 1200 && !stop; ++i) {
            std::unique_lock<std::shared_mutex> l(tracker_mutex);
            prev = add(0x100 + i, prev);
            best_id = 0x100 + i;
        }
    });
    uint160 op;
    op.SetHex(std::string(38, '0') + "ee");
    int picked = 0, busy = 0;
    for (int i = 0; i < 300; ++i) {
        ltc::Redistributor r;
        r.set_mode(ltc::RedistributeMode::PPLNS);
        r.set_operator_identity(op, 0);
        std::shared_lock<std::shared_mutex> l(tracker_mutex, std::try_to_lock);
        const auto res = r.pick_if_locked(l, tr, hxid(best_id.load()));
        if (l) ++picked; else { ++busy; EXPECT_EQ(res.pubkey_hash, op); }
    }
    stop = true;
    compute.join();
    EXPECT_EQ(picked + busy, 300);
}

// ---- the commitment rule: generated parity vectors, log-only ----------------

namespace {
struct SplitMix64 {
    uint64_t s;
    uint64_t next()
    {
        s += 0x9E3779B97F4A7C15ull;
        uint64_t z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    uint64_t below(uint64_t n) { return next() % n; }
};
std::vector<unsigned char> sha256d_bytes(const std::vector<unsigned char>& b)
{
    const uint256 h = Hash(std::span<const unsigned char>(b.data(), b.size()));
    return std::vector<unsigned char>(h.data(), h.data() + 32);
}
std::vector<unsigned char> pmerkle(uint32_t size, const std::map<uint32_t, std::vector<unsigned char>>& leaves)
{
    std::vector<std::vector<unsigned char>> layer(size, std::vector<unsigned char>(32, 0));
    for (const auto& [i, v] : leaves) layer[i] = v;
    while (layer.size() > 1) {
        std::vector<std::vector<unsigned char>> next(layer.size() / 2);
        for (size_t k = 0; k < next.size(); ++k) {
            auto cat = layer[2 * k];
            cat.insert(cat.end(), layer[2 * k + 1].begin(), layer[2 * k + 1].end());
            next[k] = sha256d_bytes(cat);
        }
        layer = std::move(next);
    }
    return layer[0];
}
uint32_t pid(SplitMix64& r)
{
    static const uint32_t REAL[] = {98, 63, 16, 8211, 8224, 8225, 74, 50, 1, 2, 7};
    static const uint32_t SPECIAL[] = {5, 5u + (1u << 30), 5u + (1u << 29), 5u + (1u << 12), 5u + (1u << 11), 0xffffffffu, 0};
    const uint64_t c = r.below(100);
    if (c < 60) return REAL[r.below(11)];
    if (c < 75) return static_cast<uint32_t>(r.below(1 << 16));
    if (c < 85) return static_cast<uint32_t>(r.next() & 0xffffffffu);
    if (c < 93) return SPECIAL[r.below(7)];
    return 98u + (1u << (1 + r.below(30)));
}
std::vector<unsigned char> pbytes(SplitMix64& r, size_t n)
{
    std::vector<unsigned char> v(n);
    for (auto& b : v) b = static_cast<unsigned char>(r.next() & 0xff);
    return v;
}
struct PVec { std::vector<unsigned char> root; uint32_t size; std::vector<std::pair<uint32_t, std::vector<unsigned char>>> carried; };
// The same generator as p2pool test_v36_merged_multi_aux_tree.py parity_vector.
PVec parity_vector(SplitMix64& r)
{
    static const int KS[] = {1, 1, 2, 2, 2, 3, 3, 4, 5, 6, 8};
    std::vector<uint32_t> ids;
    const int k = KS[r.below(11)];
    for (int i = 0; i < k; ++i) ids.push_back(pid(r));
    if (r.below(100) < 8) ids.push_back(ids[r.below(ids.size())]);
    PVec v;
    for (auto cid : ids) {
        size_t hl = 80;
        if (r.below(100) < 4) { static const size_t HL[] = {0, 79, 81, 160}; hl = HL[r.below(4)]; }
        v.carried.emplace_back(cid, pbytes(r, hl));
    }
    std::vector<uint32_t> uniq;
    for (auto c : ids) if (std::find(uniq.begin(), uniq.end(), c) == uniq.end()) uniq.push_back(c);
    std::map<uint32_t, uint32_t> slots;
    const uint32_t size = c2pool::merged::p2pool_aux_tree(uniq, &slots);
    std::vector<unsigned char> good(32, 0);
    if (size > 0 && size <= 4096) {
        std::map<uint32_t, std::vector<unsigned char>> leaves;
        for (const auto& [c, h] : v.carried) leaves[slots.at(c)] = sha256d_bytes(h);
        good = pmerkle(size, leaves);
    }
    const uint64_t mode = r.below(100);
    v.root = good;
    v.size = size;
    if (mode < 45) return v;
    if (mode < 55) {
        const auto i = r.below(32);
        v.root[i] ^= static_cast<unsigned char>(1u << r.below(8));
        return v;
    }
    if (mode < 62) {
        const uint64_t opts[] = {0, 1, 2, 4, uint64_t(size) * 2, std::max<uint64_t>(size / 2, 1), 1ull << 31, 4096, 8192,
                                 r.next() & 0xffffffffu};
        // (python builds the whole list, drawing next() for the last option,
        // before choosing: the braced list above draws it in the same order)
        v.size = static_cast<uint32_t>(opts[r.below(10)] & 0xffffffffu);
        return v;
    }
    if (mode < 75) {
        std::vector<uint32_t> extra;
        const auto ne = r.below(2) + 1;
        for (uint64_t i = 0; i < ne; ++i) extra.push_back(pid(r));
        std::vector<uint32_t> allids = uniq;
        for (auto c : extra) if (std::find(allids.begin(), allids.end(), c) == allids.end()) allids.push_back(c);
        std::map<uint32_t, uint32_t> sl2;
        const uint32_t s2 = c2pool::merged::p2pool_aux_tree(allids, &sl2);
        if (s2 > 0 && s2 <= 4096) {
            std::map<uint32_t, std::vector<unsigned char>> leaves;
            for (const auto& [c, h] : v.carried) leaves[sl2.at(c)] = sha256d_bytes(h);
            for (auto c : extra)
                if (std::find(uniq.begin(), uniq.end(), c) == uniq.end() && r.below(2) == 0)
                    leaves[sl2.at(c)] = pbytes(r, 32);
            v.root = pmerkle(s2, leaves);
            v.size = s2;
        }
        return v;
    }
    if (mode < 82 && v.carried.size() == 1) {
        auto h = v.carried[0].second;
        if (h.size() > 80) h.resize(80);
        v.root = r.below(10) < 7 ? sha256d_bytes(h) : pbytes(r, 32);
        static const uint32_t SZ[] = {1, 1, 1, 2, 0};
        v.size = SZ[r.below(5)];
        return v;
    }
    if (mode < 90) {
        if (size > 0 && size <= 4096 && uniq.size() >= 2) {
            std::map<uint32_t, std::vector<unsigned char>> leaves;
            for (size_t i = 0; i < v.carried.size(); ++i) leaves[i % size] = sha256d_bytes(v.carried[i].second);
            v.root = pmerkle(size, leaves);
        }
        return v;
    }
    v.root = pbytes(r, 32);
    v.size = r.below(10) < 3 ? static_cast<uint32_t>(r.next() & 0xffffffffu) : static_cast<uint32_t>(1u << r.below(4));
    return v;
}
std::string parity_class(const std::string& why)
{
    if (why.empty()) return "A";
    if (why.find("twice") != std::string::npos) return "R:dup";
    if (why.find("larger than") != std::string::npos) return "R:big";
    if (why.find("size mismatch") != std::string::npos) return "R:size";
    if (why.find("not 80 bytes") != std::string::npos) return "R:hdr";
    if (why.find("aux root") != std::string::npos) return "R:root";
    return "R:other";
}
} // namespace

// 5,000 generated vectors; the verdicts' digest is pinned here and in p2pool
// test_v36_merged_multi_aux_tree.py ParityVectors: both implementations give
// the same verdict on each.
TEST(MergedAuxCommitment, ParityVectors)
{
    SplitMix64 r{2026};
    std::string all;
    std::map<std::string, int> counts;
    for (int i = 0; i < 5000; ++i) {
        const auto v = parity_vector(r);
        uint256 root;
        std::memcpy(root.data(), v.root.data(), 32);
        const auto cls = parity_class(c2pool::merged::check_merged_aux_commitment(v.carried, root, v.size));
        all += cls + "\n";
        ++counts[cls];
    }
    EXPECT_EQ(counts, (std::map<std::string, int>{{"A", 1896}, {"R:big", 131}, {"R:dup", 1121},
                                                  {"R:hdr", 296}, {"R:root", 671}, {"R:size", 885}}));
    unsigned char out[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(all.data()), all.size()).Finalize(out);
    EXPECT_EQ(HexStr(std::span<const unsigned char>(out, CSHA256::OUTPUT_SIZE)),
              "a37fc58712ab0392114cd05d1e6cf13432ab577a3aaab06200b3d76f7677a83c");
}

// V36 shares: a verdict is counted (and the first ones logged), never turned
// into a rejection by the share check (3601 shares: enforced,
// share_v3601_flag_day_test.cpp).
TEST(MergedAuxCommitment, RuleIsCountedNotEnforced)
{
    auto& st = c2pool::merged::merged_rule_stats();
    const auto c0 = st.checked.load(), w0 = st.would_reject.load();
    EXPECT_FALSE(c2pool::merged::note_merged_rule_verdict(""));
    EXPECT_TRUE(c2pool::merged::note_merged_rule_verdict("merged aux tree size mismatch: expected 1 for chains [98], got 2"));
    EXPECT_EQ(st.checked.load(), c0 + 2);
    EXPECT_EQ(st.would_reject.load(), w0 + 1);
    std::lock_guard<std::mutex> l(st.mu);
    EXPECT_NE(st.last_reason.find("size mismatch"), std::string::npos);
}

// A block found again (shares on a job whose block is already out) is
// recorded once: total and per-chain counts and the recent list do not grow.
TEST(MergedAuxFind, RefindOfTheSameBlockIsRecordedOnce)
{
    Rig r({{"DOGE", 98}, {"PEP", 63}});
    int calls = 0;
    r.mm.set_on_merged_block_found([&calls](const std::string&, int, const std::string&, bool, uint64_t) { ++calls; });
    r.mm.refresh_aux_work();
    const auto job = r.mm.get_auxpow_commitment();
    submit_share(r.mm, job, 0x11);
    r.chain(1).verdict = SubmitVerdict::of(SubmitVerdict::Kind::duplicate, "duplicate");
    submit_share(r.mm, job, 0x12);
    submit_share(r.mm, job, 0x13);
    EXPECT_EQ(r.chain(0).submitted(), 3u);
    EXPECT_EQ(r.mm.get_discovered_blocks().size(), 2u);
    EXPECT_EQ(r.mm.get_total_blocks(), 2u);
    EXPECT_EQ(r.mm.get_chain_block_count(98), 1u);
    EXPECT_EQ(r.mm.get_chain_block_count(63), 1u);
    EXPECT_EQ(calls, 2);
}
