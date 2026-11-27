// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// DGB+DOGE merged mining pays (rides dgb_work_source_test, allowlisted).
//
// Before: main_dgb registered no merged payout provider, so every rebuild of
// the DOGE block recorded "no_provider", the commitment stayed empty and the
// DGB coinbase never carried fabe6d6d; DGBWorkSource::has_merged_chain() was
// hard false, so no stratum login reached the DOGE chain; the createauxblock
// address was a placeholder. These pin, on the real functions:
//   - the provider is registered (wire_doge_merged_payouts) and the DOGE
//     commitment is non-empty and spliced into the DGB coinbase;
//   - the DOGE outputs are the share chain's PPLNS split with the shares'
//     merged addresses (get_merged_expected_payouts), conserving the value;
//   - a share without a merged address is paid at its own key (derived);
//   - the fallback address is the single donation P2PKH c2pool-dash pays,
//     as a DOGE address, recomputed from the hash160 bytes;
//   - has_merged_chain() follows the manager: the "DGB,DOGE" login, the
//     auto-derived DOGE address, and an explicit PRIMARY/98:ADDR winning;
//   - no --merged: nothing bound and the coinbase is byte-identical.
// ---------------------------------------------------------------------------

#include <impl/dgb/coin/aux_doge_payout_provider.hpp>
#include "doge_backend_fixture.hpp"

#include <impl/dgb/address_encoding.hpp>       // dgb::address_acceptance
#include <impl/dgb/best_share_cell.hpp>        // wire_best_share (the one best-change hook)
#include <impl/dgb/coin/connection_coinbase.hpp>
#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/config_coin.hpp>
#include <impl/dgb/config_pool.hpp>
#include <impl/dgb/share.hpp>
#include <impl/dgb/share_check.hpp>           // pubkey_hash_to_script
#include <impl/dgb/share_tracker.hpp>
#include <impl/dgb/stratum/work_source.hpp>

#include <c2pool/merged/aux_chain_params.hpp>
#include <c2pool/merged/merged_mining.hpp>
#include <core/address_utils.hpp>
#include <core/donation.hpp>
#include <core/merged_chain_addr.hpp>
#include <core/pow.hpp>
#include <core/uint256.hpp>

#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;
using Payouts = dgb::coin::DogePayouts;
using c2pool::merged::MergedMiningManager;

constexpr uint32_t kDoge = 98;

std::string hex(const Bytes& b)
{
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (auto c : b) {
        s += H[c >> 4];
        s += H[c & 0xf];
    }
    return s;
}

std::string le64_hex(uint64_t v)
{
    Bytes b(8);
    for (int i = 0; i < 8; ++i)
        b[i] = static_cast<unsigned char>((v >> (8 * i)) & 0xff);
    return hex(b);
}

Bytes h160(unsigned char fill) { return Bytes(20, fill); }

Bytes p2pkh(const Bytes& h)
{
    Bytes s{0x76, 0xa9, 0x14};
    s.insert(s.end(), h.begin(), h.end());
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

Bytes p2wpkh(const Bytes& h)
{
    Bytes s{0x00, 0x14};
    s.insert(s.end(), h.begin(), h.end());
    return s;
}

uint160 as_uint160(const Bytes& h) { return uint160(base_uint<160>(h)); }

// ── A share chain with known merged weights ────────────────────────────────
// Four V36 shares of equal work, donation 0 (oldest first):
//   s0, s1: miner A (P2PKH a1..), explicit merged address X on chain 98;
//   s2:     miner B (P2PKH b2..), no merged address  -> paid at its own key;
//   s3:     miner C (P2WPKH c3..), no merged address -> its key as P2PKH.
const Bytes kHashA = h160(0xa1);
const Bytes kHashB = h160(0xb2);
const Bytes kHashC = h160(0xc3);
const Bytes kDogeX = p2pkh(h160(0x5c));   // miner A's explicit DOGE script

struct ShareChain {
    dgb::ShareTracker tracker;
    uint256 best;

    ShareChain()
    {
        auto mk = [&](uint8_t n, const Bytes& h, uint8_t type, const Bytes* merged) {
            auto* s = new dgb::MergedMiningShare();
            s->m_hash = uint256(std::vector<unsigned char>(32, static_cast<unsigned char>(0xd0 + n)));
            if (n == 0)
                s->m_prev_hash.SetNull();
            else
                s->m_prev_hash = uint256(std::vector<unsigned char>(32, static_cast<unsigned char>(0xd0 + n - 1)));
            s->m_pubkey_hash = as_uint160(h);
            s->m_pubkey_type = type;
            s->m_donation = 0;
            s->m_desired_version = 36;
            s->m_bits = 0x1e0fffff;
            s->m_max_bits = 0x1e0fffff;
            s->m_min_header.m_bits = 0x1e0ffff0;
            if (merged) {
                dgb::MergedAddressEntry e;
                e.m_chain_id = kDoge;
                e.m_script.m_data = *merged;
                s->m_merged_addresses.push_back(e);
            }
            best = s->m_hash;
            dgb::ShareType st;
            st = s;
            tracker.add(st);
        };
        mk(0, kHashA, 0, &kDogeX);
        mk(1, kHashA, 0, &kDogeX);
        mk(2, kHashB, 0, nullptr);
        mk(3, kHashC, 1, nullptr);
    }
};

// The node surface the provider uses (dgb::NodeImpl's): best_share_hash(),
// a try-locked read_tracker() guard, set_on_best_share_changed().
struct FakeNode {
    dgb::ShareTracker& tracker;
    uint256 best;
    std::shared_mutex mtx;
    std::function<void()> on_best;

    struct Guard {
        std::shared_lock<std::shared_mutex> lk;
        dgb::ShareTracker* t;
        explicit operator bool() const { return lk.owns_lock(); }
        dgb::ShareTracker& operator*() { return *t; }
    };

    FakeNode(dgb::ShareTracker& t, const uint256& b) : tracker(t), best(b) {}
    uint256 best_share_hash() { return best; }
    Guard read_tracker() { return Guard{std::shared_lock<std::shared_mutex>(mtx, std::try_to_lock), &tracker}; }
    void set_on_best_share_changed(std::function<void()> fn) { on_best = std::move(fn); }
};

using dgb_test::DogeBackend;
using dgb_test::add_doge;

const core::SubsidyFunc kSubsidy = [](uint32_t h) -> uint64_t { return dgb::CoinParams::subsidy(h); };

struct WsFixture {
    c2pool::dgb::HeaderChain chain;
    dgb::coin::Mempool mempool;
    std::unique_ptr<dgb::stratum::DGBWorkSource> make()
    {
        auto fn = [](const std::vector<unsigned char>&, uint32_t) -> bool { return false; };
        auto ws = std::make_unique<dgb::stratum::DGBWorkSource>(chain, mempool, /*is_testnet=*/false, fn, kSubsidy);
        // A job needs a template (its block): the external-daemon tip fallback.
        ws->set_gbt_tip_fn([]() -> std::optional<dgb::stratum::DGBWorkSource::GbtTip> {
            return dgb::stratum::DGBWorkSource::GbtTip{std::string(64, '1'), "1b0404cb"};
        });
        return ws;
    }
};

dgb::coin::ConnCoinbasePplnsInputs pplns_inputs()
{
    dgb::coin::ConnCoinbasePplnsInputs in;
    in.coinbase_script = Bytes{0x03, 0x01, 0x02, 0x03};
    in.weights = {{p2pkh(kHashA), uint288(3)}, {p2pkh(kHashB), uint288(1)}};
    in.total_weight = uint288(4);
    in.subsidy = 72000000000ULL;
    in.use_v36_pplns = true;
    in.donation_script = dgb::PoolConfig::get_donation_script(36);
    in.ref_hash = uint256(std::vector<unsigned char>(32, 0xab));
    in.last_txout_nonce = 0x0102030405060708ULL;
    return in;
}

void bind_inputs(dgb::stratum::DGBWorkSource& ws)
{
    const auto in = pplns_inputs();
    // As the producer does (conn_job_producer.hpp): the tagged commitment ends
    // the coinbase scriptSig.
    ws.set_pplns_inputs_fn([in](const uint256&, const std::string&, const Bytes&,
                                const std::vector<std::pair<uint32_t, Bytes>>&, const Bytes& aux, const dgb::stratum::DGBWorkSource::JobBlock&)
                               -> std::optional<dgb::coin::ConnCoinbasePplnsInputs> {
        auto r = in;
        r.coinbase_script.insert(r.coinbase_script.end(), aux.begin(), aux.end());
        return r;
    });
}

std::string coinbase_hex(dgb::stratum::DGBWorkSource& ws)
{
    auto r = ws.build_connection_coinbase(uint256(std::vector<unsigned char>(32, 0x11)), "cafef00d",
                                          Bytes{0x76, 0xa9, 0x14, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x88, 0xac}, {});
    return r.coinb1 + r.coinb2;
}

std::string ssot_coinbase_hex()
{
    auto o = dgb::coin::build_connection_coinbase_from_pplns(pplns_inputs());
    return o.coinb1 + o.coinb2;
}

uint64_t sum(const Payouts& p)
{
    uint64_t s = 0;
    for (const auto& [_, v] : p)
        s += v;
    return s;
}

const Bytes& combined_donation()
{
    static const Bytes d = dgb::PoolConfig::get_donation_script(36);
    return d;
}

} // namespace

// ── Fallback address: the single donation P2PKH c2pool-dash pays ───────────

TEST(DgbDogeMergedPayout, FallbackScriptIsTheDashDonationP2pkhNotTheP2sh)
{
    const Bytes h = {0x20, 0xcb, 0x5c, 0x22, 0xb1, 0xe4, 0xd5, 0x94, 0x7e, 0x5c,
                     0x11, 0x2c, 0x76, 0x96, 0xb5, 0x1a, 0xd9, 0xaf, 0x3c, 0x61};
    const Bytes script = dgb::coin::doge_fallback_payout_script();
    EXPECT_EQ(hex(script), "76a914" + hex(h) + "88ac");
    EXPECT_EQ(script, p2pkh(h));
    EXPECT_NE(script, combined_donation());
    EXPECT_NE(script, Bytes(core::donation::COMBINED_DONATION_SCRIPT.begin(),
                            core::donation::COMBINED_DONATION_SCRIPT.end()));
    // The same key is the DASH donation address c2pool-dash documents
    // (dash share_check.hpp DONATION_SCRIPT, DASH P2PKH 76 / P2SH 16).
    EXPECT_EQ(core::script_to_address(script, "", 76, 16), "XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u");
}

TEST(DgbDogeMergedPayout, FallbackAddressIsDogeP2pkhRecomputedFromHash160)
{
    const Bytes script = p2pkh(Bytes(dgb::coin::DONATION_P2PKH_HASH160.begin(),
                                     dgb::coin::DONATION_P2PKH_HASH160.end()));
    // Recomputed from the bytes with DOGE's P2PKH versions (30 main, 113 test).
    const std::string main_addr = core::script_to_address(script, "", 30, 22);
    const std::string test_addr = core::script_to_address(script, "", 113, 196);
    EXPECT_EQ(main_addr, "D88Vn6Dyct7DKfVCfR3syHkjyNx9gEyyiv");
    EXPECT_EQ(test_addr, "nXBZW6xtYrZwCe4PhEhLDhM3DFLSd1pa1R");
    EXPECT_EQ(dgb::coin::doge_fallback_payout_address(false), main_addr);
    EXPECT_EQ(dgb::coin::doge_fallback_payout_address(true), test_addr);

    // A DOGE address of the right network that pays exactly that P2PKH.
    Bytes back;
    ASSERT_EQ(core::classify_address_for_coin(main_addr, {30}, {22}, {}, back), core::AddressCoinMatch::Own);
    EXPECT_EQ(back, script);
    back.clear();
    ASSERT_EQ(core::classify_address_for_coin(test_addr, {113}, {196}, {}, back), core::AddressCoinMatch::Own);
    EXPECT_EQ(back, script);

    // Never a placeholder / burn default.
    const auto* p = c2pool::merged::find_aux_chain_params("DOGE");
    ASSERT_NE(p, nullptr);
    EXPECT_NE(main_addr, std::string(p->default_main_address));
    EXPECT_NE(test_addr, std::string(p->default_test_address));
    EXPECT_NE(main_addr, "DDogepartyxxxxxxxxxxxxxxxxxxw1dfzr");
    EXPECT_NE(test_addr, "nUCAGGgZEPN1QyknmQe1oAku817bQAFKFt");
}

// ── Provider: the share chain's PPLNS with the shares' merged addresses ────

TEST(DgbDogeMergedPayout, ProviderFollowsMergedExpectedPayouts)
{
    ShareChain sc;
    FakeNode node(sc.tracker, sc.best);
    auto provider = dgb::coin::make_doge_payout_provider(&node);
    const uint64_t value = 4'000'000'000ULL;

    const Payouts got = provider(kDoge, value);
    ASSERT_FALSE(got.empty());

    // Oracle: the tracker's merged split at the same best share.
    uint256 block_target = chain::bits_to_target(0x1e0ffff0);
    auto m = sc.tracker.get_merged_expected_payouts(sc.best, block_target, value, kDoge, combined_donation(),
                                                    {}, {});
    Payouts oracle;   // map order: sorted by script
    for (auto& [s, v] : m)
        if (v >= 1)
            oracle.emplace_back(s, v);
    EXPECT_EQ(got, oracle);
    for (size_t i = 1; i < got.size(); ++i)
        EXPECT_NE(got[i - 1].first, got[i].first) << "one output per script";

    // The whole DOGE value is paid, nothing burned or invented.
    EXPECT_EQ(sum(got), value);

    // Known split (four equal-work shares, donation 0): A's two shares under
    // its explicit DOGE script X, B at its own P2PKH, C's P2WPKH key as a
    // DOGE P2PKH; the V36 >= 1 sat donation comes off the largest (X).
    std::map<Bytes, uint64_t> by(got.begin(), got.end());
    EXPECT_EQ(by.size(), 4u);
    EXPECT_EQ(by[kDogeX], 1'999'999'999ULL);
    EXPECT_EQ(by[p2pkh(kHashB)], 1'000'000'000ULL);
    EXPECT_EQ(by[p2pkh(kHashC)], 1'000'000'000ULL);
    EXPECT_EQ(by[combined_donation()], 1ULL);
    // A's parent key is not paid on DOGE: its explicit merged address is.
    EXPECT_EQ(by.count(p2pkh(kHashA)), 0u);
}

TEST(DgbDogeMergedPayout, ProviderEmptyWithoutBestShareOrWhileTrackerBusy)
{
    ShareChain sc;
    FakeNode none(sc.tracker, uint256());
    EXPECT_TRUE(dgb::coin::make_doge_payout_provider(&none)(kDoge, 1000).empty());

    FakeNode node(sc.tracker, sc.best);
    auto provider = dgb::coin::make_doge_payout_provider(&node);
    std::promise<void> locked, release;
    auto release_f = release.get_future().share();
    std::thread holder([&] {
        std::unique_lock<std::shared_mutex> lk(node.mtx);   // the compute thread's exclusive lock
        locked.set_value();
        release_f.wait();
    });
    locked.get_future().wait();
    EXPECT_TRUE(provider(kDoge, 1000).empty()) << "a busy tracker is never waited for";
    release.set_value();
    holder.join();
    EXPECT_FALSE(provider(kDoge, 1000).empty());
}

// ── Registered provider: non-empty commitment, spliced into the DGB coinbase ─

TEST(DgbDogeMergedPayout, WiredProviderGivesNonEmptyCommitmentInDgbCoinbase)
{
    ShareChain sc;
    FakeNode node(sc.tracker, sc.best);
    WsFixture fx;
    auto ws = fx.make();
    bind_inputs(*ws);

    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    add_doge(mm);
    ws->set_merged_mining_manager(&mm);

    ASSERT_TRUE(dgb::coin::wire_doge_merged_payouts(&mm, node, ws.get()));
    EXPECT_FALSE(static_cast<bool>(node.on_best)) << "the DOGE wiring leaves the single best-change slot alone";
    EXPECT_TRUE(mm.is_pplns_dirty()) << "initial dirty mark";
    // main_dgb's one best-change hook, with the DOGE dirty mark (as main_dgb binds it).
    boost::asio::io_context hook_ioc;
    auto cell = std::make_shared<dgb::BestShareCell>();
    dgb::wire_best_share(node, cell, ws.get(), hook_ioc, [&mm]() { mm.mark_pplns_dirty(); });
    ASSERT_TRUE(static_cast<bool>(node.on_best)) << "best-share change hook bound";
    EXPECT_EQ(cell->get(), sc.best);

    mm.refresh_aux_work();
    const auto snap = mm.get_cached_header_infos_and_commitment();
    const auto& commitment = snap.second;
    ASSERT_EQ(commitment.size(), 44u) << "DOGE commitment non-empty";
    EXPECT_EQ(hex(Bytes(commitment.begin(), commitment.begin() + 4)), "fabe6d6d");
    ASSERT_EQ(snap.first.size(), 1u);
    EXPECT_EQ(snap.first[0].chain_id, kDoge);

    // The DOGE coinbase pays exactly the provider's outputs.
    const Payouts expect = dgb::coin::make_doge_payout_provider(&node)(kDoge, 1000000000000ULL);
    ASSERT_FALSE(expect.empty());
    EXPECT_EQ(sum(expect), 1000000000000ULL);
    const std::string& doge_cb = snap.first[0].coinbase_hex;
    for (const auto& [script, amount] : expect)
        EXPECT_NE(doge_cb.find(le64_hex(amount) + hex(Bytes{static_cast<unsigned char>(script.size())}) + hex(script)),
                  std::string::npos)
            << "DOGE output " << hex(script) << " x " << amount;

    // The work-change hook re-pushes stratum jobs for the new commitment.
    ioc.poll();
    EXPECT_GT(ws->get_work_generation(), 0u);

    // The DGB coinbase carries [0x2c][commitment] and nothing else changed.
    const std::string cb = coinbase_hex(*ws);
    EXPECT_NE(cb.find("2c" + hex(Bytes(commitment.begin(), commitment.end()))), std::string::npos);
    EXPECT_NE(cb, ssot_coinbase_hex());

    // A best-share change marks the payouts dirty again (and bumps the work).
    ASSERT_FALSE(mm.is_pplns_dirty());
    const auto gen = ws->get_work_generation();
    node.on_best();
    EXPECT_TRUE(mm.is_pplns_dirty());
    EXPECT_GT(ws->get_work_generation(), gen);
}

TEST(DgbDogeMergedPayout, WithoutProviderTheCommitmentStaysEmpty)
{
    // The pre-fix main_dgb state: manager with DOGE, no provider registered.
    WsFixture fx;
    auto ws = fx.make();
    bind_inputs(*ws);
    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    add_doge(mm);
    ws->set_merged_mining_manager(&mm);
    mm.mark_pplns_dirty();
    mm.refresh_aux_work();
    EXPECT_TRUE(mm.get_cached_header_infos_and_commitment().second.empty());
    EXPECT_EQ(coinbase_hex(*ws), ssot_coinbase_hex()) << "no fabe6d6d without a provider";
}

// ── No --merged: nothing bound, coinbase byte-identical ───────────────────

TEST(DgbDogeMergedPayout, StandaloneBindsNothingAndCoinbaseUnchanged)
{
    ShareChain sc;
    FakeNode node(sc.tracker, sc.best);
    WsFixture fx;
    auto ws = fx.make();
    bind_inputs(*ws);

    EXPECT_FALSE(dgb::coin::wire_doge_merged_payouts(nullptr, node, ws.get()));
    EXPECT_FALSE(static_cast<bool>(node.on_best)) << "no best-share hook without --merged";
    EXPECT_EQ(ws->get_work_generation(), 0u);
    EXPECT_FALSE(ws->has_merged_chain(kDoge));

    const std::string after = coinbase_hex(*ws);
    EXPECT_EQ(after, ssot_coinbase_hex());
    EXPECT_EQ(after.find("fabe6d6d"), std::string::npos);
}

// ── has_merged_chain() follows the manager; the stratum login path ────────

namespace {

struct Login {
    std::vector<core::merged_addr::ChainAddrInfo> table;
    std::vector<uint8_t> parent_versions;
    std::vector<std::string> hrps;
    std::function<bool(uint32_t)> configured;

    // The inputs stratum_server.cpp passes resolve_merged_login, from the DGB
    // work source's own StratumConfig, set up as main_dgb does (acceptance +
    // merged_parent_versions); `dgb_parent_versions=false` is the state
    // before main_dgb published DGB's versions.
    explicit Login(dgb::stratum::DGBWorkSource& ws, bool dgb_parent_versions = true)
    {
        const auto acc = dgb::address_acceptance(false, false);
        ws.set_payout_acceptance(acc.p2pkh_versions, acc.p2sh_versions, acc.bech32_hrps);
        if (dgb_parent_versions)
            ws.set_merged_parent_versions(dgb::merged_parent_versions());
        const auto& scfg = ws.get_stratum_config();
        table = core::merged_addr::merged_chain_table(false, scfg.merged_parent_versions);
        parent_versions = scfg.payout_p2pkh_versions;
        parent_versions.insert(parent_versions.end(), scfg.payout_p2sh_versions.begin(),
                               scfg.payout_p2sh_versions.end());
        hrps = scfg.payout_bech32_hrps;
        configured = [&ws](uint32_t id) { return ws.has_merged_chain(id); };
    }
    core::merged_addr::LoginResolution resolve(const std::string& primary, const std::string& merged,
                                               std::map<uint32_t, std::string> explicit_addrs = {}) const
    {
        return core::merged_addr::resolve_merged_login(primary, merged, std::move(explicit_addrs), table,
                                                       configured, parent_versions, hrps);
    }
    Bytes doge_script(const std::string& addr) const
    {
        return core::merged_addr::merged_payout_script(core::merged_addr::find_chain(table, kDoge), addr);
    }
};

// DGB mainnet addresses (P2PKH 30 "D...", bech32 "dgb") and DOGE addresses
// (functions, not globals: script_to_address is another TU's code).
std::string kDgbA() { return core::script_to_address(p2pkh(kHashA), "", 30, 63); }
std::string kDgbBech32C() { return core::script_to_address(p2wpkh(kHashC), "dgb", 30, 63); }
std::string kDogeY() { return core::script_to_address(p2pkh(h160(0x77)), "", 30, 22); }
std::string kDgbS()    // DGB P2SH "S..."
{
    Bytes s{0xa9, 0x14};
    const Bytes h = h160(0x99);
    s.insert(s.end(), h.begin(), h.end());
    s.push_back(0x87);
    return core::script_to_address(s, "", 30, 63);
}
std::string kDogeZ()   // DOGE P2SH "A..."
{
    Bytes s{0xa9, 0x14};
    const Bytes h = h160(0x66);
    s.insert(s.end(), h.begin(), h.end());
    s.push_back(0x87);
    return core::script_to_address(s, "", 30, 22);
}

} // namespace

TEST(DgbDogeMergedPayout, HasMergedChainFollowsTheManager)
{
    WsFixture fx;
    auto ws = fx.make();
    EXPECT_FALSE(ws->has_merged_chain(kDoge));

    boost::asio::io_context ioc;
    MergedMiningManager empty(ioc);
    ws->set_merged_mining_manager(&empty);
    EXPECT_FALSE(ws->has_merged_chain(kDoge)) << "manager without DOGE";

    MergedMiningManager mm(ioc);
    add_doge(mm);
    ws->set_merged_mining_manager(&mm);
    EXPECT_TRUE(ws->has_merged_chain(kDoge));
    EXPECT_FALSE(ws->has_merged_chain(1));      // NMC: not configured
    EXPECT_FALSE(ws->has_merged_chain(0x1AFE)); // DGB's own aux chain id
}

TEST(DgbDogeMergedPayout, LoginDgbCommaDogeReachesTheDogeChain)
{
    ASSERT_FALSE(kDgbA().empty());
    ASSERT_FALSE(kDogeZ().empty());
    WsFixture fx;
    auto ws = fx.make();
    Login off(*ws);
    EXPECT_EQ(off.resolve(kDgbA(), kDogeZ()).addresses.count(kDoge), 0u) << "merged off: DOGE not reached";

    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    add_doge(mm);
    ws->set_merged_mining_manager(&mm);
    Login on(*ws);
    for (const auto& doge : {kDogeZ(), kDogeY()}) {
        const auto r = on.resolve(kDgbA(), doge);
        EXPECT_EQ(r.primary, kDgbA());
        EXPECT_TRUE(r.usable_primary);
        ASSERT_EQ(r.addresses.count(kDoge), 1u) << doge;
        EXPECT_EQ(r.addresses.at(kDoge), doge);
    }
    EXPECT_EQ(on.doge_script(kDogeZ()).size(), 23u);   // a DOGE P2SH stays P2SH
}

TEST(DgbDogeMergedPayout, LoginWithoutDogeAddressAutoDerivesFromPrimaryKey)
{
    WsFixture fx;
    auto ws = fx.make();
    {
        Login off(*ws);
        EXPECT_TRUE(off.resolve(kDgbA(), "").addresses.empty()) << "merged off: nothing derived";
    }
    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    add_doge(mm);
    ws->set_merged_mining_manager(&mm);
    Login on(*ws);

    // DGB P2PKH primary: DOGE pays the same hash160 as P2PKH.
    auto r = on.resolve(kDgbA(), "");
    ASSERT_EQ(r.addresses.count(kDoge), 1u);
    EXPECT_EQ(on.doge_script(r.addresses.at(kDoge)), p2pkh(kHashA));

    // DGB bech32 P2WPKH primary (today's behaviour, pinned so a change is
    // deliberate): core::address_to_hash160 / address_to_script decode only
    // the tltc/ltc/bc/tb HRPs (core/address_utils.cpp), so the login gets no
    // derived DOGE address. Its DOGE payout is still its witness program as
    // a P2PKH, from the share chain (ProviderFollowsMergedExpectedPayouts,
    // miner C).
    ASSERT_FALSE(kDgbBech32C().empty());
    ASSERT_EQ(kDgbBech32C().rfind("dgb1", 0), 0u);
    r = on.resolve(kDgbBech32C(), "");
    EXPECT_EQ(r.addresses.count(kDoge), 0u);
}

TEST(DgbDogeMergedPayout, ExplicitSlashDogeAddressWinsOverDerived)
{
    WsFixture fx;
    auto ws = fx.make();
    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    add_doge(mm);
    ws->set_merged_mining_manager(&mm);
    Login on(*ws);

    // PRIMARY/98:DOGEADDR (and mining.set_merged_addresses) give explicit_addrs.
    const auto r = on.resolve(kDgbA(), "", {{kDoge, kDogeY()}});
    ASSERT_EQ(r.addresses.count(kDoge), 1u);
    EXPECT_EQ(r.addresses.at(kDoge), kDogeY());
    EXPECT_EQ(on.doge_script(r.addresses.at(kDoge)), p2pkh(h160(0x77)));
    EXPECT_NE(on.doge_script(r.addresses.at(kDoge)), p2pkh(kHashA)) << "not the derived key";
}

// ── merged_parent_versions: a DOGE login is identified by DOGE's own bytes ──

TEST(DgbDogeMergedPayout, MergedParentVersionsAreDgbsOnEveryNetwork)
{
    // mainnet P2PKH 30 "D", P2SH 63 "S"; testnet (and regtest) 126 / 140.
    EXPECT_EQ(dgb::merged_parent_versions(), (std::vector<uint8_t>{30, 63, 126, 140}));
    WsFixture fx;
    auto ws = fx.make();
    EXPECT_TRUE(ws->get_stratum_config().merged_parent_versions.empty());
    ws->set_merged_parent_versions(dgb::merged_parent_versions());
    EXPECT_EQ(ws->get_stratum_config().merged_parent_versions, dgb::merged_parent_versions());
}

TEST(DgbDogeMergedPayout, DogeLoginIdentifiedWithDogeVersionBytes)
{
    WsFixture fx;
    auto ws = fx.make();
    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    add_doge(mm);
    ws->set_merged_mining_manager(&mm);
    Login on(*ws);

    const auto* doge = core::merged_addr::find_chain(on.table, kDoge);
    ASSERT_NE(doge, nullptr);
    // DOGE is identified by its own bytes minus every DGB one: P2SH 22,
    // testnet P2PKH 113 / P2SH 196 — never 30, DGB's P2PKH.
    EXPECT_EQ(doge->versions, (std::vector<uint8_t>{22, 113, 196}));
    for (auto v : dgb::merged_parent_versions())
        EXPECT_EQ(std::count(doge->versions.begin(), doge->versions.end(), v), 0) << int(v);
    // The scripts it pays still use DOGE's mainnet versions.
    EXPECT_EQ(doge->p2pkh, (std::vector<uint8_t>{30}));
    EXPECT_EQ(doge->p2sh, (std::vector<uint8_t>{22}));

    EXPECT_TRUE(core::is_address_for_chain(kDogeZ(), doge->hrps, doge->versions));   // DOGE "A..."
    EXPECT_FALSE(core::is_address_for_chain(kDgbA(), doge->hrps, doge->versions));   // DGB "D..."
    EXPECT_FALSE(core::is_address_for_chain(kDgbS(), doge->hrps, doge->versions));   // DGB "S..."

    // DGB,DOGE(A...): the DOGE address goes to DOGE, the primary stays.
    auto r = on.resolve(kDgbA(), kDogeZ());
    EXPECT_EQ(r.primary, kDgbA());
    ASSERT_EQ(r.addresses.count(kDoge), 1u);
    EXPECT_EQ(r.addresses.at(kDoge), kDogeZ());
    EXPECT_EQ(on.doge_script(kDogeZ()).size(), 23u);

    // DGB,DOGE(D...): a "D..." is DGB's as much as DOGE's; with one merged
    // chain the second address still goes to DOGE (the single-chain rule),
    // paying that key as a DOGE P2PKH.
    r = on.resolve(kDgbA(), kDogeY());
    EXPECT_EQ(r.primary, kDgbA());
    ASSERT_EQ(r.addresses.count(kDoge), 1u);
    EXPECT_EQ(r.addresses.at(kDoge), kDogeY());
    EXPECT_EQ(on.doge_script(kDogeY()), p2pkh(h160(0x77)));
}

TEST(DgbDogeMergedPayout, DgbP2pkhPrimaryIsNeverTakenForDoge)
{
    // DGB "D...",DGB "S...": both DGB's. Without DGB's versions the "D..."
    // primary counted as a DOGE address, the pair read as swapped and the
    // DGB payout moved to the second address. With them it stays the first.
    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    add_doge(mm);

    WsFixture before_fx;
    auto before_ws = before_fx.make();
    before_ws->set_merged_mining_manager(&mm);
    Login before(*before_ws, /*dgb_parent_versions=*/false);
    EXPECT_EQ(before.resolve(kDgbA(), kDgbS()).primary, kDgbS()) << "the misread the rule removes";

    WsFixture fx;
    auto ws = fx.make();
    ws->set_merged_mining_manager(&mm);
    Login on(*ws);
    const auto r = on.resolve(kDgbA(), kDgbS());
    EXPECT_EQ(r.primary, kDgbA());
    EXPECT_TRUE(r.usable_primary);
}

// ── R3: the provider takes the tracker guard first and reads the best share
//    from the cell, never NodeImpl::best_share_hash off the IO thread ──────

namespace {

struct GuardNode {
    dgb::ShareTracker& tracker;
    uint256 best;
    std::shared_mutex mtx;
    bool held = false;
    int best_calls = 0;
    struct Guard {
        std::shared_lock<std::shared_mutex> lk;
        GuardNode* n;
        Guard(std::shared_lock<std::shared_mutex> l, GuardNode* node) : lk(std::move(l)), n(node)
        {
            if (lk.owns_lock())
                n->held = true;
        }
        Guard(Guard&& o) noexcept : lk(std::move(o.lk)), n(o.n) { o.n = nullptr; }
        ~Guard()
        {
            if (n && lk.owns_lock())
                n->held = false;
        }
        explicit operator bool() const { return lk.owns_lock(); }
        dgb::ShareTracker& operator*() { return n->tracker; }
    };
    GuardNode(dgb::ShareTracker& t, const uint256& b) : tracker(t), best(b) {}
    Guard read_tracker() { return Guard(std::shared_lock<std::shared_mutex>(mtx, std::try_to_lock), this); }
    uint256 best_share_hash()
    {
        ++best_calls;
        return best;
    }
};

// Holds the tracker exclusively on another thread (the compute thread).
struct HeldTracker {
    std::promise<void> locked, release;
    std::thread t;
    explicit HeldTracker(std::shared_mutex& m)
    {
        auto rel = release.get_future().share();
        t = std::thread([&m, this, rel] {
            std::unique_lock<std::shared_mutex> lk(m);
            locked.set_value();
            rel.wait();
        });
        locked.get_future().wait();
    }
    void done()
    {
        release.set_value();
        t.join();
    }
};

} // namespace

TEST(DgbDogeMergedPayout, ProviderTakesTheGuardFirstAndReadsBestFromTheCell)
{
    ShareChain sc;
    GuardNode node(sc.tracker, sc.best);
    int fn_calls = 0;
    bool fn_under_guard = false;
    int busy = 0;
    auto provider = dgb::coin::make_doge_payout_provider(
        &node, std::make_shared<const dgb::coin::DogeP2shSplit>(),
        [&]() {
            ++fn_calls;
            fn_under_guard = node.held;
            return sc.best;
        },
        [&]() { ++busy; });
    EXPECT_FALSE(provider(kDoge, 1000).empty());
    EXPECT_EQ(fn_calls, 1);
    EXPECT_TRUE(fn_under_guard) << "the best share was read without the tracker guard";
    EXPECT_EQ(node.best_calls, 0) << "NodeImpl::best_share_hash was called from the provider";

    HeldTracker held(node.mtx);
    EXPECT_TRUE(provider(kDoge, 1000).empty());
    EXPECT_EQ(busy, 1) << "a busy tracker is not reported";
    EXPECT_EQ(fn_calls, 1) << "the best share was read while the tracker was busy";
    held.done();
}

TEST(DgbDogeMergedPayout, ProviderSplitsAtTheGivenBestNotTheTip)
{
    ShareChain sc;
    const uint256 older(std::vector<unsigned char>(32, 0xd2));   // the tip's parent
    ASSERT_TRUE(sc.tracker.chain.contains(older));
    GuardNode node(sc.tracker, sc.best);
    auto provider = dgb::coin::make_doge_payout_provider(
        &node, std::make_shared<const dgb::coin::DogeP2shSplit>(), [older]() { return older; });
    const uint64_t value = 3'000'000'000ULL;
    const Payouts got = provider(kDoge, value);
    auto oracle_at = [&](const uint256& b) {
        Payouts o;
        for (auto& [scr, v] : sc.tracker.get_merged_expected_payouts(b, chain::bits_to_target(0x1e0ffff0), value,
                                                                     kDoge, combined_donation(), {}, {}))
            if (v >= 1)
                o.emplace_back(scr, v);
        return o;
    };
    EXPECT_EQ(got, oracle_at(older));
    EXPECT_NE(got, oracle_at(sc.best)) << "the provider split at the tip, not at the best share it was given";
}

TEST(DgbDogeMergedPayout, BusyTrackerReMarksThePayoutsDirty)
{
    ShareChain sc;
    FakeNode node(sc.tracker, sc.best);
    WsFixture fx;
    auto ws = fx.make();
    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    add_doge(mm);
    ASSERT_TRUE(dgb::coin::wire_doge_merged_payouts(&mm, node, ws.get(), nullptr,
                                                    [&sc]() { return sc.best; }));
    std::promise<void> locked, release;
    auto rel = release.get_future().share();
    std::thread holder([&] {
        std::unique_lock<std::shared_mutex> lk(node.mtx);
        locked.set_value();
        rel.wait();
    });
    locked.get_future().wait();
    mm.refresh_aux_work();   // the rebuild's provider finds the tracker busy
    EXPECT_TRUE(mm.is_pplns_dirty()) << "a busy tracker left the old split for the next poll";
    release.set_value();
    holder.join();
    mm.refresh_aux_work();
    EXPECT_FALSE(mm.is_pplns_dirty());
    EXPECT_EQ(mm.get_cached_header_infos_and_commitment().second.size(), 44u);
}

// Review 713dc77a0 R3: core gives DOGE the primary's hash160 when the login
// names no DOGE address, and types a DGB "S..." (version 63) as P2PKH, so an
// S... login's DOGE script was P2PKH(redeem-script hash): unspendable, and as
// the share's merged address it also hid the operator's P2SH split. The DGB
// job drops exactly that entry; a DOGE address the miner gave is kept, and a
// "D..." login's auto-derived DOGE key is kept.
TEST(DgbDogeMergedPayout, P2shLoginGetsNoAutoDerivedDogeAndTakesTheSplit)
{
    WsFixture fx;
    auto ws = fx.make();
    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    add_doge(mm);
    ws->set_merged_mining_manager(&mm);
    Login on(*ws);
    const auto own = dgb::address_acceptance(false, false);

    // What core resolves for a bare S... login, and the job's scripts.
    const auto r = on.resolve(kDgbS(), "");
    ASSERT_EQ(r.addresses.count(kDoge), 1u) << "core no longer auto-derives DOGE (re-check this KAT)";
    Bytes payout = core::accepted_payout_script(kDgbS(), own);
    ASSERT_EQ(payout.size(), 23u);
    std::vector<std::pair<uint32_t, Bytes>> merged{{kDoge, on.doge_script(r.addresses.at(kDoge))}};
    Bytes unspendable{0x76, 0xa9, 0x14};
    unspendable.insert(unspendable.end(), payout.begin() + 2, payout.begin() + 22);
    unspendable.push_back(0x88);
    unspendable.push_back(0xac);
    ASSERT_EQ(merged[0].second, unspendable) << "the auto-derived DOGE script is the P2PKH of the redeem hash";
    ws->decide_job_payout(payout, merged);
    EXPECT_TRUE(merged.empty()) << "an S... login's DOGE was paid to P2PKH(redeem hash): burned";
    EXPECT_EQ(payout.size(), 23u) << "the DGB payout is unchanged";

    // A DOGE address the miner gave is kept (P2PKH, and P2SH of any script).
    for (const auto& doge : {kDogeY(), kDogeZ()}) {
        SCOPED_TRACE(doge);
        const auto rg = on.resolve(kDgbS(), doge);
        ASSERT_EQ(rg.addresses.at(kDoge), doge);
        Bytes p = core::accepted_payout_script(kDgbS(), own);
        std::vector<std::pair<uint32_t, Bytes>> m{{kDoge, on.doge_script(doge)}};
        const auto before = m;
        ws->decide_job_payout(p, m);
        EXPECT_EQ(m, before);
    }
    // A P2PKH login's auto-derived DOGE key is spendable: kept.
    {
        const auto ra = on.resolve(kDgbA(), "");
        ASSERT_EQ(ra.addresses.count(kDoge), 1u);
        Bytes p = core::accepted_payout_script(kDgbA(), own);
        std::vector<std::pair<uint32_t, Bytes>> m{{kDoge, on.doge_script(ra.addresses.at(kDoge))}};
        const auto before = m;
        ws->decide_job_payout(p, m);
        EXPECT_EQ(m, before);
    }
    // The job's coinbase is built without a DOGE entry, so the S... share
    // carries none and the provider applies the P2SH split to it
    // (DgbDogeP2shSplit.P2shKeyIsSplitOwnerDonationOthersUnchanged).
}

// Review 713dc77a0 NIT 15: while the tracker is busy the DOGE provider declines
// and re-marks the payouts dirty, and every session's job build retried the
// rebuild inline. The inline rebuild runs at most once a second; the manager's
// poll rebuilds a dirty cache too.
TEST(DgbDogeMergedPayout, BusyPayoutsAreRebuiltInlineAtMostOnceASecond)
{
    WsFixture fx;
    auto ws = fx.make();
    bind_inputs(*ws);
    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    add_doge(mm);
    ws->set_merged_mining_manager(&mm);
    mm.refresh_aux_work();   // DOGE work in hand
    int calls = 0;
    mm.set_payout_provider([&](uint32_t, uint64_t) -> std::vector<std::pair<Bytes, uint64_t>> {
        ++calls;
        mm.mark_pplns_dirty();   // the tracker was busy: declined, dirty again
        return {};
    });
    mm.mark_pplns_dirty();
    for (int i = 0; i < 20; ++i)
        (void)coinbase_hex(*ws);
    EXPECT_EQ(calls, 1) << "every job build retried the busy rebuild (or none rebuilt)";
    EXPECT_TRUE(mm.is_pplns_dirty());
}
