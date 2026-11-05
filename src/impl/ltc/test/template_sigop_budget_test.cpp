// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The block sigop budget of the embedded LTC and DOGE templates (#2137;
// rides share_test). A block's total sigop cost must stay within the
// chain's limit (litecoind / dogecoind ConnectBlock: bad-blk-sigops):
// Litecoin Core 0.21.4 MAX_BLOCK_SIGOPS_COST 80,000 with
// GetTransactionSigOpCost (legacy x4 + P2SH x4 + witness); Dogecoin Core
// 1.14.9 20,000 sigops, legacy and P2SH (no segwit).
//   - the counting mirrors Core's: CScript::GetSigOpCount (accurate and
//     not), the P2SH redeem-script count, CountWitnessSigOps / WitnessSigOps,
//     GetTransactionSigOpCost -- and reproduces the "sigops" litecoind put
//     on every entry of its REAL 3200605 template;
//   - the selection keeps the block's cost within the limit with the
//     coinbase reserved: a tx that fits exactly is taken, one 1 over is
//     left out and counted;
//   - TemplateBuilder reserves the coinbase's cost; c2pool's own HogEx has
//     none;
//   - a DOGE pool has its own rules and limit.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/coin/sigop_cost.hpp>
#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <btclibs/util/strencodings.h>

#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/mweb_builder.hpp>
#include <impl/ltc/coin/template_builder.hpp>

#include "ltc_mweb_tx_fixtures.hpp"

namespace {

using namespace ltc::coin;
namespace sg = core::coin::sigops;
namespace tf = ltc_mweb_tx_fixture;
using Script = std::vector<unsigned char>;
using Witness = std::vector<std::vector<unsigned char>>;

sg::Bytes b(const Script& s)
{
    return sg::Bytes(s.data(), s.size());
}

Script rep(unsigned char op, size_t n)
{
    return Script(n, op);
}

Script cat(std::initializer_list<Script> parts)
{
    Script out;
    for (const auto& p : parts)
        out.insert(out.end(), p.begin(), p.end());
    return out;
}

Script push(const Script& data)
{
    Script out;
    if (data.size() < 0x4c) {
        out.push_back(static_cast<unsigned char>(data.size()));
    } else {
        out.push_back(0x4c);
        out.push_back(static_cast<unsigned char>(data.size()));
    }
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

const Script kPubkey = cat({{0x02}, rep(0x11, 32)});
const Script kSig = rep(0x30, 71);

Script p2pkh() { return cat({{0x76, 0xa9, 0x14}, rep(0x22, 20), {0x88, 0xac}}); }
Script p2sh() { return cat({{0xa9, 0x14}, rep(0x33, 20), {0x87}}); }
Script p2wpkh() { return cat({{0x00, 0x14}, rep(0x44, 20)}); }
Script p2wsh() { return cat({{0x00, 0x20}, rep(0x55, 32)}); }
Script p2tr() { return cat({{0x51, 0x20}, rep(0x66, 32)}); }
Script hogaddr() { return cat({{0x58, 0x20}, rep(0x77, 32)}); }
// m-of-n multisig: OP_m <n keys> OP_n OP_CHECKMULTISIG.
Script multisig(int m, int n)
{
    Script s{static_cast<unsigned char>(0x50 + m)};
    for (int i = 0; i < n; ++i) {
        const Script k = push(kPubkey);
        s.insert(s.end(), k.begin(), k.end());
    }
    s.push_back(static_cast<unsigned char>(0x50 + n));
    s.push_back(0xae);
    return s;
}

MutableTransaction tx_from_hex(const std::string& hex)
{
    auto bytes = ParseHex(hex);
    PackStream ps(bytes);
    MutableTransaction tx;
    ps >> TX_WITH_WITNESS(tx);
    return tx;
}

uint256 fund(uint16_t n)
{
    uint256 v;
    v.SetNull();
    v.data()[0] = 0xf1;
    v.data()[1] = static_cast<unsigned char>(n & 0xff);
    v.data()[2] = static_cast<unsigned char>(n >> 8);
    return v;
}

// One input (scriptSig, witness), one output (spk).
MutableTransaction tx1(const uint256& prev, const Script& script_sig, const Witness& witness,
                       const Script& out_spk, int64_t value = 90'000)
{
    MutableTransaction tx;
    tx.version = 2;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash = prev;
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    in.scriptSig.m_data = script_sig;
    in.scriptWitness.stack = witness;
    tx.vin.push_back(in);
    TxOut out;
    out.value = value;
    out.scriptPubKey.m_data = out_spk;
    tx.vout.push_back(out);
    return tx;
}

std::optional<int64_t> cost_of(const MutableTransaction& tx, const sg::SigopRules& r,
                               const std::vector<Script>& prevout_spks)
{
    return tx_sigop_cost(tx, r, [&](size_t i) -> const Script* {
        return i < prevout_spks.size() ? &prevout_spks[i] : nullptr;
    });
}

// The prevout an input of litecoind's template spends, by its shape: no
// witness -> P2PKH (<sig> <pubkey>); an empty scriptSig and a 2-item
// witness ending in a 33-byte key -> P2WPKH; a scriptSig pushing a v0
// keyhash program and that witness -> P2SH-P2WPKH.
std::optional<Script> prevout_by_shape(const TxIn& in)
{
    const auto& ss = in.scriptSig.m_data;
    const auto& w = in.scriptWitness.stack;
    if (w.empty() && !ss.empty())
        return p2pkh();
    if (w.size() == 2 && w[1].size() == 33 && ss.empty())
        return p2wpkh();
    if (w.size() == 2 && w[1].size() == 33 && ss.size() == 23 && ss[0] == 0x16 && ss[1] == 0x00 && ss[2] == 0x14)
        return p2sh();
    return std::nullopt;
}

} // namespace

// GetTransactionSigOpCost over litecoind's own template at 3200605: every
// entry's cost equals the "sigops" litecoind computed (its mempool's
// GetTransactionSigOpCost with the standard flags: P2SH and witness), the
// prevouts taken from the inputs' shapes; the HogEx, spending a HogAddr,
// costs 0.
TEST(LtcSigopBudget, CountsAsLitecoindOnItsOwnTemplate)
{
    const auto g = nlohmann::json::parse(tf::kGbt3200605Json);
    const auto& entries = g["transactions"];
    ASSERT_EQ(entries.size(), 14u);
    int64_t total = 0;
    for (size_t i = 0; i < entries.size(); ++i) {
        const MutableTransaction tx = tx_from_hex(entries[i]["data"].get<std::string>());
        std::vector<Script> prev;
        for (const auto& in : tx.vin) {
            if (tx.m_hogEx) {
                prev.push_back(hogaddr());
                continue;
            }
            auto s = prevout_by_shape(in);
            ASSERT_TRUE(s) << "entry " << i << ": an input of an unexpected shape";
            prev.push_back(*s);
        }
        const auto c = cost_of(tx, sg::LTC_SIGOP_RULES, prev);
        ASSERT_TRUE(c);
        EXPECT_EQ(*c, entries[i]["sigops"].get<int64_t>()) << "entry " << i << " " << entries[i]["txid"];
        total += *c;
    }
    EXPECT_EQ(total, 36) << "1+0+5+5+4+0+8+1+1+1+1+1+8, the HogEx 0";
}

// The script counts, case by case, as Core's functions give them.
TEST(LtcSigopBudget, ScriptCountsMirrorCore)
{
    // CScript::GetSigOpCount(bool fAccurate).
    EXPECT_EQ(sg::script_sigops(b(p2pkh()), false), 1u);
    EXPECT_EQ(sg::script_sigops(b(multisig(2, 3)), false), 20u) << "inaccurate: MAX_PUBKEYS_PER_MULTISIG";
    EXPECT_EQ(sg::script_sigops(b(multisig(2, 3)), true), 3u) << "accurate: DecodeOP_N(OP_3)";
    EXPECT_EQ(sg::script_sigops(b(Script{0xad, 0xac, 0xaf}), true), 22u) << "CHECKSIGVERIFY, CHECKSIG, a bare CHECKMULTISIGVERIFY";
    EXPECT_EQ(sg::script_sigops(b(Script{0xac, 0x4c, 0xff, 0xac}), false), 1u) << "a truncated push ends the count";
    EXPECT_EQ(sg::script_sigops(b(cat({push(rep(0xac, 80)), {0xac}})), false), 1u) << "pushed bytes are data";
    EXPECT_EQ(sg::script_sigops(b(p2wpkh()), false), 0u);
    EXPECT_EQ(sg::script_sigops(b(hogaddr()), false), 0u);

    // CScript::GetSigOpCount(const CScript& scriptSig): a P2SH prevout counts
    // the redeem script (accurately); a non-push scriptSig counts 0.
    const Script redeem = multisig(2, 3);
    const Script ss = cat({{0x00}, push(kSig), push(kSig), push(redeem)});
    EXPECT_EQ(sg::p2sh_sigops(b(p2sh()), b(ss)), 3u);
    EXPECT_EQ(sg::p2sh_sigops(b(p2sh()), b(cat({{0x76}, push(redeem)}))), 0u);
    EXPECT_EQ(sg::p2sh_sigops(b(p2pkh()), b(ss)), 1u) << "not P2SH: the prevout's own accurate count";

    // CountWitnessSigOps / WitnessSigOps.
    const Witness wpkh{kSig, kPubkey};
    EXPECT_EQ(sg::witness_sigops(b(Script{}), b(p2wpkh()), wpkh), 1u) << "v0 keyhash";
    EXPECT_EQ(sg::witness_sigops(b(Script{}), b(p2wsh()), Witness{{}, kSig, kSig, multisig(2, 2)}), 2u)
        << "v0 scripthash: the witness script, accurately";
    EXPECT_EQ(sg::witness_sigops(b(Script{}), b(p2wsh()), Witness{}), 0u) << "no witness script";
    EXPECT_EQ(sg::witness_sigops(b(push(p2wpkh())), b(p2sh()), wpkh), 1u) << "P2SH-P2WPKH";
    EXPECT_EQ(sg::witness_sigops(b(push(p2wsh())), b(p2sh()), Witness{kSig, multisig(1, 1)}), 1u) << "P2SH-P2WSH";
    EXPECT_EQ(sg::witness_sigops(b(Script{}), b(p2tr()), Witness{kSig}), 0u) << "v1: no sigop counted";
    EXPECT_EQ(sg::witness_sigops(b(Script{}), b(hogaddr()), Witness{}), 0u) << "v8 (HogAddr)";

    // GetTransactionSigOpCost: legacy x4 + P2SH x4 + witness.
    const auto spend_p2sh = tx1(fund(1), ss, {}, p2pkh());
    EXPECT_EQ(cost_of(spend_p2sh, sg::LTC_SIGOP_RULES, {p2sh()}), std::optional<int64_t>(1 * 4 + 3 * 4))
        << "the P2PKH output (legacy 1) and the 2-of-3 redeem script (P2SH 3)";
    const auto spend_wsh = tx1(fund(2), {}, Witness{{}, kSig, kSig, multisig(2, 3)}, p2wpkh());
    EXPECT_EQ(cost_of(spend_wsh, sg::LTC_SIGOP_RULES, {p2wsh()}), std::optional<int64_t>(3));
    EXPECT_FALSE(cost_of(spend_wsh, sg::LTC_SIGOP_RULES, {})) << "a prevout not known: no cost";
    // A coinbase: legacy only.
    MutableTransaction cb = tx1(uint256(), cat({push(Script{0x5d, 0xd6, 0x30}), push(rep(0x01, 8))}), {}, p2pkh());
    cb.vin[0].prevout.index = 0xffffffff;
    cb.vout.push_back(cb.vout[0]);
    EXPECT_EQ(cost_of(cb, sg::LTC_SIGOP_RULES, {}), std::optional<int64_t>(2 * 4));

    // c2pool's own HogEx (the empty body; TemplateBuilder reserves nothing
    // for it): no legacy, P2SH or witness sigop.
    MWEBState st;
    st.prev_hogex_txid = fund(9);
    st.hogaddr_value = 1'000'000;
    st.valid = true;
    const MutableTransaction hog = MWEBBuilder::build_hogex(st, 100);
    EXPECT_EQ(cost_of(hog, sg::LTC_SIGOP_RULES, {hogaddr()}), std::optional<int64_t>(0));

    // The legacy count of a serialized coinbase (MiningInterface's reserve).
    auto cb_hex = HexStr(pack(TX_NO_WITNESS(cb)).get_span());
    EXPECT_EQ(sg::tx_hex_legacy_sigops(cb_hex), std::optional<unsigned>(2u));
    EXPECT_FALSE(sg::tx_hex_legacy_sigops(cb_hex.substr(0, cb_hex.size() - 10)));
}

namespace {

// A pool over an in-memory view whose coins (OP_TRUE) fund `n` txs, each
// paying one output of `checksigs` OP_CHECKSIG (legacy `checksigs`), with
// fee 1,000 + i (so the selection order is fixed).
struct SigopPool {
    core::coin::UTXOViewCache view{nullptr};
    Mempool pool;
    std::vector<MutableTransaction> txs;
    explicit SigopPool(core::coin::ChainLimits limits = core::coin::LTC_LIMITS) : pool(limits) {}
    void fill(size_t n, size_t checksigs, uint16_t base = 0)
    {
        pool.set_utxo(&view);
        for (size_t i = 0; i < n; ++i) {
            const uint256 f = fund(static_cast<uint16_t>(base + i));
            core::coin::Coin c;
            c.value = 1'000'000;
            c.scriptPubKey.m_data = {0x51};
            c.height = 1;
            view.add_coin(core::coin::Outpoint(f, 0), c);
            auto tx = tx1(f, Script{0x51}, {}, rep(0xac, checksigs), 1'000'000 - 1'000 - static_cast<int64_t>(i));
            EXPECT_FALSE(pool.admit(tx, &view)) << i;
            txs.push_back(tx);
        }
    }
};

} // namespace

// The boundary: a tx whose cost fits the remaining budget exactly is taken
// (the block's cost is the limit), one 1 over is left out and counted --
// and a cheaper tx after it still is taken.
TEST(LtcSigopBudget, SelectionStopsExactlyAtTheLimit)
{
    SigopPool p;
    p.fill(1, 100);  // cost 400 at admission
    auto zero = tx1(fund(500), Script{0x51}, {}, Script{0x51}, 1'000);
    {
        core::coin::Coin c;
        c.value = 1'000'000;
        c.scriptPubKey.m_data = {0x51};
        c.height = 1;
        p.view.add_coin(core::coin::Outpoint(fund(500), 0), c);
    }
    ASSERT_FALSE(p.pool.admit(zero, &p.view));
    ASSERT_EQ(p.pool.get_entry(compute_txid(p.txs[0]))->sigop_cost, 400) << "priced at admission";
    ASSERT_EQ(p.pool.get_entry(compute_txid(zero))->sigop_cost, 0);

    Mempool::SelectionSeed fits;
    fits.sigop_cost = 80'000 - 400;
    auto [sel, fees] = p.pool.get_sorted_txs_with_fees(4'000'000, &fits);
    EXPECT_EQ(sel.size(), 2u);
    auto j = p.pool.reject_stats_json();
    EXPECT_EQ(j["template_sigop_cost"], 80'000) << "exactly the limit";
    EXPECT_EQ(j["template_sigop_skipped"], 0);
    EXPECT_EQ(j["sigop_limit"], 80'000);

    Mempool::SelectionSeed over;
    over.sigop_cost = 80'000 - 399;
    auto [sel2, fees2] = p.pool.get_sorted_txs_with_fees(4'000'000, &over);
    ASSERT_EQ(sel2.size(), 1u) << "the 400-cost tx is 1 over";
    EXPECT_EQ(compute_txid(sel2[0].tx), compute_txid(zero));
    j = p.pool.reject_stats_json();
    EXPECT_EQ(j["template_sigop_cost"], 80'000 - 399);
    EXPECT_EQ(j["template_sigop_skipped"], 1);
}

// TemplateBuilder keeps the block's cost within 80,000 with the coinbase's
// cost reserved: 250 txs of cost 400 (100,000 in all) give 200 with nothing
// reserved, 190 with 4,000 (1,000 legacy sigops) reserved; the coinbase's
// count EmbeddedCoinNode takes from MiningInterface, at Litecoin's scale,
// or the default without one.
TEST(LtcSigopBudget, TheTemplateReservesTheCoinbase)
{
    BlockHeaderType genesis;
    genesis.m_version = 1;
    genesis.m_previous_block.SetNull();
    genesis.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    genesis.m_timestamp = 1486949366;
    genesis.m_bits = 0x1e0ffff0;
    genesis.m_nonce = 293345;
    HeaderChain chain(make_ltc_chain_params_testnet());
    ASSERT_TRUE(chain.init());
    ASSERT_TRUE(chain.add_header(genesis));

    SigopPool p;
    p.fill(250, 100);
    {
        BlockType blk;
        static_cast<BlockHeaderType&>(blk) = genesis;
        p.pool.remove_for_block(blk);
    }
    auto count = [&](int64_t reserve) {
        std::optional<rpc::WorkData> refused;
        auto wd = TemplateBuilder::build_template(chain, p.pool, true, nullptr,
                                                  TemplateBuilder::MAX_BLOCK_WEIGHT - TemplateBuilder::COINBASE_RESERVE,
                                                  &refused, true, reserve);
        EXPECT_TRUE(wd);
        return wd ? wd->m_data["transactions"].size() : 0;
    };
    EXPECT_EQ(count(0), 200u);
    EXPECT_EQ(count(4'000), 190u);
    EXPECT_EQ(count(4'001), 189u) << "one sigop cost over: one tx fewer";
    EXPECT_EQ(p.pool.reject_stats_json()["template_sigop_cost"], 4'001 + 189 * 400);

    EmbeddedCoinNode node(chain, p.pool, true);
    EXPECT_EQ(node.coinbase_sigop_cost(), TemplateBuilder::COINBASE_SIGOP_RESERVE) << "not told: the default";
    node.set_coinbase_sigop_reserve_fn([] { return 1'000u; });
    EXPECT_EQ(node.coinbase_sigop_cost(), 4'000) << "1,000 legacy sigops x 4";
}

// A DOGE pool keeps Dogecoin's rules: no witness counted, P2SH at scale 1,
// at most 20,000 sigops -- never Litecoin's.
TEST(LtcSigopBudget, DogeHasItsOwnRulesAndLimit)
{
    EXPECT_EQ(Mempool(core::coin::DOGE_LIMITS).sigop_rules(), sg::DOGE_SIGOP_RULES);
    EXPECT_EQ(Mempool(core::coin::LTC_LIMITS).sigop_rules(), sg::LTC_SIGOP_RULES);
    EXPECT_EQ(Mempool().sigop_rules(), sg::LTC_SIGOP_RULES);
    EXPECT_EQ(sg::DOGE_SIGOP_RULES.max_block_cost, 20'000);
    EXPECT_FALSE(sg::DOGE_SIGOP_RULES.witness);

    const Script ss = cat({{0x00}, push(kSig), push(kSig), push(multisig(2, 3))});
    const auto spend_p2sh = tx1(fund(1), ss, {}, p2pkh());
    EXPECT_EQ(cost_of(spend_p2sh, sg::DOGE_SIGOP_RULES, {p2sh()}), std::optional<int64_t>(1 + 3));
    EXPECT_EQ(cost_of(spend_p2sh, sg::LTC_SIGOP_RULES, {p2sh()}), std::optional<int64_t>(4 + 12));
    const auto spend_wsh = tx1(fund(2), {}, Witness{{}, kSig, kSig, multisig(2, 3)}, p2wpkh());
    EXPECT_EQ(cost_of(spend_wsh, sg::DOGE_SIGOP_RULES, {p2wsh()}), std::optional<int64_t>(0)) << "no segwit";
    EXPECT_EQ(cost_of(spend_wsh, sg::LTC_SIGOP_RULES, {p2wsh()}), std::optional<int64_t>(3));

    // 250 txs of 100 sigops: within 20,000 with 1,000 reserved, 190 of them.
    SigopPool d(core::coin::DOGE_LIMITS);
    d.fill(250, 100);
    ASSERT_EQ(d.pool.get_entry(compute_txid(d.txs[0]))->sigop_cost, 100) << "scale 1";
    Mempool::SelectionSeed seed;
    seed.sigop_cost = 1'000;
    auto [sel, fees] = d.pool.get_sorted_txs_with_fees(4'000'000, &seed);
    EXPECT_EQ(sel.size(), 190u);
    EXPECT_EQ(d.pool.reject_stats_json()["template_sigop_cost"], 20'000);
    EXPECT_EQ(d.pool.reject_stats_json()["sigop_limit"], 20'000);
}
