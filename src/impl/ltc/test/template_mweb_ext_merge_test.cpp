// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The hybrid MWEB extension merged into the embedded LTC template (#2137 S3;
// rides share_test). REAL TemplateBuilder, Mempool, HeaderChain (the real
// tip 3200604 on a checkpoint), MWEBTracker (fed the tip's real HogEx and
// mw::Block) and UTXOViewCache/UTXOViewDB (best block moved with flush()):
//   - none mode: the templates are byte-for-byte the ones the S0+S1 head
//     6edb9326b built from the same fixture (full, budget-truncated, the
//     empty template on the tip, the refused template without MWEB state),
//     with and without a source in mode none;
//   - litecoind's extension on the tip -- a peg-in (3200601's pegin output)
//     whose parent P is also in the pool, a 2-input HogEx with a peg-out,
//     3200601's 2-kernel body -- merges as coinbase | P | peg-in | the
//     pool's selection | litecoind's HogEx: a pool tx spending what the
//     peg-in spends is refused, a pool tx with a pegin output stays barred,
//     P is not repeated, P's child in the pool follows it; the template
//     passes check_template_txs, coinbasevalue = subsidy + every listed fee,
//     mweb = litecoind's; the source counts what it imported;
//   - every fallback is the empty-body template with c2pool's own HogEx,
//     byte-for-byte the one built without the source, and is counted;
//   - a degraded template (the view behind the tip, the pool not cleaned for
//     it) never imports, nor one without the tip's MWEB state;
//   - a merged template failing check_template_txs falls back;
//   - the selection budget leaves room for the imported txs;
//   - the coinbase is exactly what litecoind's ConnectBlock allows (its
//     nFees recomputed over the template's bytes and the view);
//   - the selection reserves litecoind's HogEx inputs too: a pool tx
//     spending the tip's HogAddr never rides along;
//   - every imported fee is recomputed from the view: any listed fee off it
//     falls back; a parent missing from "depends" ships first.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/coin/mweb_shape.hpp>
#include <core/coin/template_gate.hpp>
#include <core/coin/template_txs_check.hpp>

#include "template_mweb_ext_fixture.hpp"
#include "template_mweb_ext_none_golden.hpp"

#include <impl/ltc/coin/mweb_ext_import.hpp>

namespace {

using namespace ltc::coin;
using namespace ltc_mweb_ext_test;
namespace mx = ltc::coin::mweb_ext;

constexpr int64_t kSubsidy = 625000000;
constexpr uint32_t kBudget = TemplateBuilder::MAX_BLOCK_WEIGHT - TemplateBuilder::COINBASE_RESERVE;

std::string txid_hex(const std::string& data)
{
    auto t = core::coin::walk_tx_hex(data);
    return t ? t->txid.GetHex() : std::string();
}

std::string wtxid_hex(const std::string& data)
{
    auto t = core::coin::walk_tx_hex(data);
    if (!t)
        return "";
    if (t->witness_size == 0)
        return t->txid.GetHex();
    auto b = bytes_of(data);
    return Hash(std::span<const unsigned char>(b.data(), b.size())).GetHex();
}

void commit(MutableTransaction& hogex, const MWEBHeader& hdr)
{
    const uint256 h = blake3_hash_serialized(hdr);
    auto& spk = hogex.vout[0].scriptPubKey.m_data;
    spk.assign(34, 0);
    spk[0] = 0x58;
    spk[1] = 0x20;
    std::memcpy(spk.data() + 2, h.data(), 32);
}

// litecoind's template on the tip 3200604 with a peg-in: P (a canonical
// parent, also in our pool) funds the peg-in; Q is unrelated. The body is
// 3200601's (a peg-in of 570771880 at fee 2100, a 30000000 peg-out at fee
// 2540), under a header for 3200605 that extends the tip's txo count by its
// two outputs; the HogEx spends the tip's HogEx and the pegin output, pays
// the HogAddr the value equation gives and the peg-out.
struct LitecoindG {
    MutableTransaction p, pegin, hogex;
    MWEBHeader header;
    std::vector<unsigned char> body;
    int64_t p_fee = 10'000;
    int64_t pegin_fee = 0;
    int64_t q_fee = 15'000;
    int64_t hogex_fee = 2'540;
    int64_t cbv_delta = 0;  // G's coinbasevalue off its fees
    bool pegin_depends = true;
    uint256 prev = u256(xf::kHash3200604);

    LitecoindG()
    {
        p = spend(fund(10), 0, 600'000'000, 10);
        TxOut p1;
        p1.value = 399'990'000;
        p1.scriptPubKey.m_data = {0x51};
        p.vout.push_back(p1);  // fee 10,000 from 1,000,000,000
        pegin = spend(compute_txid(p), 0, 29'000'000, 11);
        pegin.vout.insert(pegin.vout.begin(), tx_from_hex(xf::kPeginTx3200601Hex).vout[0]);
        pegin_fee = 600'000'000 - xf::kPegin3200601 - 29'000'000 + xf::kPeginKernelFee3200601;

        // 3200601's mw::Block taken apart: its header re-dated, its body kept.
        const auto raw = bytes_of(tf::kBlock3200601MwebRawHex);
        PackStream ps(raw);
        MWEBBlock blk;
        ps >> blk;
        PackStream h;
        h << blk.header;
        body.assign(raw.begin() + static_cast<std::ptrdiff_t>(h.get_span().size()), raw.end());
        header = blk.header;
        header.height = xf::kHeight3200604 + 1;
        header.output_mmr_size = 381309 + 2;

        hogex = tx_from_hex(tf::kBlock3200601HogexHex);
        hogex.vin[0].prevout.hash = u256(tf::kBlock3200604HogexTxid);
        hogex.vin[0].prevout.index = 0;
        hogex.vin[1].prevout.hash = compute_txid(pegin);
        hogex.vin[1].prevout.index = 0;
        hogex.vout[0].value = tf::kBlock3200603HogaddrValue + xf::kPegin3200601 - xf::kPegout3200601
                            - xf::kKernelFees3200601;
        commit(hogex, header);
    }

    std::string mweb() const
    {
        PackStream ps;
        ps << header;
        auto sp = ps.get_span();
        std::vector<unsigned char> out(reinterpret_cast<const unsigned char*>(sp.data()),
                                       reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
        out.insert(out.end(), body.begin(), body.end());
        return hex_of(out);
    }

    nlohmann::json json() const
    {
        const std::string q = nlohmann::json::parse(tf::kGbt3200605Json)["transactions"][0]["data"].get<std::string>();
        struct E { std::string data; int64_t fee; std::vector<int> dep; };
        const std::vector<E> es = {
            {tx_hex(p), p_fee, {}},
            {q, q_fee, {}},
            {tx_hex(pegin), pegin_fee, pegin_depends ? std::vector<int>{1} : std::vector<int>{}},
            {MWEBBuilder::serialize_hogex_hex(hogex), hogex_fee, {}},
        };
        nlohmann::json txs = nlohmann::json::array();
        for (const auto& e : es)
            txs.push_back({{"data", e.data}, {"txid", txid_hex(e.data)}, {"hash", wtxid_hex(e.data)},
                           {"depends", e.dep}, {"fee", e.fee}});
        return {{"previousblockhash", prev.GetHex()},
                {"height", xf::kHeight3200604 + 1},
                {"coinbasevalue", kSubsidy + p_fee + q_fee + pegin_fee + hogex_fee + cbv_delta},
                {"transactions", std::move(txs)},
                {"mweb", mweb()}};
    }
};

// The tip 3200604, its MWEB state, a view at the tip, a pool cleaned for it.
struct Tip {
    std::unique_ptr<HeaderChain> chain = chain_at_3200604();
    MWEBTracker tracker;
    BlockHeaderType hdr = header_from_hex(xf::kHeader3200604Hex);
    View view;
    Mempool pool;
    Tip(bool at_tip = true, bool cleaned = true)
    {
        EXPECT_TRUE(feed_3200604(tracker));
        pool.set_utxo(view.cache.get());
        if (at_tip)
            EXPECT_TRUE(view.best(hash_of(hdr), xf::kHeight3200604));
        else
            EXPECT_TRUE(view.best(u256(xf::kHash3200603), xf::kHeight3200604 - 1));
        if (cleaned)
            clean_for(pool, hdr);
    }
    std::optional<rpc::WorkData> build(mx::MwebExtSource* src, uint32_t budget = kBudget,
                                       std::optional<rpc::WorkData>* refused = nullptr,
                                       const MWEBTracker* t = nullptr)
    {
        return TemplateBuilder::build_template(*chain, pool, false, t ? t : &tracker, budget, refused, true,
                                               TemplateBuilder::COINBASE_SIGOP_RESERVE, src);
    }
};

// Our pool around litecoind's txs: P itself (litecoind imports it), K (P's
// other output), A (independent), B (spends what the peg-in spends), C (a
// pegin output: no block of ours may carry it).
struct OurTxs {
    MutableTransaction k, a, b, c;
};

OurTxs fill(Tip& t, const LitecoindG& g)
{
    t.view.add(fund(10), 0, 1'000'000'000);
    t.view.add(fund(11), 0, 100'000);
    t.view.add(fund(12), 0, 100'000);
    OurTxs o;
    o.k = spend(compute_txid(g.p), 1, 399'980'000, 20);          // fee 10,000
    o.a = spend(fund(11), 0, 95'000, 21);                         // fee 5,000
    o.b = spend(compute_txid(g.p), 0, 599'000'000, 22);           // fee 1,000,000: the best feerate
    o.c = spend(fund(12), 0, 90'000, 23);
    o.c.vout[0] = tx_from_hex(xf::kPeginTx3200601Hex).vout[0];
    o.c.vout[0].value = 90'000;
    EXPECT_FALSE(t.pool.admit(g.p, t.view.cache.get()));
    EXPECT_FALSE(t.pool.admit(o.k, t.view.cache.get()));
    EXPECT_FALSE(t.pool.admit(o.a, t.view.cache.get()));
    EXPECT_FALSE(t.pool.admit(o.b, t.view.cache.get()));
    EXPECT_TRUE(t.pool.add_tx_unchecked(o.c));  // past admission (which refuses it)
    t.pool.set_tx_fee(compute_txid(o.c), 10'000);
    return o;
}

std::vector<std::string> txids_of(const rpc::WorkData& wd)
{
    std::vector<std::string> v;
    for (const auto& e : wd.m_data["transactions"])
        v.push_back(e["txid"].get<std::string>());
    return v;
}

const std::string kOwnHogex3200605 = "48c7ebb937e2a26cce9ea47dead179ed5f8ca8242e8282c1dd4c7f2355d59239";

// litecoind ConnectBlock's nFees over the template's bytes
// (Consensus::CheckTxInputs per tx: inputs from the view or earlier txs of
// the block; the HogEx's vin[0] is the tip's HogAddr, worth the state's
// value). nullopt with the reason when an input is neither, an outpoint is
// spent twice, or a tx's inputs are below its outputs.
struct CoreFees {
    std::optional<int64_t> nfees;
    std::string why;
};
CoreFees core_nfees(const nlohmann::json& d, core::coin::UTXOViewCache& view, const MWEBState& st)
{
    CoreFees r;
    std::map<std::pair<uint256, uint32_t>, int64_t> created;
    std::set<std::pair<uint256, uint32_t>> spent;
    int64_t total = 0;
    const auto& txs = d["transactions"];
    for (size_t i = 0; i < txs.size(); ++i) {
        auto t = core::coin::walk_tx_hex(txs[i]["data"].get<std::string>());
        if (!t) {
            r.why = "undecodable " + std::to_string(i);
            return r;
        }
        const bool hogex = (t->flags & 0x08) != 0;
        int64_t in = 0;
        for (size_t k = 0; k < t->prevouts.size(); ++k) {
            const auto& op = t->prevouts[k];
            if (!spent.insert(op).second) {
                r.why = "double spend at tx " + std::to_string(i);
                return r;
            }
            if (hogex && k == 0) {
                if (op.first != st.prev_hogex_txid || op.second != 0) {
                    r.why = "hogex vin0";
                    return r;
                }
                in += st.hogaddr_value;
                continue;
            }
            if (auto c = created.find(op); c != created.end()) {
                in += c->second;
                continue;
            }
            core::coin::Coin coin;
            if (view.get_coin(core::coin::Outpoint(op.first, op.second), coin)) {
                in += coin.value;
                continue;
            }
            r.why = "missing input at tx " + std::to_string(i);
            return r;
        }
        int64_t out = 0;
        for (const auto& [v, spk] : t->vout)
            out += v;
        if (in < out) {
            r.why = "in below out at tx " + std::to_string(i);
            return r;
        }
        total += in - out;
        for (uint32_t n = 0; n < t->vout.size(); ++n)
            created[{t->txid, n}] = t->vout[n].first;
    }
    r.nfees = total;
    return r;
}

} // namespace

// none: the S0+S1 head's templates, byte for byte; a source in mode none is
// no source.
TEST(LtcTemplateMwebExtMerge, NoneModeIsByteIdenticalToTheS0S1Head)
{
    EXPECT_EQ(none_mode_dump(), std::string(kNoneModeGoldenDump));

    Tip t;
    fill_pool(t.pool, t.view);
    mx::MwebExtSource none("none");
    auto a = t.build(nullptr);
    auto b = t.build(&none);
    ASSERT_TRUE(a && b);
    EXPECT_EQ(template_dump(*a), template_dump(*b));
    EXPECT_EQ(none.to_json()["last"], nullptr) << "a source in mode none is never asked";
}

TEST(LtcTemplateMwebExtMerge, MergedTemplateCarriesLitecoindsExtension)
{
    Tip t;
    const LitecoindG g;
    const OurTxs ours = fill(t, g);
    mx::MwebExtSource src("litecoind");
    src.set_parsed(mx::parse_extension(g.json()), mx::MwebExtSource::clock::now());
    ASSERT_TRUE(src.current().bundle) << src.current().reason << ": " << src.current().detail;

    auto wd = t.build(&src);
    ASSERT_TRUE(wd);
    const auto& d = wd->m_data;
    const auto ids = txids_of(*wd);
    ASSERT_EQ(ids.size(), 5u) << d["transactions"].dump();
    EXPECT_EQ(ids[0], compute_txid(g.p).GetHex()) << "litecoind's txs first, in its order";
    EXPECT_EQ(ids[1], compute_txid(g.pegin).GetHex());
    EXPECT_EQ(ids[2], compute_txid(ours.k).GetHex()) << "P's child follows P";
    EXPECT_EQ(ids[3], compute_txid(ours.a).GetHex());
    EXPECT_EQ(ids[4], txid_hex(MWEBBuilder::serialize_hogex_hex(g.hogex))) << "litecoind's HogEx last";
    for (const auto& id : ids) {
        EXPECT_NE(id, compute_txid(ours.b).GetHex()) << "B spends what the peg-in spends";
        EXPECT_NE(id, compute_txid(ours.c).GetHex()) << "a pegin output of ours is barred";
    }
    EXPECT_EQ(std::count(ids.begin(), ids.end(), compute_txid(g.p).GetHex()), 1) << "P once";
    EXPECT_FALSE(core::coin::check_template_txs(d)) << "a block litecoind accepts (rules 1-8)";
    EXPECT_FALSE(core::coin::check_template_shape(d));
    EXPECT_FALSE(core::coin::template_degraded_code(d));
    EXPECT_EQ(d["mweb"].get<std::string>(), g.mweb());
    EXPECT_EQ(d["transactions"][4]["data"].get<std::string>(), MWEBBuilder::serialize_hogex_hex(g.hogex));
    EXPECT_EQ(d["transactions"][4]["fee"].get<int64_t>(), g.hogex_fee);
    EXPECT_EQ(d["transactions"][1]["fee"].get<int64_t>(), g.pegin_fee) << "litecoind's fee, kernel fee included";
    EXPECT_EQ(d["transactions"][1]["hash"].get<std::string>(), wtxid_hex(tx_hex(g.pegin)));
    EXPECT_EQ(d["coinbasevalue"].get<int64_t>(),
              kSubsidy + g.p_fee + g.pegin_fee + 10'000 + 5'000 + g.hogex_fee) << "subsidy + every listed fee";
    int64_t listed = 0;
    for (const auto& e : d["transactions"])
        listed += e["fee"].get<int64_t>();
    EXPECT_EQ(d["coinbasevalue"].get<int64_t>(), kSubsidy + listed);
    // ... which is exactly what litecoind's ConnectBlock allows.
    const auto cf = core_nfees(d, *t.view.cache, *t.tracker.get_state());
    ASSERT_TRUE(cf.nfees) << cf.why;
    EXPECT_EQ(d["coinbasevalue"].get<int64_t>() - kSubsidy, *cf.nfees);
    // The stratum merkle branches and the block use the same txs.
    ASSERT_EQ(wd->m_hashes.size(), 5u);
    for (size_t i = 0; i < 5; ++i)
        EXPECT_EQ(wd->m_hashes[i].GetHex(), ids[i]);
    ASSERT_EQ(wd->m_txs.size(), 5u);
    EXPECT_TRUE(wd->m_txs.back().m_hogEx);
    EXPECT_EQ(wd->m_txs.back().vin.size(), 2u);

    const auto j = src.to_json();
    EXPECT_EQ(j["imported_txs"], 2);
    EXPECT_EQ(j["imported_pegins"], 1);
    EXPECT_EQ(j["imported_kernels"], 2);
    EXPECT_EQ(j["imported_fee_sat"], g.p_fee + g.pegin_fee + g.hogex_fee);
    EXPECT_EQ(j["last"]["outcome"], "imported");
    EXPECT_EQ(src.templates_imported(), 1u);
}

// Every failure: the template the builder makes without the source (the
// empty body, c2pool's own HogEx on the tip), byte for byte, counted.
TEST(LtcTemplateMwebExtMerge, EveryFallbackIsTheEmptyBodyTemplate)
{
    struct Case {
        const char* reason;
        std::function<void(LitecoindG&)> mutate;
        bool none = false;  // no G at all
    };
    const std::vector<Case> cases = {
        {mx::kUnavailable, [](LitecoindG&) {}, true},
        {mx::kPrevMismatch, [](LitecoindG& g) { g.prev = u256(xf::kHash3200603); }},
        {mx::kPrevHogexMismatch, [](LitecoindG& g) {
             g.hogex.vin[0].prevout.hash = u256(tf::kBlock3200603HogexTxid);
         }},
        {mx::kHogaddrValueMismatch, [](LitecoindG& g) { g.hogex.vout[0].value += 1; }},
        {"mweb-hash-mismatch", [](LitecoindG& g) { g.header.leafset_root.data()[0] ^= 1; }},
        {mx::kTxoCountMismatch, [](LitecoindG& g) {
             g.header.output_mmr_size = 381309;
             commit(g.hogex, g.header);
         }},
        {mx::kGFeeSumMismatch, [](LitecoindG& g) { g.cbv_delta = -(g.q_fee + 1); }},
        {mx::kImportedFeeMismatch, [](LitecoindG& g) {
             g.p_fee += 1'000'000;  // G's coinbasevalue carries it
         }},
    };
    for (const auto& k : cases) {
        Tip t;
        LitecoindG g;
        fill(t, g);
        k.mutate(g);
        mx::MwebExtSource src("litecoind");
        if (!k.none) {
            auto parsed = mx::parse_extension(g.json());
            ASSERT_TRUE(parsed.bundle) << k.reason << ": " << parsed.reason;
            src.set_parsed(std::move(parsed), mx::MwebExtSource::clock::now());
        }
        auto with = t.build(&src);
        auto without = t.build(nullptr);
        ASSERT_TRUE(with && without) << k.reason;
        EXPECT_EQ(template_dump(*with), template_dump(*without)) << k.reason;
        EXPECT_EQ(with->m_data["transactions"].back()["txid"].get<std::string>(), kOwnHogex3200605)
            << k.reason << ": c2pool's own HogEx, never none";
        EXPECT_FALSE(core::coin::check_template_txs(with->m_data)) << k.reason;
        EXPECT_EQ(src.fallback_count(k.reason), 1u) << k.reason;
        EXPECT_EQ(src.to_json()["imported_txs"], 0) << k.reason;
        EXPECT_EQ(src.last().kind, mx::Outcome::fallback) << k.reason;
    }
}

// The empty template on the tip never imports: the view behind the tip, the
// pool not cleaned for it (an empty pool too); nor a template without the
// tip's MWEB state (refused as before: the MWEB HOLD).
TEST(LtcTemplateMwebExtMerge, OnlyAFullTemplateImports)
{
    const LitecoindG g;
    auto source = [&g](mx::MwebExtSource& s) {
        s.set_parsed(mx::parse_extension(g.json()), mx::MwebExtSource::clock::now());
    };
    {
        Tip t(/*at_tip=*/false);
        fill(t, g);
        mx::MwebExtSource src("litecoind");
        source(src);
        auto wd = t.build(&src);
        ASSERT_TRUE(wd);
        EXPECT_EQ(core::coin::template_degraded_code(wd->m_data),
                  std::optional<std::string>(core::coin::kUtxoViewNotAtTip));
        ASSERT_EQ(wd->m_data["transactions"].size(), 1u) << "the HogEx only";
        EXPECT_EQ(wd->m_data["transactions"][0]["txid"].get<std::string>(), kOwnHogex3200605);
        EXPECT_EQ(src.skipped_count(mx::kSkipNotFull), 1u);
        EXPECT_EQ(src.templates_imported(), 0u);
    }
    {
        Tip t(/*at_tip=*/true, /*cleaned=*/false);
        fill(t, g);
        mx::MwebExtSource src("litecoind");
        source(src);
        auto wd = t.build(&src);
        ASSERT_TRUE(wd);
        EXPECT_EQ(core::coin::template_degraded_code(wd->m_data),
                  std::optional<std::string>(core::coin::kNotCleanedForTip));
        EXPECT_EQ(src.skipped_count(mx::kSkipNotFull), 1u);
    }
    {
        // An empty pool is not gated, but a pool never cleaned for the tip
        // is no full template: no import.
        Tip t(/*at_tip=*/true, /*cleaned=*/false);
        mx::MwebExtSource src("litecoind");
        source(src);
        auto wd = t.build(&src);
        ASSERT_TRUE(wd);
        EXPECT_FALSE(core::coin::template_degraded_code(wd->m_data));
        EXPECT_EQ(wd->m_data["transactions"].size(), 1u);
        EXPECT_EQ(src.skipped_count(mx::kSkipNotFull), 1u);
    }
    {
        // An empty pool cleaned for the tip, the view at it (holding P's
        // input): litecoind's extension alone.
        Tip t;
        t.view.add(fund(10), 0, 1'000'000'000);
        mx::MwebExtSource src("litecoind");
        source(src);
        auto wd = t.build(&src);
        ASSERT_TRUE(wd);
        EXPECT_EQ(txids_of(*wd).size(), 3u) << "P, the peg-in, the HogEx";
        EXPECT_EQ(src.templates_imported(), 1u);
    }
    {
        Tip t;
        fill(t, g);
        mx::MwebExtSource src("litecoind");
        source(src);
        MWEBTracker no_state;
        std::optional<rpc::WorkData> refused;
        auto wd = t.build(&src, kBudget, &refused, &no_state);
        EXPECT_FALSE(wd) << "no MWEB state for the tip: refused, as before";
        ASSERT_TRUE(refused);
        EXPECT_TRUE(core::coin::check_template_shape(refused->m_data));
        EXPECT_EQ(src.skipped_count(mx::kSkipNoMwebState), 1u);
    }
}

// A merged template that fails check_template_txs (a bundle whose bytes
// disagree with its txid; parse_extension never yields one) is not served:
// the template without the extension is.
TEST(LtcTemplateMwebExtMerge, MergedCheckFailureFallsBack)
{
    Tip t;
    const LitecoindG g;
    fill(t, g);
    auto parsed = mx::parse_extension(g.json());
    ASSERT_TRUE(parsed.bundle);
    auto forged = std::make_shared<mx::ExtensionBundle>(*parsed.bundle);
    ASSERT_FALSE(forged->txs[0].pegin);
    // P's bytes swapped for another tx's, its txid, inputs and outputs kept
    // (check_extension reads those, the template the bytes).
    forged->txs[0].hex = tx_hex(spend(fund(11), 0, 1'000, 99));
    mx::ParseResult pr;
    pr.bundle = forged;
    mx::MwebExtSource src("litecoind");
    src.set_parsed(std::move(pr), mx::MwebExtSource::clock::now());
    ASSERT_FALSE(mx::check_extension(*forged, *t.tracker.get_state(), hash_of(t.hdr), xf::kHeight3200604, kSubsidy,
                                     [&t](const mx::Outpoint& op, core::coin::Coin& c) {
                                         return t.view.cache->get_coin(core::coin::Outpoint(op.first, op.second), c);
                                     }));

    auto with = t.build(&src);
    auto without = t.build(nullptr);
    ASSERT_TRUE(with && without);
    EXPECT_EQ(template_dump(*with), template_dump(*without));
    EXPECT_EQ(src.fallback_count("merged-txid-mismatch"), 1u);
}

// The selection leaves room for litecoind's txs and its HogEx.
TEST(LtcTemplateMwebExtMerge, SelectionBudgetLeavesRoomForTheImport)
{
    const LitecoindG g;
    auto x = mx::parse_extension(g.json()).bundle;
    ASSERT_TRUE(x);
    const uint32_t imported = static_cast<uint32_t>(x->weight());
    EXPECT_GT(imported, 0u);
    struct Case { uint32_t budget; size_t ours; };
    for (const auto& k : {Case{imported + 300, 1}, Case{imported + 1000, 2}, Case{imported - 1, 0}}) {
        Tip t;
        fill(t, g);
        mx::MwebExtSource src("litecoind");
        src.set_parsed(mx::parse_extension(g.json()), mx::MwebExtSource::clock::now());
        auto wd = t.build(&src, k.budget);
        ASSERT_TRUE(wd);
        EXPECT_EQ(txids_of(*wd).size(), 3u + k.ours) << "budget " << k.budget;
        EXPECT_EQ(src.templates_imported(), 1u);
    }
}

// Only the next block's HogEx spends the tip's HogAddr, with litecoind's
// extension too: the selection starts with litecoind's HogEx's inputs
// spent, and a pool tx spending the HogAddr never rides along (the same
// rule as hogaddr_spend_guard_test.cpp without the extension).
TEST(LtcTemplateMwebExtMerge, SelectionReservesTheHogexInputsWithTheExtension)
{
    for (bool with_ext : {false, true}) {
        Tip t;
        const LitecoindG g;
        fill(t, g);
        const auto st = *t.tracker.get_state();
        const auto hogaddr_spk = tx_from_hex(tf::kBlock3200604HogexHex).vout[0].scriptPubKey.m_data;
        t.view.add(st.prev_hogex_txid, 0, st.hogaddr_value);  // under an ordinary script: the reservation alone
        const MutableTransaction x = spend(st.prev_hogex_txid, 0, st.hogaddr_value - 1'000'000, 30);
        ASSERT_TRUE(t.pool.add_tx_unchecked(x, t.view.cache.get()));
        mx::MwebExtSource src("litecoind");
        src.set_parsed(mx::parse_extension(g.json()), mx::MwebExtSource::clock::now());
        auto wd = t.build(with_ext ? &src : nullptr);
        ASSERT_TRUE(wd);
        for (const auto& id : txids_of(*wd))
            EXPECT_NE(id, compute_txid(x).GetHex()) << "with_ext=" << with_ext;
        EXPECT_EQ(src.templates_imported(), with_ext ? 1u : 0u);
        const auto cf = core_nfees(wd->m_data, *t.view.cache, st);
        ASSERT_TRUE(cf.nfees) << "with_ext=" << with_ext << ": " << cf.why;
        EXPECT_EQ(wd->m_data["coinbasevalue"].get<int64_t>() - kSubsidy, *cf.nfees) << "with_ext=" << with_ext;
        (void)hogaddr_spk;
    }
}

// Each imported tx's fee is recomputed from the UTXO view (inputs -
// outputs, plus its peg-in kernel fees from the body): a listed fee off by
// any amount, inside or beyond what G's coinbasevalue carries, gives the
// empty-body template, never a coinbase above what litecoind allows.
TEST(LtcTemplateMwebExtMerge, ImportedFeesAreRecomputedFromTheView)
{
    struct Case {
        const char* reason;
        std::function<void(LitecoindG&)> mutate;
    };
    const std::vector<Case> cases = {
        // P listed at 1,010,000, priced at 10,000; coinbasevalue carries it.
        {mx::kImportedFeeMismatch, [](LitecoindG& g) { g.p_fee += 1'000'000; }},
        // The peg-in listed 15,000 above, within the slack of Q's fee: G's
        // coinbasevalue as an honest litecoind prints it.
        {mx::kGFeeSumMismatch, [](LitecoindG& g) {
             g.pegin_fee += 15'000;
             g.cbv_delta = -15'000;
         }},
        // The same with coinbasevalue following the listed fees.
        {mx::kImportedFeeMismatch, [](LitecoindG& g) { g.pegin_fee += 15'000; }},
        // Listed below: refused as well (the number is litecoind's, not ours).
        {mx::kImportedFeeMismatch, [](LitecoindG& g) { g.pegin_fee -= 1; }},
    };
    for (const auto& k : cases) {
        Tip t;
        LitecoindG g;
        fill(t, g);
        k.mutate(g);
        mx::MwebExtSource src("litecoind");
        src.set_parsed(mx::parse_extension(g.json()), mx::MwebExtSource::clock::now());
        ASSERT_TRUE(src.current().bundle) << k.reason;
        auto with = t.build(&src);
        auto without = t.build(nullptr);
        ASSERT_TRUE(with && without);
        EXPECT_EQ(src.templates_imported(), 0u) << k.reason;
        EXPECT_EQ(src.fallback_count(k.reason), 1u) << k.reason;
        EXPECT_EQ(template_dump(*with), template_dump(*without)) << k.reason;
        const auto cf = core_nfees(with->m_data, *t.view.cache, *t.tracker.get_state());
        ASSERT_TRUE(cf.nfees) << cf.why;
        EXPECT_EQ(with->m_data["coinbasevalue"].get<int64_t>() - kSubsidy, *cf.nfees) << k.reason;
    }
}

// A peg-in whose parent P is missing from its "depends": P is imported all
// the same (the peg-in spends it), first; our own copy of P is not selected
// after it. The block is one litecoind accepts.
TEST(LtcTemplateMwebExtMerge, ImportedParentsShipFirstWithoutDepends)
{
    Tip t;
    LitecoindG g;
    g.pegin_depends = false;
    fill(t, g);
    mx::MwebExtSource src("litecoind");
    src.set_parsed(mx::parse_extension(g.json()), mx::MwebExtSource::clock::now());
    auto wd = t.build(&src);
    ASSERT_TRUE(wd);
    ASSERT_EQ(src.templates_imported(), 1u);
    const auto ids = txids_of(*wd);
    ASSERT_GE(ids.size(), 3u);
    EXPECT_EQ(ids[0], compute_txid(g.p).GetHex());
    EXPECT_EQ(ids[1], compute_txid(g.pegin).GetHex());
    EXPECT_EQ(std::count(ids.begin(), ids.end(), compute_txid(g.p).GetHex()), 1);
    EXPECT_FALSE(core::coin::check_template_txs(wd->m_data));
    const auto cf = core_nfees(wd->m_data, *t.view.cache, *t.tracker.get_state());
    ASSERT_TRUE(cf.nfees) << cf.why;
    EXPECT_EQ(wd->m_data["coinbasevalue"].get<int64_t>() - kSubsidy, *cf.nfees);
}
