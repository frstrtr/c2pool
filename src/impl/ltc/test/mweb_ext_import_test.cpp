// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The hybrid MWEB extension's import (#2137 S3; rides share_test):
// ltc::coin::mweb_ext::parse_extension and check_extension over REAL mainnet
// data, and the source's counters.
//
//   - litecoind's real template at 3200605 on the real tip 3200604 (its MWEB
//     state fed to a real MWEBTracker) imports: an empty body, no peg-in,
//     and HogEx and mw::Block byte-equal to the ones c2pool builds itself;
//   - block 3200601 as a template (its real peg-in 92dd3109.., its real
//     HogEx with the peg-in input and a peg-out output, its real 2-kernel
//     body) on the state of 3200600 (the HogEx txid 3200601 spends, the
//     HogAddr value the consensus equation gives, the txo count less the
//     two outputs) imports the peg-in alone, not an unrelated tx; each check
//     refuses its own mutation (prev, prev HogEx, peg-ins missing / extra /
//     out of order, commitment, height, kernel count, peg-in coins, peg-outs,
//     HogAddr value, a pegin script among the HogEx outputs, G's fee sum,
//     the HogEx's listed fee, txo count), and the peg-in against the view
//     (its fee recomputed, an input missing / immature / a HogAddr / worth
//     less than the outputs); the parse refuses malformed templates;
//   - block 3200603 (6 inputs, 2 outputs, a 25 LTC peg-out) as a template on
//     the state of 3200602 DERIVED from the real block 3200601 (3200602's
//     body was empty): c2pool's own empty-body HogEx for 3200602 is the txid
//     3200603 spends, and every check passes on real values;
//   - a peg-in's in-template ancestors ship with it, first: by G "depends"
//     and by its inputs, whatever G's order;
//   - MwebExtSource's /local_stats block in both modes.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "template_mweb_ext_fixture.hpp"

#include <impl/ltc/coin/mweb_ext_import.hpp>

namespace {

using namespace ltc::coin;
using namespace ltc_mweb_ext_test;
namespace mx = ltc::coin::mweb_ext;

constexpr int64_t kSubsidy = 625000000;  // heights 2,520,000 .. 3,359,999

// ─── building a getblocktemplate answer ─────────────────────────────────────

struct Entry {
    std::string data;
    int64_t fee{0};
    std::vector<int> depends;               // 1-based, as litecoind's
    std::optional<std::string> txid, hash;  // overrides
};

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

std::string txid_hex(const std::string& data)
{
    auto t = core::coin::walk_tx_hex(data);
    return t ? t->txid.GetHex() : std::string();
}

nlohmann::json make_g(const uint256& prev, uint32_t height, int64_t coinbasevalue,
                      const std::vector<Entry>& entries, const std::string& mweb_hex)
{
    nlohmann::json txs = nlohmann::json::array();
    for (const auto& e : entries) {
        nlohmann::json j;
        j["data"] = e.data;
        j["txid"] = e.txid ? *e.txid : txid_hex(e.data);
        j["hash"] = e.hash ? *e.hash : wtxid_hex(e.data);
        j["depends"] = e.depends;
        j["fee"] = e.fee;
        txs.push_back(std::move(j));
    }
    return {
        {"previousblockhash", prev.GetHex()},
        {"height", height},
        {"coinbasevalue", coinbasevalue},
        {"transactions", std::move(txs)},
        {"rules", nlohmann::json::array({"csv", "!segwit", "taproot", "mweb"})},
        {"mweb", mweb_hex},
    };
}

// ─── the mw::Block and the HogEx, taken apart and put together ─────────────

struct Mweb {
    MWEBHeader header;
    std::vector<unsigned char> body;  // the TxBody bytes after the header
};

Mweb split_mweb(const std::string& raw_hex)
{
    const auto raw = bytes_of(raw_hex);
    PackStream ps(raw);
    MWEBBlock blk;
    ps >> blk;
    PackStream h;
    h << blk.header;
    const size_t hlen = h.get_span().size();
    Mweb m;
    m.header = blk.header;
    m.body.assign(raw.begin() + static_cast<std::ptrdiff_t>(hlen), raw.end());
    return m;
}

std::string mweb_hex(const MWEBHeader& hdr, const std::vector<unsigned char>& body)
{
    PackStream ps;
    ps << hdr;
    auto sp = ps.get_span();
    std::vector<unsigned char> out(reinterpret_cast<const unsigned char*>(sp.data()),
                                   reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    out.insert(out.end(), body.begin(), body.end());
    return hex_of(out);
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

std::string hogex_hex(const MutableTransaction& hogex)
{
    return MWEBBuilder::serialize_hogex_hex(hogex);
}

// ─── block 3200601 as a template on the state of 3200600 ───────────────────

MWEBState state_3200600()
{
    MWEBState s;
    s.prev_hogex_txid = u256(xf::kHogexTxid3200600);
    s.prev_hogex_vout = 0;
    // The consensus equation (mweb-amount-mismatch) solved for the parent:
    // 3200600 is not among the captured blocks.
    s.hogaddr_value = xf::kHogaddrValue3200601 - xf::kPegin3200601 + xf::kPegout3200601 + xf::kKernelFees3200601;
    s.prev_header.height = xf::kHeight3200601 - 1;
    s.prev_header.output_mmr_size = xf::kTxos3200601 - 2;  // the body adds 2 outputs
    s.captured_at_height = xf::kHeight3200601 - 1;
    s.captured_block_hash = u256(xf::kHash3200600);
    s.valid = true;
    return s;
}

// An unrelated canonical tx (litecoind's first entry at 3200605): in G, not
// imported.
std::string unrelated_tx()
{
    auto g = nlohmann::json::parse(tf::kGbt3200605Json);
    return g["transactions"][0]["data"].get<std::string>();
}

struct G3200601 {
    MutableTransaction pegin = tx_from_hex(xf::kPeginTx3200601Hex);
    MutableTransaction hogex = tx_from_hex(tf::kBlock3200601HogexHex);
    Mweb mweb = split_mweb(tf::kBlock3200601MwebRawHex);
    int64_t pegin_fee = xf::kPeginKernelFee3200601 + 1880;  // its canonical fee is not captured
    int64_t hogex_fee = xf::kPegoutKernelFee3200601;        // the MWEB-only peg-out tx
    int64_t unrelated_fee = 15000;
    std::optional<int64_t> coinbasevalue;
    uint256 prev = u256(xf::kHash3200600);
    uint32_t height = xf::kHeight3200601;
    bool with_pegin = true;

    nlohmann::json json() const
    {
        std::vector<Entry> e;
        e.push_back({unrelated_tx(), unrelated_fee, {}, {}, {}});
        if (with_pegin)
            e.push_back({tx_hex(pegin), pegin_fee, {}, {}, {}});
        e.push_back({hogex_hex(hogex), hogex_fee, {}, {}, {}});
        const int64_t cbv = coinbasevalue ? *coinbasevalue
                                          : kSubsidy + unrelated_fee + pegin_fee + hogex_fee;
        return make_g(prev, height, cbv, e, mweb_hex(mweb.header, mweb.body));
    }
};

std::shared_ptr<const mx::ExtensionBundle> parse_ok(const nlohmann::json& g)
{
    auto r = mx::parse_extension(g);
    EXPECT_TRUE(r.bundle) << r.reason << ": " << r.detail;
    return r.bundle;
}

// A UTXO view for check 4f: outpoint -> coin.
using Coins = std::map<mx::Outpoint, core::coin::Coin>;

core::coin::Coin coin_of_value(int64_t value, std::vector<unsigned char> spk = {0x51}, uint32_t height = 1,
                               bool coinbase = false)
{
    core::coin::Coin c;
    c.value = value;
    c.scriptPubKey.m_data = std::move(spk);
    c.height = height;
    c.coinbase = coinbase;
    return c;
}

mx::CoinLookup lookup(const Coins& coins)
{
    return [coins](const mx::Outpoint& op, core::coin::Coin& c) {
        auto it = coins.find(op);
        if (it == coins.end())
            return false;
        c = it->second;
        return true;
    };
}

// The three coins the real peg-in 92dd3109.. spends, as the view at 3200600
// would hold them. Their values are not among the captures: these sum to
// the peg-in output plus a canonical fee of 1,880, which G3200601 lists.
Coins coins_3200600()
{
    const MutableTransaction pegin = tx_from_hex(xf::kPeginTx3200601Hex);
    Coins c;
    const int64_t in[3] = {300'000'000, 200'000'000, xf::kPegin3200601 + 1'880 - 500'000'000};
    for (size_t i = 0; i < 3; ++i)
        c[{pegin.vin[i].prevout.hash, pegin.vin[i].prevout.index}] = coin_of_value(in[i]);
    return c;
}

std::string check_3200601(const G3200601& g, const MWEBState& st = state_3200600(),
                          const Coins& coins = coins_3200600())
{
    auto r = mx::parse_extension(g.json());
    if (!r.bundle)
        return "parse:" + r.reason;
    auto f = mx::check_extension(*r.bundle, st, u256(xf::kHash3200600), xf::kHeight3200601 - 1, kSubsidy,
                                 lookup(coins));
    return f ? f->reason : std::string("ok");
}

} // namespace

// litecoind's real template at 3200605 on the real tip 3200604: it imports,
// and its HogEx and mw::Block are the ones c2pool builds from the tip's
// state (no MWEB tx in litecoind's mempool then): mweb_eq.
TEST(LtcMwebExtImport, RealGbt3200605OnTheRealTip3200604)
{
    MWEBTracker tracker;
    ASSERT_TRUE(feed_3200604(tracker));
    const auto st = tracker.get_state();
    ASSERT_TRUE(st);
    ASSERT_EQ(st->captured_block_hash.GetHex(), xf::kHash3200604);

    auto x = parse_ok(nlohmann::json::parse(tf::kGbt3200605Json));
    ASSERT_TRUE(x);
    EXPECT_EQ(x->prev.GetHex(), xf::kHash3200604);
    EXPECT_EQ(x->height, 3200605u);
    EXPECT_TRUE(x->txs.empty()) << "no peg-in: nothing but the HogEx is imported";
    EXPECT_TRUE(x->body_empty());
    EXPECT_EQ(x->fee_hogex(), 0);
    EXPECT_FALSE(mx::check_extension(*x, *st, st->captured_block_hash, xf::kHeight3200604, kSubsidy, {}))
        << "no imported tx: the view is not asked";

    const auto own = MWEBBuilder::build_hogex(*st, 3200605);
    EXPECT_EQ(x->hogex.hex, MWEBBuilder::serialize_hogex_hex(own)) << "litecoind's HogEx == c2pool's own";
    EXPECT_EQ(x->hogex.txid, MWEBBuilder::compute_hogex_txid(own));
    EXPECT_EQ(x->mweb_hex, hex_of(MWEBBuilder::build_empty_mweb_block(*st, 3200605)))
        << "litecoind's mw::Block == c2pool's own empty body";
    EXPECT_EQ(x->mweb_hex, tf::kGbt3200605MwebHex);

    // Check 5 on the empty body: a header that does not carry the tip's
    // state is refused even when the HogAddr commits to it.
    nlohmann::json g = nlohmann::json::parse(tf::kGbt3200605Json);
    Mweb m = split_mweb(tf::kGbt3200605MwebHex);
    m.header.output_root.data()[0] ^= 1;
    MutableTransaction hog = tx_from_hex(g["transactions"].back()["data"].get<std::string>());
    commit(hog, m.header);
    g["transactions"].back()["data"] = hogex_hex(hog);
    g["transactions"].back()["txid"] = txid_hex(hogex_hex(hog));
    g["transactions"].back()["hash"] = txid_hex(hogex_hex(hog));
    g["mweb"] = mweb_hex(m.header, m.body);
    auto bad = parse_ok(g);
    ASSERT_TRUE(bad);
    auto f = mx::check_extension(*bad, *st, st->captured_block_hash, xf::kHeight3200604, kSubsidy, {});
    ASSERT_TRUE(f);
    EXPECT_EQ(f->reason, mx::kCarriedStateMismatch);
}

// Block 3200601 as litecoind's template: its peg-in is imported (not the
// unrelated tx), every check passes, and each mutation is refused by its
// own check.
TEST(LtcMwebExtImport, Block3200601PeginAndPegoutAndEveryCheck)
{
    G3200601 base;
    auto x = parse_ok(base.json());
    ASSERT_TRUE(x);
    ASSERT_EQ(x->txs.size(), 1u) << "the peg-in alone";
    EXPECT_EQ(x->txs[0].txid.GetHex(), xf::kPeginTx3200601Txid);
    EXPECT_EQ(x->txs[0].wtxid.GetHex(), xf::kPeginTx3200601Wtxid);
    EXPECT_TRUE(x->txs[0].pegin);
    EXPECT_EQ(x->txs[0].fee, base.pegin_fee);
    EXPECT_EQ(x->n_pegins(), 1u);
    EXPECT_EQ(x->hogex.txid.GetHex(), tf::kBlock3200601HogexTxid);
    EXPECT_EQ(x->hogex_tx.vin.size(), 2u);
    EXPECT_EQ(x->body.kernels.size(), 2u);
    EXPECT_EQ(x->spent.size(), 3u) << "the peg-in's three inputs";
    EXPECT_EQ(check_3200601(base), "ok");

    // 0. G for another block; G's height; the state of another block.
    {
        G3200601 g;
        g.prev = u256(xf::kHash3200601);
        EXPECT_EQ(check_3200601(g), mx::kPrevMismatch);
        G3200601 h;
        h.height = xf::kHeight3200601 + 1;
        EXPECT_EQ(check_3200601(h), mx::kGHeightMismatch);
        MWEBState st = state_3200600();
        st.captured_block_hash = u256(xf::kHash3200601);
        EXPECT_EQ(check_3200601(base, st), mx::kStateNotForTip);
    }
    // 1. HogEx vin[0] is not the tip's HogEx output 0.
    {
        G3200601 g;
        g.hogex.vin[0].prevout.hash = u256(xf::kHogexTxid3200602);
        EXPECT_EQ(check_3200601(g), mx::kPrevHogexMismatch);
        G3200601 h;
        h.hogex.vin[0].prevout.index = 1;
        EXPECT_EQ(check_3200601(h), mx::kPrevHogexMismatch);
    }
    // 2. The peg-in entry dropped: the HogEx has an input no pegin output
    //    matches; the HogEx's peg-in input dropped: a pegin output without
    //    one; the input pointing elsewhere.
    {
        G3200601 g;
        g.with_pegin = false;
        g.coinbasevalue = kSubsidy + g.unrelated_fee + g.hogex_fee;
        EXPECT_EQ(check_3200601(g), "extra-hogex-input");
        G3200601 h;
        h.hogex.vin.pop_back();
        EXPECT_EQ(check_3200601(h), "pegins-missing");
        G3200601 k;
        k.hogex.vin[1].prevout.index = 1;
        EXPECT_EQ(check_3200601(k), "pegin-mismatch");
    }
    // 3. A header byte flipped (the HogAddr no longer commits to it); the
    //    height one less, the kernel count one more (each with the HogAddr
    //    committing to the mutated header).
    {
        G3200601 g;
        g.mweb.header.kernel_root.data()[5] ^= 0x10;
        EXPECT_EQ(check_3200601(g), "mweb-hash-mismatch");
        G3200601 h;
        h.mweb.header.height -= 1;
        commit(h.hogex, h.mweb.header);
        EXPECT_EQ(check_3200601(h), "mweb-height-mismatch");
        G3200601 k;
        k.mweb.header.kernel_mmr_size += 1;
        commit(k.hogex, k.mweb.header);
        EXPECT_EQ(check_3200601(k), mx::kKernelCountMismatch);
    }
    // 4. The value.
    {
        // The HogAddr value one more / one less.
        for (int64_t d : {+1, -1}) {
            G3200601 g;
            g.hogex.vout[0].value += d;
            EXPECT_EQ(check_3200601(g), mx::kHogaddrValueMismatch) << d;
        }
        // The peg-out paid one satoshi more than the body pegs out.
        G3200601 g;
        g.hogex.vout[1].value += 1;
        EXPECT_EQ(check_3200601(g), mx::kPegoutMismatch);
        // A peg-out to another script.
        G3200601 s;
        s.hogex.vout[1].scriptPubKey.m_data.back() ^= 1;
        EXPECT_EQ(check_3200601(s), mx::kPegoutMismatch);
        // The pegin output pays another amount than the peg-in kernel (the
        // HogEx input follows the new txid, so check 2 passes).
        G3200601 p;
        p.pegin.vout[0].value -= 1;
        p.hogex.vin[1].prevout.hash = compute_txid(p.pegin);
        EXPECT_EQ(check_3200601(p), mx::kPeginKernelMismatch);
        // A HogEx output paying a pegin script (bad-tx-unexpected-pegin),
        // the body's peg-out unchanged.
        G3200601 q;
        TxOut extra;
        extra.value = 0;
        extra.scriptPubKey = q.pegin.vout[0].scriptPubKey;
        q.hogex.vout.push_back(extra);
        EXPECT_EQ(check_3200601(q), mx::kHogexPeginOutput);
        // The listed fees: G's own sum off its coinbasevalue; the HogEx's
        // above the kernel fees outside the peg-in.
        G3200601 c;
        c.coinbasevalue = kSubsidy + c.unrelated_fee + c.pegin_fee + c.hogex_fee - 1;
        EXPECT_EQ(check_3200601(c), mx::kGFeeSumMismatch);
        G3200601 f;
        f.hogex_fee += 1;
        EXPECT_EQ(check_3200601(f), mx::kHogexFeeEntryTooHigh);
    }
    // 4f. The peg-in against the view: its listed fee is inputs - outputs +
    // its peg-in kernel fee, one satoshi either way is refused (G's sum
    // kept consistent); an input missing from the view, immature, a
    // HogAddr, or worth less than the outputs is refused.
    {
        for (int64_t d : {+1, -1}) {
            G3200601 g;
            g.pegin_fee += d;
            EXPECT_EQ(check_3200601(g), mx::kImportedFeeMismatch) << d;
        }
        G3200601 k;
        k.pegin_fee = xf::kPeginKernelFee3200601 - 1;
        EXPECT_EQ(check_3200601(k), mx::kImportedFeeMismatch) << "below its own kernel fee";
        const MutableTransaction pegin = tx_from_hex(xf::kPeginTx3200601Hex);
        const mx::Outpoint in2{pegin.vin[2].prevout.hash, pegin.vin[2].prevout.index};
        Coins missing = coins_3200600();
        missing.erase(in2);
        EXPECT_EQ(check_3200601(G3200601{}, state_3200600(), missing), mx::kImportedInputMissing);
        Coins immature = coins_3200600();
        immature[in2].coinbase = true;
        immature[in2].height = xf::kHeight3200601 - 50;
        EXPECT_EQ(check_3200601(G3200601{}, state_3200600(), immature), mx::kImportedInputImmature);
        Coins hogaddr = coins_3200600();
        hogaddr[in2].scriptPubKey = tx_from_hex(tf::kBlock3200601HogexHex).vout[0].scriptPubKey;
        EXPECT_EQ(check_3200601(G3200601{}, state_3200600(), hogaddr), mx::kImportedInputHogaddr);
        Coins short_in = coins_3200600();
        short_in[in2].value -= 10'000;
        EXPECT_EQ(check_3200601(G3200601{}, state_3200600(), short_in), mx::kImportedInputsBelowOutputs);
    }
    // 5. A txo count that is not the parent's plus the body's outputs.
    {
        G3200601 g;
        g.mweb.header.output_mmr_size += 1;
        commit(g.hogex, g.mweb.header);
        EXPECT_EQ(check_3200601(g), mx::kTxoCountMismatch);
    }
}

// The parse refuses what litecoind never sends, before any check.
TEST(LtcMwebExtImport, ParseRefusesMalformedTemplates)
{
    auto reason = [](const nlohmann::json& g) {
        auto r = mx::parse_extension(g);
        return r.bundle ? std::string("ok") : r.reason;
    };
    G3200601 base;
    EXPECT_EQ(reason(base.json()), "ok");
    EXPECT_EQ(reason(nlohmann::json::array()), mx::kGMalformed);
    {
        auto g = base.json();
        g["previousblockhash"] = "zz";
        EXPECT_EQ(reason(g), mx::kGMalformed);
    }
    {
        auto g = base.json();
        g.erase("mweb");
        EXPECT_EQ(reason(g), mx::kNoMweb);
        // As litecoind answers on a chain without MWEB: no mweb, no tx.
        g["transactions"] = nlohmann::json::array();
        EXPECT_EQ(reason(g), mx::kNoMweb);
        auto h = base.json();
        h["transactions"] = nlohmann::json::array();
        EXPECT_EQ(reason(h), mx::kGMalformed);
    }
    {
        auto g = base.json();
        g["transactions"][1]["txid"] = std::string(64, '0');
        EXPECT_EQ(reason(g), mx::kTxidMismatch);
    }
    {
        auto g = base.json();
        g["transactions"][1]["hash"] = std::string(64, '0');
        EXPECT_EQ(reason(g), mx::kWtxidMismatch);
    }
    {
        auto g = base.json();
        g["transactions"][1]["fee"] = -1;
        EXPECT_EQ(reason(g), mx::kGMalformed);
    }
    {
        // The HogEx not last; nothing but canonical txs.
        auto g = base.json();
        std::swap(g["transactions"][1], g["transactions"][2]);
        EXPECT_EQ(reason(g), mx::kHogexNotLast);
        auto h = base.json();
        h["transactions"].erase(h["transactions"].size() - 1);
        EXPECT_EQ(reason(h), mx::kHogexNotLast);
    }
    {
        // An entry with its mw::Transaction attached (litecoind strips it).
        auto g = base.json();
        g["transactions"][1]["data"] = tf::kPeginTxHex;
        g["transactions"][1]["txid"] = tf::kPeginTxid;
        EXPECT_EQ(reason(g), mx::kEntryCarriesMwebData);
    }
    {
        // A byte after the mw::Block; a truncated one.
        auto g = base.json();
        g["mweb"] = g["mweb"].get<std::string>() + "00";
        EXPECT_EQ(reason(g), mx::kMwebBodyMalformed);
        auto h = base.json();
        h["mweb"] = h["mweb"].get<std::string>().substr(0, 400);
        EXPECT_EQ(reason(h), mx::kMwebBodyMalformed);
    }
    {
        // depends out of range (a parent after its child).
        auto g = base.json();
        g["transactions"][1]["depends"] = nlohmann::json::array({3});
        EXPECT_EQ(reason(g), mx::kGMalformed);
    }
}

// 3200603 on the state of 3200602, derived from the real block 3200601:
// 3200602 had an empty body (no kernel; its HogAddr value and txo count are
// 3200601's), so its HogEx is the one c2pool builds from 3200601's state --
// and that is the txid 3200603's HogEx spends. Every check then passes on
// real values: the peg-out, the HogAddr value 44658862062751, the txo count
// 381307 + 2.
TEST(LtcMwebExtImport, Block3200603OnTheStateDerivedFrom3200601)
{
    MWEBTracker tracker;
    const BlockType b601 = state_block(xf::kHeader3200601Hex, tf::kBlock3200601HogexHex, tf::kBlock3200601MwebRawHex);
    ASSERT_TRUE(tracker.update(b601, xf::kHeight3200601, b601.m_mweb_raw));
    const MWEBState s601 = *tracker.get_state();
    ASSERT_EQ(s601.captured_block_hash.GetHex(), xf::kHash3200601);

    MWEBState s602 = s601;
    const auto hogex602 = MWEBBuilder::build_hogex(s601, xf::kHeight3200601 + 1);
    s602.prev_hogex_txid = MWEBBuilder::compute_hogex_txid(hogex602);
    EXPECT_EQ(s602.prev_hogex_txid.GetHex(), xf::kHogexTxid3200602)
        << "c2pool's empty-body HogEx for 3200602 is litecoind's";
    s602.hogaddr_value = hogex602.vout[0].value;
    s602.prev_header = MWEBBuilder::next_empty_header(s601.prev_header, xf::kHeight3200601 + 1);
    s602.captured_at_height = xf::kHeight3200601 + 1;
    s602.captured_block_hash = u256(xf::kHash3200602);

    auto g = make_g(u256(xf::kHash3200602), xf::kHeight3200603,
                    kSubsidy + xf::kKernelFees3200603,
                    {{tf::kBlock3200603HogexHex, xf::kKernelFees3200603, {}, {}, {}}},
                    tf::kBlock3200603MwebRawHex);
    auto x = parse_ok(g);
    ASSERT_TRUE(x);
    EXPECT_EQ(x->hogex.txid.GetHex(), tf::kBlock3200603HogexTxid);
    EXPECT_EQ(x->body.n_inputs, 6u);
    EXPECT_EQ(x->body.n_outputs, 2u);
    EXPECT_EQ(x->header.output_mmr_size, 381309u);
    auto f = mx::check_extension(*x, s602, u256(xf::kHash3200602), xf::kHeight3200601 + 1, kSubsidy, {});
    EXPECT_FALSE(f) << f->reason << ": " << f->detail;
    EXPECT_EQ(x->hogex_tx.vout[0].value, tf::kBlock3200603HogaddrValue);
    EXPECT_EQ(s602.hogaddr_value - xf::kPegout3200603 - xf::kKernelFees3200603, tf::kBlock3200603HogaddrValue);

    // The same G on 3200601's state (one block too early) is refused.
    auto early = mx::check_extension(*x, s601, u256(xf::kHash3200602), xf::kHeight3200601 + 1, kSubsidy, {});
    ASSERT_TRUE(early);
    EXPECT_EQ(early->reason, mx::kStateNotForTip);
}

// A peg-in whose input is another tx of the template: both are imported,
// parent first; an unrelated tx after them is not.
TEST(LtcMwebExtImport, PeginAncestorsShipWithIt)
{
    // P funds the peg-in; the peg-in pays the same pegin output as 3200601's.
    const MutableTransaction p = spend(fund(9), 0, 600'000'000, 9);
    MutableTransaction pegin = spend(compute_txid(p), 0, 0, 10);
    pegin.vout[0] = tx_from_hex(xf::kPeginTx3200601Hex).vout[0];
    MutableTransaction hogex = tx_from_hex(tf::kBlock3200601HogexHex);
    hogex.vin[1].prevout.hash = compute_txid(pegin);
    const Mweb m = split_mweb(tf::kBlock3200601MwebRawHex);
    const int64_t pegin_fee = 600'000'000 - xf::kPegin3200601 + xf::kPeginKernelFee3200601;
    auto g = make_g(u256(xf::kHash3200600), xf::kHeight3200601,
                    kSubsidy + 500 + pegin_fee + 15000 + xf::kPegoutKernelFee3200601,
                    {{tx_hex(p), 500, {}, {}, {}},
                     {unrelated_tx(), 15000, {}, {}, {}},
                     {tx_hex(pegin), pegin_fee, {1}, {}, {}},
                     {hogex_hex(hogex), xf::kPegoutKernelFee3200601, {}, {}, {}}},
                    mweb_hex(m.header, m.body));
    auto x = parse_ok(g);
    ASSERT_TRUE(x);
    ASSERT_EQ(x->txs.size(), 2u);
    EXPECT_EQ(x->txs[0].txid, compute_txid(p)) << "the parent first";
    EXPECT_FALSE(x->txs[0].pegin);
    EXPECT_EQ(x->txs[1].txid, compute_txid(pegin));
    EXPECT_TRUE(x->txs[1].pegin);
    EXPECT_EQ(x->txids.count(compute_txid(p)), 1u);
    EXPECT_EQ(x->spent.count({fund(9), 0}), 1u);
    EXPECT_EQ(x->spent.count({compute_txid(p), 0}), 1u);
    EXPECT_EQ(x->txs_fee(), 500 + pegin_fee);
    const Coins coins = {{{fund(9), 0}, coin_of_value(600'000'500)}};
    EXPECT_FALSE(mx::check_extension(*x, state_3200600(), u256(xf::kHash3200600), xf::kHeight3200601 - 1, kSubsidy,
                                     lookup(coins)));

    // The same G with the peg-in BEFORE its parent and no "depends": the
    // parent is still imported (the peg-in spends it), and first.
    auto swapped = make_g(u256(xf::kHash3200600), xf::kHeight3200601,
                          kSubsidy + 500 + pegin_fee + 15000 + xf::kPegoutKernelFee3200601,
                          {{tx_hex(pegin), pegin_fee, {}, {}, {}},
                           {unrelated_tx(), 15000, {}, {}, {}},
                           {tx_hex(p), 500, {}, {}, {}},
                           {hogex_hex(hogex), xf::kPegoutKernelFee3200601, {}, {}, {}}},
                          mweb_hex(m.header, m.body));
    auto y = parse_ok(swapped);
    ASSERT_TRUE(y);
    ASSERT_EQ(y->txs.size(), 2u);
    EXPECT_EQ(y->txs[0].txid, compute_txid(p)) << "parents first, whatever G's order";
    EXPECT_EQ(y->txs[1].txid, compute_txid(pegin));
    EXPECT_FALSE(mx::check_extension(*y, state_3200600(), u256(xf::kHash3200600), xf::kHeight3200601 - 1, kSubsidy,
                                     lookup(coins)));
    // Without the view's coin for P's input the import is refused.
    auto f = mx::check_extension(*y, state_3200600(), u256(xf::kHash3200600), xf::kHeight3200601 - 1, kSubsidy, {});
    ASSERT_TRUE(f);
    EXPECT_EQ(f->reason, mx::kImportedInputMissing);
    // A tx listed twice is malformed.
    auto twice = make_g(u256(xf::kHash3200600), xf::kHeight3200601,
                        kSubsidy + 1000 + pegin_fee + xf::kPegoutKernelFee3200601,
                        {{tx_hex(p), 500, {}, {}, {}},
                         {tx_hex(p), 500, {}, {}, {}},
                         {tx_hex(pegin), pegin_fee, {1}, {}, {}},
                         {hogex_hex(hogex), xf::kPegoutKernelFee3200601, {}, {}, {}}},
                        mweb_hex(m.header, m.body));
    EXPECT_EQ(mx::parse_extension(twice).reason, mx::kGMalformed);
}

// ─── the source and its /local_stats block ──────────────────────────────────

TEST(LtcMwebExtImport, SourceCountersAndLocalStats)
{
    {
        mx::MwebExtSource none;
        EXPECT_FALSE(none.enabled());
        const auto j = none.to_json();
        EXPECT_EQ(j["mode"], "none");
        EXPECT_EQ(j["imported_txs"], 0);
        EXPECT_EQ(j["imported_kernels"], 0);
        EXPECT_EQ(j["imported_fee_sat"], 0);
        EXPECT_TRUE(j["fallback"].is_object() && j["fallback"].empty());
        EXPECT_TRUE(j["g_age_ms"].is_null());
    }
    mx::MwebExtSource src("litecoind");
    EXPECT_TRUE(src.enabled());
    auto cur = src.current();
    EXPECT_FALSE(cur.bundle);
    EXPECT_EQ(cur.reason, mx::kUnavailable);

    const auto t0 = mx::MwebExtSource::clock::now();
    src.note_fetch(true, false, 12, "");
    G3200601 g;
    src.set_parsed(mx::parse_extension(g.json()), t0);
    cur = src.current(t0 + std::chrono::milliseconds(1500));
    ASSERT_TRUE(cur.bundle);
    EXPECT_EQ(cur.age_ms, 1500);

    mx::Outcome imp;
    imp.kind = mx::Outcome::imported;
    imp.txs = 1;
    imp.pegins = 1;
    imp.kernels = 2;
    imp.fee_sat = 6520;
    imp.g_age_ms = 1500;
    src.note(3200601, imp);
    auto j = src.to_json(t0 + std::chrono::milliseconds(2000));
    EXPECT_EQ(j["mode"], "litecoind");
    EXPECT_EQ(j["imported_txs"], 1);
    EXPECT_EQ(j["imported_pegins"], 1);
    EXPECT_EQ(j["imported_kernels"], 2);
    EXPECT_EQ(j["imported_fee_sat"], 6520);
    EXPECT_EQ(j["g_age_ms"], 2000);
    EXPECT_EQ(j["last"]["outcome"], "imported");
    EXPECT_EQ(j["g"]["kernels"], 2);
    EXPECT_EQ(j["fetch"]["ok"], 1);

    mx::Outcome fb;
    fb.kind = mx::Outcome::fallback;
    fb.reason = mx::kHogaddrValueMismatch;
    src.note(3200602, fb);
    src.note(3200602, fb);  // one WARNING for the height, two counts
    fb.reason = mx::kPrevMismatch;
    src.note(3200603, fb);
    src.note_fetch(false, true, 3000, "no answer");
    j = src.to_json();
    EXPECT_EQ(j["imported_txs"], 0) << "the last template did not import";
    EXPECT_EQ(j["fallback"][mx::kHogaddrValueMismatch], 2);
    EXPECT_EQ(j["fallback"][mx::kPrevMismatch], 1);
    EXPECT_EQ(j["templates_imported"], 1);
    EXPECT_EQ(j["totals"]["fee_sat"], 6520);
    EXPECT_EQ(j["fetch"]["timeouts"], 1);
    EXPECT_EQ(j["fetch"]["last_error"], "no answer");
    EXPECT_EQ(src.fallback_count(mx::kHogaddrValueMismatch), 2u);
}
