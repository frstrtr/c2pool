// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/web_server.hpp>
#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/target_utils.hpp>
#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>
#include <core/coin/mweb_shape.hpp>
#include <impl/ltc/coin/block.hpp>
#include <btclibs/util/strencodings.h>
#include <crypto/scrypt.h>

// ---------------------------------------------------------------------------
// KATs for the LTC MWEB block shape on the shared-core submit path
// (core::MiningInterface). Release gate: a python p2pool node lost LTC
// mainnet blocks because the HogEx was dropped and litecoind rejected them
// with "mweb-missing".
//
// Positive: a share that meets the block target, mined on a job whose tx set
// ends with the HogEx and which carries mweb data M, reaches the daemon as
// header | coinbase | tx1 | HogEx | "01" M — the block parses with the HogEx
// last and M as the extension block, and the P2P relay gets the same bytes.
//
// Negatives (choke 1, block assembly): mweb without a trailing HogEx (N1) and
// a HogEx without mweb (N2) never reach the daemon. Both shares still reach
// the merged-mining check (DOGE aux validity needs only the header).
//
// Template ingress (choke 2): a template failing the shape check is refused
// with HOLD semantics — the previous template stays, m_work_valid is not
// touched, the refusal is counted.
// ---------------------------------------------------------------------------

namespace {

using core::MiningInterface;

struct MockCoinNode : public core::coin::ICoinNode {
    nlohmann::json work_data;
    bool           accept          = true;
    bool           throw_on_submit = false;
    bool           throw_hold      = false;  // coin-side MWEB refusal
    bool           throw_failure   = false;  // any other template failure
    int            submit_calls    = 0;
    std::string    last_submitted_hex;

    core::coin::WorkView get_work_view() override {
        if (throw_hold)
            throw core::coin::MwebTemplateHold("mock: MWEB state not bootstrapped");
        if (throw_failure)
            throw std::runtime_error("mock: chain not synced");
        core::coin::WorkView v;
        v.m_data = work_data;
        return v;
    }
    bool submit_block_hex(const std::string& block_hex, bool /*ignore_failure*/) override {
        ++submit_calls;
        last_submitted_hex = block_hex;
        if (throw_on_submit) throw std::runtime_error("coin RPC unreachable");
        return accept;
    }
    bool is_embedded() const override { return false; }
    bool has_rpc()     const override { return true; }
};

std::string rep(const std::string& unit, int n)
{
    std::string s;
    for (int i = 0; i < n; ++i) s += unit;
    return s;
}

// M: the serialized MWEB block (opaque to the assembler; any even-length hex).
const std::string kMweb = rep("ab", 64);

// tx1: 1-in/1-out legacy transaction.
const std::string kTx1 =
    "01000000" "01" + rep("11", 32) + "00000000" "00" "ffffffff"
    "01" "00e1f50500000000" "00" "00000000";

// Minimal HogEx, byte-identical to MWEBBuilder::serialize_hogex_hex:
// version 2 | dummy 00 | flags 08 | vin | vout (HogAddr OP_8 PUSH32) |
// null mweb tx 00 | locktime.
const std::string kHogexPrevout = rep("22", 32) + "00000000";
const std::string kHogexVout =
    "01" "0010a5d4e8000000" "22" "5820" + rep("33", 32);
const std::string kHogex =
    "02000000" "00" "08" "01" + kHogexPrevout + "00" "ffffffff" + kHogexVout + "00" "00000000";
// txid serialization: no dummy/flags, no mweb tx (TX_NO_WITNESS).
const std::string kHogexStripped =
    "02000000" "01" + kHogexPrevout + "00" "ffffffff" + kHogexVout + "00000000";

const std::string kCoinb1 = "01000000" "01" + rep("00", 32) + "ffffffff" "08";
const std::string kCoinb2 = "ffffffff" "01" "00f2052a01000000" "00" "00000000";
const std::string kEn1    = "aabbccdd";
const std::string kEn2    = "00000001";
const std::string kNtime  = "5f5e1000";
const std::string kBits   = "207fffff";
const std::string kPrev   = rep("0", 62) + "ab";
constexpr uint32_t kVersion = 0x20000000u;

std::string txid_hex(const std::string& stripped_hex)
{
    auto bytes = ParseHex(stripped_hex);
    return Hash(std::span<const unsigned char>(bytes.data(), bytes.size())).GetHex();
}

std::string to_hex(const std::vector<unsigned char>& b)
{
    return HexStr(std::span<const unsigned char>(b.data(), b.size()));
}

bool ends_with(const std::string& s, const std::string& tail)
{
    return s.size() >= tail.size() && s.compare(s.size() - tail.size(), tail.size(), tail) == 0;
}

// The 80-byte header built field by field, independently of production code.
std::vector<unsigned char> test_header(uint32_t version, const std::string& prev_hex,
                                       const uint256& merkle_root, const std::string& ntime,
                                       const std::string& bits, const std::string& nonce)
{
    std::vector<unsigned char> h;
    for (int i = 0; i < 4; ++i) h.push_back(static_cast<unsigned char>(version >> (8 * i)));
    uint256 prev;
    prev.SetHex(prev_hex);
    h.insert(h.end(), prev.data(), prev.data() + 32);
    h.insert(h.end(), merkle_root.data(), merkle_root.data() + 32);
    for (const std::string* f : {&ntime, &bits, &nonce}) {
        auto b = ParseHex(*f);
        h.insert(h.end(), b.rbegin(), b.rend());
    }
    return h;
}

uint256 scrypt_hash(const std::vector<unsigned char>& header)
{
    char out[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header.data()), out);
    uint256 r;
    std::memcpy(r.begin(), out, 32);
    return r;
}

std::string nonce_hex(uint32_t n)
{
    char buf[9];
    std::snprintf(buf, sizeof(buf), "%08x", n);
    return buf;
}

// Find a nonce whose header meets the block target encoded in `bits`
// (207fffff: about one try in two). Also pins build_header_bytes against the
// independently built header.
std::string find_block_nonce(uint32_t version, const std::string& prev_hex,
                             const uint256& merkle_root, const std::string& bits,
                             std::vector<unsigned char>* header_out = nullptr)
{
    const uint256 target = chain::bits_to_target(
        static_cast<uint32_t>(std::stoul(bits, nullptr, 16)));
    for (uint32_t n = 0; n < 10000; ++n) {
        const std::string nh = nonce_hex(n);
        auto h = MiningInterface::build_header_bytes(version, prev_hex, merkle_root, kNtime, bits, nh);
        EXPECT_EQ(to_hex(h), to_hex(test_header(version, prev_hex, merkle_root, kNtime, bits, nh)));
        if (h.size() == 80 && scrypt_hash(h) <= target) {
            if (header_out) *header_out = h;
            return nh;
        }
    }
    ADD_FAILURE() << "no nonce met the block target in 10000 tries";
    return "00000000";
}

ltc::coin::BlockType parse_block(const std::string& hex)
{
    auto bytes = ParseHex(hex);
    PackStream ps(bytes);
    ltc::coin::BlockType b;
    ps >> b;
    return b;
}

// A MiningInterface wired to the mock RPC node, capturing every found-block
// fire and the P2P relay payload.
struct Fixture {
    MiningInterface   mi{/*testnet=*/true};  // Blockchain::LITECOIN
    MockCoinNode      node;
    std::vector<int>  fires;
    std::string       relay_hex;
    int               relay_calls = 0;

    Fixture() {
        mi.set_coin_node(&node);
        mi.set_on_block_submitted(
            [this](const std::string&, int stale_info) { fires.push_back(stale_info); });
        mi.set_on_block_relay(
            [this](const std::string& hex) { ++relay_calls; relay_hex = hex; });
    }
};

// A job frozen over `txs` / `mweb`, plus the nonce that solves it.
struct Job {
    MiningInterface::JobSnapshot snap;
    std::string nonce;
    std::vector<unsigned char> header;
};

Job make_job(const std::vector<std::string>& txs, const std::vector<std::string>& txids,
             const std::string& mweb, bool mweb_active)
{
    Job j;
    j.snap.coinb1 = kCoinb1;
    j.snap.coinb2 = kCoinb2;
    j.snap.gbt_prevhash = kPrev;
    j.snap.nbits = kBits;
    j.snap.block_nbits = kBits;
    j.snap.version = kVersion;
    j.snap.merkle_branches = MiningInterface::compute_merkle_branches(txids);
    j.snap.tx_data = std::make_shared<std::vector<std::string>>(txs);
    j.snap.mweb = mweb;
    j.snap.mweb_active = mweb_active;
    j.snap.segwit_active = true;
    const uint256 root = MiningInterface::reconstruct_merkle_root(
        kCoinb1 + kEn1 + kEn2 + kCoinb2, j.snap.merkle_branches);
    j.nonce = find_block_nonce(kVersion, kPrev, root, kBits, &j.header);
    return j;
}

nlohmann::json submit(Fixture& f, const Job& j)
{
    return f.mi.mining_submit("mweb-kat-miner", "j1", kEn1, kEn2, kNtime, j.nonce, "1", {}, &j.snap);
}

nlohmann::json mweb_template(const std::vector<std::pair<std::string, std::string>>& txs,
                             const std::string& mweb, const std::string& prev = kPrev)
{
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& [data, txid] : txs)
        arr.push_back({{"data", data}, {"txid", txid}, {"hash", txid}});
    return {
        {"previousblockhash", prev},
        {"version", kVersion},
        {"height", 100},
        {"bits", kBits},
        {"curtime", 1600000000},
        {"coinbasevalue", 5000000000LL},
        {"transactions", arr},
        {"rules", nlohmann::json::array({"csv", "!segwit", "taproot", "mweb"})},
        {"mweb", mweb},
    };
}

} // namespace

// ------------------------------ fixtures are sound -------------------------

TEST(LtcMwebHogex, FixtureHogexParsesAsHogex)
{
    auto bytes = ParseHex(kHogex);
    PackStream ps(bytes);
    ltc::coin::MutableTransaction tx;
    ps >> ltc::coin::TX_WITH_WITNESS(tx);
    EXPECT_TRUE(tx.m_hogEx);
    ASSERT_EQ(tx.vout.size(), 1u);
    EXPECT_EQ(tx.vout[0].scriptPubKey.m_data.size(), 34u);
    auto stripped = pack(ltc::coin::TX_NO_WITNESS(tx));
    EXPECT_EQ(HexStr(stripped.get_span()), kHogexStripped)
        << "txid serialization drops the dummy, the flags and the null mweb tx";
}

TEST(LtcMwebHogex, ShapePredicate)
{
    using core::coin::check_block_shape;
    using core::coin::tx_hex_is_hogex;
    EXPECT_TRUE(tx_hex_is_hogex(kHogex));
    EXPECT_FALSE(tx_hex_is_hogex(kTx1));
    EXPECT_FALSE(tx_hex_is_hogex("02000000" "0001" "01"));  // segwit marker/flag
    EXPECT_FALSE(tx_hex_is_hogex("0200"));

    const std::vector<std::string> good{kTx1, kHogex};
    const std::vector<std::string> no_hogex{kTx1};
    EXPECT_FALSE(check_block_shape(good, kMweb, true));
    EXPECT_FALSE(check_block_shape(good, kMweb, false));
    EXPECT_FALSE(check_block_shape(no_hogex, "", false))   << "pre-MWEB block";
    EXPECT_TRUE(check_block_shape(no_hogex, kMweb, true))  << "mweb without HogEx";
    EXPECT_TRUE(check_block_shape(std::vector<std::string>{}, kMweb, true)) << "mweb, no txs";
    EXPECT_TRUE(check_block_shape(good, "", true))         << "HogEx without mweb";
    EXPECT_TRUE(check_block_shape(good, "", false))        << "HogEx without mweb";
    EXPECT_TRUE(check_block_shape(no_hogex, "", true))     << "MWEB active, nothing";

    auto t = mweb_template({{kTx1, txid_hex(kTx1)}, {kHogex, txid_hex(kHogexStripped)}}, kMweb);
    EXPECT_FALSE(core::coin::check_template_shape(t));
    t["rules"] = nlohmann::json::array({"segwit", "!mweb"});
    EXPECT_TRUE(core::coin::template_rules_have_mweb(t));
    t["mweb"] = "";
    EXPECT_TRUE(core::coin::check_template_shape(t));
}

TEST(LtcMwebHogex, BuildHeaderBytesRejectsMalformedFields)
{
    uint256 root;
    EXPECT_EQ(MiningInterface::build_header_bytes(kVersion, kPrev, root, kNtime, kBits, "00000001").size(), 80u);
    EXPECT_TRUE(MiningInterface::build_header_bytes(kVersion, kPrev, root, "5f5e10", kBits, "00000001").empty());
    EXPECT_TRUE(MiningInterface::build_header_bytes(kVersion, kPrev, root, kNtime, kBits, "0001").empty());
}

// ------------------------------ positive KAT -------------------------------

TEST(LtcMwebHogex, FoundBlockCarriesHogexAndMweb)
{
    Fixture f;
    const std::string t1 = txid_hex(kTx1), th = txid_hex(kHogexStripped);
    Job j = make_job({kTx1, kHogex}, {t1, th}, kMweb, /*mweb_active=*/true);

    submit(f, j);

    ASSERT_EQ(f.node.submit_calls, 1) << "a block-target share must reach the daemon";
    const std::string& hex = f.node.last_submitted_hex;
    EXPECT_TRUE(ends_with(hex, "01" + kMweb)) << "block must end with 01 + mweb";
    EXPECT_EQ(hex.substr(0, 160), to_hex(j.header))
        << "submitted header == the header build_header_bytes produced for the PoW check";
    EXPECT_EQ(f.fires, std::vector<int>{0});

    auto b = parse_block(hex);
    ASSERT_EQ(b.m_txs.size(), 3u) << "coinbase + tx1 + HogEx";
    EXPECT_TRUE(b.m_txs.back().m_hogEx) << "HogEx must be the last tx";
    EXPECT_FALSE(b.m_txs[1].m_hogEx);
    EXPECT_EQ(HexStr(std::span<const unsigned char>(b.m_mweb_raw.data(), b.m_mweb_raw.size())), kMweb);

    EXPECT_EQ(f.relay_calls, 1);
    EXPECT_EQ(f.relay_hex, hex) << "P2P relay must carry the same bytes as submitblock";
    auto rb = parse_block(f.relay_hex);
    EXPECT_TRUE(rb.m_txs.back().m_hogEx);
    EXPECT_EQ(rb.m_mweb_raw, b.m_mweb_raw);

    EXPECT_EQ(f.mi.get_aux_checks(), 1u);
    EXPECT_EQ(f.mi.get_mweb_refusals(), 0u);
}

// Production-faithful variant: the job comes out of refresh_work() and
// build_connection_coinbase() the way the stratum server freezes it.
TEST(LtcMwebHogex, FoundBlockFromRefreshedTemplate)
{
    Fixture f;
    const std::string t1 = txid_hex(kTx1), th = txid_hex(kHogexStripped);
    f.node.work_data = mweb_template({{kTx1, t1}, {kHogex, th}}, kMweb);
    f.mi.set_ref_hash_fn([](const uint256&, const std::vector<unsigned char>&,
                            const std::vector<unsigned char>&, uint64_t, uint32_t, uint32_t,
                            bool, const std::string&, const uint256&,
                            const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>&,
                            const std::vector<uint256>&) {
        MiningInterface::RefHashResult r;
        r.ref_hash.SetHex(rep("5", 64));
        r.bits = 0x207fffff;
        return r;
    });
    f.mi.refresh_work();
    ASSERT_FALSE(f.mi.get_current_work_template().is_null());
    EXPECT_EQ(f.mi.get_cached_mweb(), kMweb);
    EXPECT_TRUE(f.mi.get_cached_mweb_active());

    const std::vector<unsigned char> payout{0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                            11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x88, 0xac};
    auto cbr = f.mi.build_connection_coinbase(uint256(), kEn1, payout, {});
    ASSERT_FALSE(cbr.coinb1.empty());
    EXPECT_EQ(cbr.snapshot.mweb, kMweb);
    EXPECT_TRUE(cbr.snapshot.mweb_active);
    ASSERT_TRUE(cbr.snapshot.tx_data);
    ASSERT_EQ(cbr.snapshot.tx_data->size(), 2u);

    MiningInterface::JobSnapshot snap;
    snap.coinb1 = cbr.coinb1;
    snap.coinb2 = cbr.coinb2;
    snap.gbt_prevhash = kPrev;
    snap.nbits = kBits;
    snap.block_nbits = kBits;
    snap.version = kVersion;
    snap.merkle_branches = cbr.snapshot.merkle_branches;
    snap.tx_data = cbr.snapshot.tx_data;
    snap.mweb = cbr.snapshot.mweb;
    snap.mweb_active = cbr.snapshot.mweb_active;
    snap.segwit_active = cbr.snapshot.segwit_active;
    const uint256 root = MiningInterface::reconstruct_merkle_root(
        snap.coinb1 + kEn1 + kEn2 + snap.coinb2, snap.merkle_branches);
    const std::string nonce = find_block_nonce(kVersion, kPrev, root, kBits);

    f.mi.mining_submit("mweb-kat-miner", "j1", kEn1, kEn2, kNtime, nonce, "1", {}, &snap);

    ASSERT_EQ(f.node.submit_calls, 1);
    EXPECT_TRUE(ends_with(f.node.last_submitted_hex, "01" + kMweb));
    auto b = parse_block(f.node.last_submitted_hex);
    ASSERT_EQ(b.m_txs.size(), 3u);
    EXPECT_TRUE(b.m_txs.back().m_hogEx);
    EXPECT_EQ(f.relay_hex, f.node.last_submitted_hex);
}

// ------------------------------ negatives (choke 1) ------------------------

// N1: mweb present, no HogEx. Master appended "01"+mweb after tx1 and
// submitted a block litecoind cannot accept.
TEST(LtcMwebHogex, N1_MwebWithoutHogexNeverSubmitted)
{
    Fixture f;
    Job j = make_job({kTx1}, {txid_hex(kTx1)}, kMweb, /*mweb_active=*/true);

    submit(f, j);

    EXPECT_EQ(f.node.submit_calls, 0) << "mweb without a trailing HogEx must not be submitted";
    EXPECT_TRUE(f.fires.empty());
    EXPECT_EQ(f.relay_calls, 0);
    EXPECT_EQ(f.mi.get_mweb_refusals(), 1u);
    EXPECT_EQ(f.mi.get_aux_checks(), 1u)
        << "the merged-mining check must still see the share (DOGE needs only the header)";
}

// N2: HogEx present, mweb empty.
TEST(LtcMwebHogex, N2_HogexWithoutMwebNeverSubmitted)
{
    Fixture f;
    Job j = make_job({kTx1, kHogex}, {txid_hex(kTx1), txid_hex(kHogexStripped)}, "",
                     /*mweb_active=*/true);

    submit(f, j);

    EXPECT_EQ(f.node.submit_calls, 0);
    EXPECT_TRUE(f.fires.empty());
    EXPECT_EQ(f.mi.get_mweb_refusals(), 1u);
    EXPECT_EQ(f.mi.get_aux_checks(), 1u);
}

// Non-MWEB chain (e.g. NMC): segwit without mweb is a valid block. Master
// refused it because the refusal was keyed on segwit.
TEST(LtcMwebHogex, SegwitWithoutMwebIsNotRefused)
{
    Fixture f;
    Job j = make_job({kTx1}, {txid_hex(kTx1)}, "", /*mweb_active=*/false);

    submit(f, j);

    EXPECT_EQ(f.node.submit_calls, 1);
    EXPECT_EQ(f.mi.get_mweb_refusals(), 0u);
}

// ------------------------------ ingress HOLD (choke 2) ---------------------

TEST(LtcMwebHogex, N3_IngressRefusalHoldsPreviousTemplate)
{
    Fixture f;
    const std::string t1 = txid_hex(kTx1), th = txid_hex(kHogexStripped);
    f.node.work_data = mweb_template({{kTx1, t1}, {kHogex, th}}, kMweb);
    f.mi.refresh_work();
    const auto good = f.mi.get_current_work_template();
    ASSERT_FALSE(good.is_null());
    EXPECT_EQ(f.mi.get_cached_mweb(), kMweb);
    EXPECT_TRUE(f.mi.get_cached_mweb_active());
    EXPECT_TRUE(f.mi.get_work_snapshot().mweb_active);
    EXPECT_EQ(f.mi.get_mweb_template_refusals(), 0u);

    const std::string new_prev = rep("0", 62) + "cd";

    // rules [segwit, mweb], mweb present, no HogEx
    f.node.work_data = mweb_template({{kTx1, t1}}, kMweb, new_prev);
    f.mi.refresh_work();
    EXPECT_EQ(f.mi.get_current_work_template(), good) << "previous template must stay (HOLD)";
    EXPECT_EQ(f.mi.get_cached_mweb(), kMweb);
    EXPECT_EQ(f.mi.get_mweb_template_refusals(), 1u);

    // rules [segwit, mweb], HogEx present, mweb empty
    f.node.work_data = mweb_template({{kTx1, t1}, {kHogex, th}}, "", new_prev);
    f.mi.refresh_work();
    EXPECT_EQ(f.mi.get_current_work_template(), good);
    EXPECT_EQ(f.mi.get_mweb_template_refusals(), 2u);

    // rules [segwit, mweb], neither
    f.node.work_data = mweb_template({{kTx1, t1}}, "", new_prev);
    f.mi.refresh_work();
    EXPECT_EQ(f.mi.get_current_work_template(), good);
    EXPECT_EQ(f.mi.get_mweb_template_refusals(), 3u);
    EXPECT_GE(f.mi.get_mweb_hold_seconds(), 0.0);

    // The next good template ends the HOLD.
    f.node.work_data = mweb_template({{kTx1, t1}, {kHogex, th}}, kMweb, new_prev);
    f.mi.refresh_work();
    EXPECT_EQ(f.mi.get_current_gbt_prevhash(), new_prev);
    EXPECT_EQ(f.mi.get_mweb_template_refusals(), 3u);
}

TEST(LtcMwebHogex, N3_IngressRefusalLeavesWorkInvalidUntouched)
{
    Fixture f;
    f.node.work_data = mweb_template({{kTx1, txid_hex(kTx1)}}, kMweb);
    f.mi.refresh_work();
    EXPECT_TRUE(f.mi.get_current_work_template().is_null())
        << "no previous template: nothing to serve, and the refused one is never cached";
    EXPECT_EQ(f.mi.get_mweb_template_refusals(), 1u);
}

// The coin-side builder's refusal (EmbeddedCoinNode::getwork) is the same
// HOLD; any other template failure still invalidates the work.
TEST(LtcMwebHogex, CoinSideHoldKeepsWorkValid)
{
    Fixture f;
    f.node.work_data = mweb_template({{kTx1, txid_hex(kTx1)}, {kHogex, txid_hex(kHogexStripped)}}, kMweb);
    f.mi.refresh_work();
    const auto good = f.mi.get_current_work_template();
    ASSERT_FALSE(good.is_null());

    f.node.throw_hold = true;
    f.mi.refresh_work();
    EXPECT_EQ(f.mi.get_current_work_template(), good) << "HOLD keeps the previous template";
    EXPECT_EQ(f.mi.get_mweb_template_refusals(), 1u);

    f.node.throw_hold = false;
    f.node.throw_failure = true;
    f.mi.refresh_work();
    EXPECT_TRUE(f.mi.get_current_work_template().is_null())
        << "a non-MWEB template failure still invalidates the work";
}

TEST(LtcMwebHogex, CountersInLocalStats)
{
    Fixture f;
    Job j = make_job({kTx1}, {txid_hex(kTx1)}, kMweb, /*mweb_active=*/true);
    submit(f, j);
    auto stats = f.mi.rest_local_stats();
    EXPECT_EQ(stats.value("aux_checks", uint64_t(0)), 1u);
    EXPECT_EQ(stats.value("mweb_refusals", uint64_t(0)), 1u);
    EXPECT_TRUE(stats.contains("mweb_template_refusals"));
    EXPECT_TRUE(stats.contains("mweb_hold_seconds"));
}
