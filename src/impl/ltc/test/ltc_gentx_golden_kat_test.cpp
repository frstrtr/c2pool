// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// T5: LTC gentx golden-vector KAT -- cross-implementation differential against
// the six frozen fixtures emitted by the Python p2pool reference
// (frstrtr/p2pool-merged-v36 commit f38d6bb7, p2pool/test/gen_gentx_golden.py
// -> p2pool/test/golden/ltc_gentx_*.json, embedded verbatim in
// ltc_gentx_golden_fixtures.hpp).
//
// Fixture inputs: litecoin MAINNET net, V36 MergedMiningShare, EMPTY tracker,
// previous_share_hash=None, frozen time 1700000000, share nonce 0x5AFE5AFE,
// donation perfect_round(65535*1.0/100) with random=0 -> 655, v36_active=True,
// coinbase = push(height), synthetic non-segwit GBT tx set in GBT order.
//
// The coinbase is NOT re-implemented here. Test-side glue only maps fixture
// inputs onto the share fields; every consensus byte comes from REAL c2pool
// production code:
//   bits / max_bits      ShareTracker::compute_share_target (empty tracker)
//   donation u16         core::donation_percent_to_u16
//   txid / wtxid         ltc::coin tx (de)serializer + ltc::coin::compute_txid
//   txid_merkle_link     core::MiningInterface::compute_merkle_branches, fed to
//                        the share exactly as web_server.cpp build_cb does
//   wtxid_merkle_root    ltc::coin::compute_merkle_root([0] + wtxids)
//   mint ref_hash        ltc::compute_ref_hash_for_work (the ref_hash_fn path)
//   stripped gentx       ltc::generate_share_transaction (the verify path); its
//                        bytes are taken from the function's own dump_diag
//                        "[GENTX-DIAG] coinbase_hex=" line and cross-checked
//                        against the txid it returns
//   witness gentx        ltc::coin::MutableTransaction + TX_WITH_WITNESS with
//                        ltc::P2POOL_WITNESS_NONCE as the coinbase witness
//   hash_link resume     ltc::prefix_to_hash_link + ltc::derive_gentx_hash
//   share_info bytes     the REAL ltc::Formatter (ShareType serializer)
//
// Acceptance per fixture: byte-equal gentx_hex, gentx_txid_hex,
// share_info_packed_hex, and other_tx_hashes in GBT order. A mismatch reports
// the first differing byte offset and the field/region it falls in.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <boost/log/attributes/value_extraction.hpp>
#include <boost/log/core.hpp>
#include <boost/log/sinks/basic_sink_backend.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/smart_ptr/make_shared_object.hpp>

#include <nlohmann/json.hpp>

#include <btclibs/util/strencodings.h>

#include <core/author_fee.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>

#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/config_pool.hpp>
#include <impl/ltc/params.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_check.hpp>
#include <impl/ltc/share_tracker.hpp>

// Last: mweb_builder.hpp (via template_builder.hpp) pulls btclibs/serialize.h,
// whose READWRITE would shadow the c2pool one the share headers above expand.
#include <impl/ltc/coin/template_builder.hpp>

#include "ltc_gentx_golden_fixtures.hpp"

#include <cstring>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;

// --- generator inputs that are constants of gen_gentx_golden.py ------------
constexpr uint32_t kFrozenEpoch = 1700000000;       // FROZEN_EPOCH
constexpr uint32_t kShareNonce  = 0x5AFE5AFE;       // random.randrange(2**32) frozen
constexpr double   kDonationPct = 1.0;              // build_share_data default

Bytes to_bytes(PackStream ps)
{
    auto* p = reinterpret_cast<const unsigned char*>(ps.data());
    return Bytes(p, p + ps.size());
}

std::string hex(const Bytes& b)
{
    return HexStr(std::span<const unsigned char>(b.data(), b.size()));
}

// --- byte-diff with region labels ------------------------------------------
struct Region { size_t begin, end; std::string label; };

std::string region_of(const std::vector<Region>& regions, size_t off)
{
    for (const auto& r : regions)
        if (off >= r.begin && off < r.end)
            return r.label;
    return "<past end of expected>";
}

// "" when equal, else first differing offset + region + both bytes.
std::string byte_diff(const Bytes& got, const Bytes& exp, const std::vector<Region>& regions)
{
    if (got == exp)
        return "";
    size_t n = std::min(got.size(), exp.size());
    size_t off = 0;
    while (off < n && got[off] == exp[off])
        ++off;
    std::ostringstream os;
    os << "first diff at byte offset " << off << " (region: " << region_of(regions, off) << ")";
    auto at = [](const Bytes& b, size_t i) {
        if (i >= b.size()) return std::string("<eof>");
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", b[i]);
        return std::string(buf);
    };
    os << " c2pool=" << at(got, off) << " p2pool=" << at(exp, off)
       << " c2pool_len=" << got.size() << " p2pool_len=" << exp.size();
    return os.str();
}

// Minimal reader used ONLY to label regions of the EXPECTED bytes for diffs.
struct Cursor
{
    const Bytes& b;
    size_t pos{0};
    std::vector<Region> regions;

    uint64_t peek_varint(size_t& len) const
    {
        if (pos >= b.size()) { len = 0; return 0; }
        unsigned char c = b[pos];
        auto rd = [&](size_t n) {
            uint64_t v = 0;
            for (size_t i = 0; i < n && pos + 1 + i < b.size(); ++i)
                v |= uint64_t(b[pos + 1 + i]) << (8 * i);
            return v;
        };
        if (c < 0xfd) { len = 1; return c; }
        if (c == 0xfd) { len = 3; return rd(2); }
        if (c == 0xfe) { len = 5; return rd(4); }
        len = 9; return rd(8);
    }
    void take(size_t n, const std::string& label)
    {
        size_t end = std::min(b.size(), pos + n);
        regions.push_back({pos, end, label});
        pos = end;
    }
    uint64_t varint(const std::string& label)
    {
        size_t len = 0;
        uint64_t v = peek_varint(len);
        take(len, label);
        return v;
    }
    void varstr(const std::string& label)
    {
        uint64_t n = varint(label + ".len");
        take(static_cast<size_t>(n), label);
    }
};

std::vector<Region> tx_regions(const Bytes& b, bool witness)
{
    Cursor c{b};
    c.take(4, "tx.version");
    if (witness) c.take(2, "tx.segwit_marker_flag");
    uint64_t nin = c.varint("tx.vin_count");
    for (uint64_t i = 0; i < nin; ++i) {
        std::string p = "tx.vin[" + std::to_string(i) + "]";
        c.take(36, p + ".prevout");
        c.varstr(p + ".scriptSig(coinbase)");
        c.take(4, p + ".sequence");
    }
    uint64_t nout = c.varint("tx.vout_count");
    for (uint64_t i = 0; i < nout; ++i) {
        std::string p = "tx.vout[" + std::to_string(i) + "]";
        std::string role = (i == 0) ? " witness_commitment"
                         : (i + 1 == nout) ? " op_return_ref_hash+last_txout_nonce"
                         : (i + 2 == nout) ? " donation" : " pplns_payout";
        c.take(8, p + ".value" + role);
        c.varstr(p + ".script" + role);
    }
    if (witness) {
        for (uint64_t i = 0; i < nin; ++i) {
            uint64_t items = c.varint("tx.witness[" + std::to_string(i) + "].count");
            for (uint64_t k = 0; k < items; ++k)
                c.varstr("tx.witness[" + std::to_string(i) + "][" + std::to_string(k) + "]");
        }
    }
    c.take(4, "tx.locktime");
    return c.regions;
}

// V36 share_info_type field order (p2pool data.py MergedMiningShare).
std::vector<Region> share_info_regions(const Bytes& b)
{
    Cursor c{b};
    c.take(32, "share_data.previous_share_hash");
    c.varstr("share_data.coinbase");
    c.take(4, "share_data.nonce");
    c.take(20, "share_data.pubkey_hash");
    c.take(1, "share_data.pubkey_type");
    c.varint("share_data.subsidy");
    c.take(2, "share_data.donation");
    c.take(1, "share_data.stale_info");
    c.varint("share_data.desired_version");
    uint64_t nb = c.varint("segwit_data.txid_merkle_link.branch.len");
    c.take(static_cast<size_t>(32 * nb), "segwit_data.txid_merkle_link.branch");
    c.take(32, "segwit_data.wtxid_merkle_root");
    uint64_t nma = c.varint("merged_addresses.len");
    for (uint64_t i = 0; i < nma; ++i) {
        c.take(4, "merged_addresses[" + std::to_string(i) + "].chain_id");
        c.varstr("merged_addresses[" + std::to_string(i) + "].script");
    }
    c.take(32, "far_share_hash");
    c.take(4, "max_bits");
    c.take(4, "bits");
    c.take(4, "timestamp");
    c.take(4, "absheight");
    c.varint("abswork");
    uint64_t nmc = c.varint("merged_coinbase_info.len");
    if (nmc != 0) {
        c.take(b.size() - c.pos, "merged_coinbase_info..(unlabelled)");
        return c.regions;
    }
    c.take(32, "merged_payout_hash");
    return c.regions;
}

// --- capture of generate_share_transaction's own dump_diag coinbase bytes --
struct DiagCapture
    : boost::log::sinks::basic_sink_backend<boost::log::sinks::synchronized_feeding>
{
    std::vector<std::string> lines;
    void consume(const boost::log::record_view& rec)
    {
        if (auto m = boost::log::extract<std::string>("Message", rec))
            lines.push_back(*m);
    }
};

// Run the REAL verify-path gentx builder, return (txid, stripped coinbase bytes).
template <typename TrackerT>
std::pair<uint256, Bytes> run_generate_share_transaction(
    const ltc::MergedMiningShare& share, TrackerT& tracker, const core::CoinParams& params)
{
    using sink_t = boost::log::sinks::synchronous_sink<DiagCapture>;
    auto backend = boost::make_shared<DiagCapture>();
    auto sink = boost::make_shared<sink_t>(backend);
    boost::log::core::get()->add_sink(sink);
    uint256 txid = ltc::generate_share_transaction(share, tracker, params,
                                                   /*dump_diag=*/true, /*v36_active=*/true);
    boost::log::core::get()->remove_sink(sink);
    sink->flush();

    static const std::string kTag = "[GENTX-DIAG] coinbase_hex=";
    Bytes cb;
    for (const auto& l : backend->lines) {
        auto p = l.find(kTag);
        if (p != std::string::npos)
            cb = ParseHex(l.substr(p + kTag.size()));
    }
    return {txid, cb};
}

uint256 hash256(const Bytes& b)
{
    return Hash(std::span<const unsigned char>(b.data(), b.size()));
}

// BIP34 push(height) -- build_share_data's create_push_script([height]).
// Generator INPUT, not consensus assembly; cross-checked against the fixture.
Bytes bip34_height_push(uint64_t height)
{
    Bytes num;
    while (height) { num.push_back(height & 0xff); height >>= 8; }
    if (!num.empty() && (num.back() & 0x80)) num.push_back(0);
    Bytes out{static_cast<unsigned char>(num.size())};
    out.insert(out.end(), num.begin(), num.end());
    return out;
}

// Results table printed once at the end of the suite.
std::mutex g_rows_mu;
std::vector<std::string> g_rows;

class PoolConfigMainnet
{
public:
    PoolConfigMainnet() : saved_(ltc::PoolConfig::is_testnet) { ltc::PoolConfig::is_testnet = false; }
    ~PoolConfigMainnet() { ltc::PoolConfig::is_testnet = saved_; }
private:
    bool saved_;
};

class LTC_T5_GentxGolden : public ::testing::TestWithParam<size_t>
{
protected:
    static void TearDownTestSuite()
    {
        std::lock_guard<std::mutex> lk(g_rows_mu);
        std::cout << "\n[T5] gentx golden KAT vs p2pool-merged-v36 f38d6bb7\n";
        for (const auto& r : g_rows)
            std::cout << r << "\n";
        std::cout << std::flush;
    }
};

TEST_P(LTC_T5_GentxGolden, reproduces_p2pool_golden_byte_equal)
{
    const auto& fx = ltc_t5_golden::kFixtures[GetParam()];
    SCOPED_TRACE(fx.file);
    const auto j = nlohmann::json::parse(fx.json);
    const auto& art = j.at("artifact");

    ASSERT_EQ(j.at("net").get<std::string>(), "litecoin");
    ASSERT_EQ(j.at("share_version").get<int>(), 36);
    ASSERT_TRUE(j.at("v36_active").get<bool>());
    ASSERT_EQ(static_cast<uint32_t>(j.at("frozen_epoch").get<double>()), kFrozenEpoch);

    PoolConfigMainnet mainnet;
    const auto params = ltc::make_coin_params(/*testnet=*/false);
    ltc::ShareTracker tracker;   // deliberately EMPTY: previous_share_hash=None

    // ---- GBT tx set: parse with the LTC tx deserializer, hash in GBT order --
    const auto& gbt_txs    = j.at("gbt_transactions");
    const auto& gbt_hashes = j.at("gbt_transaction_hashes");
    ASSERT_EQ(gbt_txs.size(), gbt_hashes.size());
    std::vector<std::string> c2pool_txid_hex;   // GBT order, display hex
    std::vector<uint256> wtxids;
    for (size_t i = 0; i < gbt_txs.size(); ++i) {
        PackStream ps;
        ps.from_hex(gbt_txs[i].get<std::string>());
        ltc::coin::MutableTransaction tx;
        ps >> ltc::coin::TX_WITH_WITNESS(tx);
        const uint256 txid = ltc::coin::compute_txid(tx);
        const uint256 wtxid = hash256(to_bytes(pack(ltc::coin::TX_WITH_WITNESS(tx))));
        EXPECT_EQ(txid.GetHex(), gbt_hashes[i].get<std::string>()) << "gbt tx " << i;
        c2pool_txid_hex.push_back(txid.GetHex());
        wtxids.push_back(wtxid);
    }

    // ---- segwit_data: txid_merkle_link + wtxid_merkle_root -----------------
    // Same conversion web_server.cpp build_cb applies before ref_hash_fn.
    std::vector<uint256> branches;
    for (const auto& h : core::MiningInterface::compute_merkle_branches(c2pool_txid_hex)) {
        uint256 u;
        auto bytes = ParseHex(h);
        if (bytes.size() == 32)
            std::memcpy(u.begin(), bytes.data(), 32);
        branches.push_back(u);
    }
    std::vector<uint256> wtxid_leaves{uint256()};   // coinbase wtxid = 0
    wtxid_leaves.insert(wtxid_leaves.end(), wtxids.begin(), wtxids.end());
    const uint256 witness_root = ltc::coin::compute_merkle_root(wtxid_leaves);
    ltc::SegwitData segwit;
    segwit.m_txid_merkle_link.m_branch = branches;
    segwit.m_txid_merkle_link.m_index = 0;
    segwit.m_wtxid_merkle_root = witness_root;

    // ---- share_data inputs -------------------------------------------------
    uint160 pubkey_hash;
    pubkey_hash.SetHex(j.at("pubkey_hash").get<std::string>());   // IntType(160)
    const uint8_t pubkey_type = j.at("pubkey_type").get<uint8_t>();
    const uint64_t subsidy = j.at("subsidy").get<uint64_t>();
    const Bytes coinbase = bip34_height_push(j.at("height").get<uint64_t>());
    EXPECT_EQ(hex(coinbase),
              art.at("share_info").at("share_data").at("coinbase").at("__hex__").get<std::string>())
        << "generator coinbase input (push(height)) not reproduced";
    const uint16_t donation = core::donation_percent_to_u16(kDonationPct);

    uint256 block_target, desired_target;
    block_target.SetHex(j.at("block_target_hex").get<std::string>());
    desired_target.SetHex(j.at("desired_target_hex").get<std::string>());

    // ---- share target + genesis chain position (empty tracker) -------------
    auto [max_bits, bits] = tracker.compute_share_target(uint256(), kFrozenEpoch, desired_target);
    const uint32_t absheight = 1;   // (None -> 0) + 1, as create_local_share / ref_hash_fn
    const uint128 abswork(chain::target_to_average_attempts(chain::bits_to_target(bits)).GetLow64());

    // ---- mint path ref_hash (ref_hash_fn -> compute_ref_hash_for_work) -----
    ltc::RefHashParams rp;
    rp.share_version = 36;
    rp.prev_share = uint256();
    rp.coinbase_scriptSig = coinbase;
    rp.share_nonce = kShareNonce;
    rp.pubkey_hash = pubkey_hash;
    rp.pubkey_type = pubkey_type;
    rp.subsidy = subsidy;
    rp.donation = donation;
    rp.stale_info = 0;
    rp.desired_version = 36;
    rp.has_segwit = true;
    rp.segwit_data = segwit;
    rp.far_share_hash = uint256();
    rp.max_bits = max_bits;
    rp.bits = bits;
    rp.timestamp = kFrozenEpoch;
    rp.absheight = absheight;
    rp.abswork = abswork;
    const uint256 mint_ref_hash = ltc::compute_ref_hash_for_work(rp, params).first;

    // ---- the share object (verify path input) ------------------------------
    ltc::MergedMiningShare share;
    share.m_min_header.m_version = 0x20000000;
    share.m_min_header.m_timestamp = kFrozenEpoch;
    share.m_min_header.m_bits = chain::target_to_bits_upper_bound(block_target);
    share.m_min_header.m_nonce = 0;
    share.m_prev_hash = uint256();
    share.m_coinbase.m_data = coinbase;
    share.m_nonce = kShareNonce;
    share.m_pubkey_hash = pubkey_hash;
    share.m_pubkey_type = pubkey_type;
    share.m_subsidy = subsidy;
    share.m_donation = donation;
    share.m_stale_info = ltc::StaleInfo::none;
    share.m_desired_version = 36;
    share.m_segwit_data = segwit;
    share.m_far_share_hash = uint256();
    share.m_max_bits = max_bits;
    share.m_bits = bits;
    share.m_timestamp = kFrozenEpoch;
    share.m_absheight = absheight;
    share.m_abswork = abswork;
    share.m_ref_merkle_link.m_branch.clear();
    share.m_ref_merkle_link.m_index = 0;
    share.m_last_txout_nonce = 0;   // generate_transaction(last_txout_nonce=0)
    share.m_merkle_link.m_branch.clear();
    share.m_merkle_link.m_index = 0;

    // ---- stripped gentx: the REAL verify-path builder ----------------------
    auto [gst_txid, stripped] = run_generate_share_transaction(share, tracker, params);
    ASSERT_FALSE(stripped.empty()) << "no [GENTX-DIAG] coinbase_hex line captured";
    EXPECT_EQ(hash256(stripped), gst_txid) << "captured bytes do not hash to the returned txid";

    const Bytes exp_stripped = ParseHex(art.at("gentx_txid_hex").get<std::string>());
    const std::string d_txid = byte_diff(stripped, exp_stripped, tx_regions(exp_stripped, false));
    EXPECT_EQ(d_txid, "") << "gentx_txid_hex: " << d_txid;
    EXPECT_EQ(gst_txid, hash256(exp_stripped)) << "gentx txid";

    // mint ref_hash == verify ref_hash == the 32 bytes in the OP_RETURN
    ASSERT_GT(stripped.size(), size_t(44));
    uint256 op_return_ref;
    std::memcpy(op_return_ref.begin(), stripped.data() + stripped.size() - 44, 32);
    EXPECT_EQ(op_return_ref, mint_ref_hash) << "mint ref_hash != verify-path OP_RETURN ref_hash";

    // ---- witness gentx: LTC tx serializer + coinbase witness nonce ---------
    Bytes witness_gentx;
    {
        PackStream ps(stripped);
        ltc::coin::MutableTransaction tx;
        ps >> ltc::coin::TX_NO_WITNESS(tx);
        ASSERT_EQ(tx.vin.size(), size_t(1));
        tx.vin[0].scriptWitness.stack.assign(
            1, Bytes(ltc::P2POOL_WITNESS_NONCE, ltc::P2POOL_WITNESS_NONCE + 32));
        witness_gentx = to_bytes(pack(ltc::coin::TX_WITH_WITNESS(tx)));
    }
    const Bytes exp_gentx = ParseHex(art.at("gentx_hex").get<std::string>());
    const std::string d_gentx = byte_diff(witness_gentx, exp_gentx, tx_regions(exp_gentx, true));
    EXPECT_EQ(d_gentx, "") << "gentx_hex: " << d_gentx;

    // ---- hash_link (as create_local_share derives it) + resume path --------
    {
        Bytes prefix(stripped.begin(), stripped.end() - 44);
        share.m_hash_link = ltc::prefix_to_hash_link(
            prefix, ltc::compute_gentx_before_refhash(36, params));
        EXPECT_EQ(ltc::derive_gentx_hash(share, params), gst_txid)
            << "hash_link resume (derive_gentx_hash) disagrees with generate_share_transaction";
    }

    // ---- share_info bytes: the REAL share Formatter ------------------------
    Bytes share_info;
    {
        ltc::ShareType variant;
        variant = &share;   // borrowed; never destroy()ed
        const Bytes packed = to_bytes(pack(variant));
        const Bytes head = to_bytes(pack(share.m_min_header));
        PackStream tail_ps;
        tail_ps << share.m_ref_merkle_link.m_branch;   // MERKLE_LINK_SMALL
        tail_ps << share.m_last_txout_nonce;
        tail_ps << share.m_hash_link;
        tail_ps << share.m_merkle_link.m_branch;       // MERKLE_LINK_SMALL
        tail_ps << share.m_message_data;
        const Bytes tail = to_bytes(tail_ps);
        ASSERT_GE(packed.size(), head.size() + tail.size());
        ASSERT_TRUE(std::equal(head.begin(), head.end(), packed.begin()));
        ASSERT_TRUE(std::equal(tail.begin(), tail.end(), packed.end() - tail.size()));
        share_info.assign(packed.begin() + head.size(), packed.end() - tail.size());

        // Round trip: the packed share re-loads and re-derives the same gentx.
        PackStream rs(packed);
        auto loaded = ltc::load_share(36, rs, NetService{"0.0.0.0", 0});
        loaded.ACTION({
            if constexpr (std::is_same_v<share_t, ltc::MergedMiningShare>) {
                EXPECT_EQ(ltc::generate_share_transaction(*obj, tracker, params, false, true), gst_txid)
                    << "re-loaded share derives a different gentx";
            } else {
                ADD_FAILURE() << "re-loaded share is not a MergedMiningShare";
            }
        });
        loaded.destroy();
    }
    const Bytes exp_si = ParseHex(art.at("share_info_packed_hex").get<std::string>());
    const std::string d_si = byte_diff(share_info, exp_si, share_info_regions(exp_si));
    EXPECT_EQ(d_si, "") << "share_info_packed_hex: " << d_si;

    // ---- other_tx_hashes in GBT order --------------------------------------
    std::vector<std::string> exp_other;
    for (const auto& h : art.at("other_tx_hashes"))
        exp_other.push_back(h.get<std::string>());
    std::string d_other;
    if (c2pool_txid_hex != exp_other) {
        std::ostringstream os;
        os << "c2pool n=" << c2pool_txid_hex.size() << " p2pool n=" << exp_other.size();
        for (size_t i = 0; i < std::max(c2pool_txid_hex.size(), exp_other.size()); ++i) {
            auto g = i < c2pool_txid_hex.size() ? c2pool_txid_hex[i] : "<none>";
            auto e = i < exp_other.size() ? exp_other[i] : "<none>";
            if (g != e) { os << "; first diff at index " << i << " c2pool=" << g << " p2pool=" << e; break; }
        }
        d_other = os.str();
    }
    EXPECT_EQ(d_other, "") << "other_tx_hashes: " << d_other;

    auto verdict = [](const std::string& d) { return d.empty() ? std::string("PASS") : "FAIL(" + d + ")"; };
    std::ostringstream row;
    row << "[T5] " << fx.file
        << " | gentx_hex=" << verdict(d_gentx)
        << " | gentx_txid_hex=" << verdict(d_txid)
        << " | share_info_packed_hex=" << verdict(d_si)
        << " | other_tx_hashes=" << verdict(d_other);
    std::lock_guard<std::mutex> lk(g_rows_mu);
    g_rows.push_back(row.str());
}

std::string fixture_name(const ::testing::TestParamInfo<size_t>& info)
{
    std::string n = ltc_t5_golden::kFixtures[info.param].file;   // ltc_gentx_<scen>_difftest_<user>.json
    n = n.substr(std::strlen("ltc_gentx_"));
    n = n.substr(0, n.size() - std::strlen(".json"));
    for (auto& ch : n)
        if (!std::isalnum(static_cast<unsigned char>(ch))) ch = '_';
    return n;
}

INSTANTIATE_TEST_SUITE_P(
    P2poolMergedV36_f38d6bb7, LTC_T5_GentxGolden,
    ::testing::Range(size_t(0), std::size(ltc_t5_golden::kFixtures)),
    fixture_name);

} // namespace
