// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// A local DGB share is credited: producer -> job -> submit -> mint round trip
// (rides dgb_work_source_test).
//
// The real producer (build_conn_job_inputs, lifted from main_dgb) builds the
// job's PPLNS inputs at the tracker's tip; the real DGBWorkSource turns them
// into coinb1/coinb2 and freezes the share fields on the job; the miner hashes
// coinb1||en1||en2||coinb2; the real mining_submit hands the mint the mined
// coinbase and the frozen fields; the real mint (mint_local_share_at_frozen_
// version -> create_local_share) records the share. Before the fix the mint
// got neither: it rebuilt the gentx without the miner's extranonce and with a
// submit-time timestamp, so the share never matched the header the miner
// hashed and nothing was credited.
// Pinned:
//   - the minted share hash IS sha256d of the miner's 80-byte header;
//   - a peer re-deriving the share's generation transaction from the share
//     (generate_share_transaction, the verifier) gets the txid of the coinbase
//     the miner hashed, and the share carries the job's frozen fields;
//   - the job classifies with the tracker's share target (frozen bits), not a
//     fallback diff-1, so a submit above it is rejected as low difficulty.
// PoW: classification uses a maximal share target here (a scrypt fixture is
// not steerable) and the mint's self-check runs with an all-zero digest
// (kat_params); everything else is the production path.
// ---------------------------------------------------------------------------

#include <impl/dgb/conn_job_producer.hpp>
#include <impl/dgb/coin/aux_doge_payout_provider.hpp>
#include "doge_backend_fixture.hpp"
#include <impl/dgb/run_loop_mint.hpp>
#include <impl/dgb/share.hpp>
#include <impl/dgb/share_check.hpp>
#include <impl/dgb/share_tracker.hpp>
#include <impl/dgb/params.hpp>
#include <impl/dgb/config_coin.hpp>
#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/stratum/work_source.hpp>

#include <core/address_utils.hpp>
#include <core/hash.hpp>
#include <core/stratum_types.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <btclibs/util/strencodings.h>
#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <ctime>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;

core::CoinParams rt_params()
{
    auto p = dgb::make_coin_params(/*testnet=*/false);
    p.pow_func = [](std::span<const unsigned char>) { return uint256(); };
    return p;
}

const core::SubsidyFunc kRtSubsidy = [](uint32_t h) -> uint64_t { return dgb::CoinParams::subsidy(h); };
constexpr uint32_t kRtBlockHeight = 20000000;

// A genesis-rooted V36 chain of `n` shares, one miner each in turn.
struct RtChain {
    dgb::ShareTracker tracker;
    uint256 tip;
    uint32_t tip_ts = 0;
    explicit RtChain(int n, uint32_t t0)
    {
        uint128 abswork;
        for (int i = 0; i < n; ++i) {
            auto* s = new dgb::MergedMiningShare();
            s->m_hash = uint256(std::vector<unsigned char>(32, static_cast<unsigned char>(0x40 + i)));
            if (i == 0)
                s->m_prev_hash.SetNull();
            else
                s->m_prev_hash = tip;
            s->m_pubkey_hash = uint160(base_uint<160>(Bytes(20, static_cast<unsigned char>(0xa1 + (i % 3)))));
            s->m_pubkey_type = 0;
            s->m_donation = 66;
            s->m_desired_version = 36;
            s->m_bits = 0x1e0fffff;
            s->m_max_bits = 0x1e0fffff;
            s->m_timestamp = t0 + 15u * static_cast<uint32_t>(i);
            s->m_min_header.m_bits = 0x1b0404cb;
            s->m_min_header.m_timestamp = s->m_timestamp;
            s->m_absheight = static_cast<uint32_t>(i + 1);
            abswork = abswork + uint128(chain::target_to_average_attempts(chain::bits_to_target(s->m_bits)).GetLow64());
            s->m_abswork = abswork;
            s->m_subsidy = dgb::CoinParams::subsidy(kRtBlockHeight - 1);
            tip = s->m_hash;
            tip_ts = s->m_timestamp;
            dgb::ShareType st;
            st = s;
            tracker.add(st);
        }
    }
};

Bytes miner_script()
{
    Bytes s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, 0xa1);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

// The miner's login (a DGB mainnet P2PKH "D...") and the job payout script the
// core stratum server builds from it (stratum_server.cpp send_notify_work:
// address_to_script(username_)); mining_submit gets the same username_.
std::string miner_login() { return core::script_to_address(miner_script(), "", 30, 63); }
Bytes stratum_payout(const std::string& login) { return core::address_to_script(login); }

struct RtRig {
    core::CoinParams params = rt_params();
    RtChain chain;
    uint32_t now = 0;   // the producer's clock; 0: 15 s after the tip
    c2pool::dgb::HeaderChain hc;
    dgb::coin::Mempool mempool;
    std::unique_ptr<dgb::stratum::DGBWorkSource> ws;
    int64_t mint_version = 36;
    std::optional<dgb::coin::ConnCoinbasePplnsInputs> last_inputs;
    dgb::stratum::DGBWorkSource::JobBlock last_block;   // what the producer was handed
    std::string tip_bits = "1b0404cb";                   // the template's block bits
    Bytes last_payout;                                   // what the producer was handed
    std::vector<std::pair<uint32_t, Bytes>> last_merged;
    uint256 minted;

    explicit RtRig(uint32_t t0 = 1795600000u) : chain(12, t0)
    {
        auto submit = [](const std::vector<unsigned char>&, uint32_t) -> bool { return false; };
        // The DGB block the jobs are for: height 20,000,000 (the coinbase's
        // BIP34 height and its subsidy), header bits 0x1b0404cb.
        hc.set_base_height(kRtBlockHeight);
        ws = std::make_unique<dgb::stratum::DGBWorkSource>(hc, mempool, false, submit, kRtSubsidy);
        ws->set_gbt_tip_fn([this]() -> std::optional<dgb::stratum::DGBWorkSource::GbtTip> {
            return dgb::stratum::DGBWorkSource::GbtTip{std::string(56, '0') + "0badf00d", tip_bits};
        });
        ws->set_pplns_inputs_fn([this](const uint256& prev, const std::string&, const Bytes& payout,
                                       const std::vector<std::pair<uint32_t, Bytes>>& merged, const Bytes& aux, const dgb::stratum::DGBWorkSource::JobBlock& block)
                                    -> std::optional<dgb::coin::ConnCoinbasePplnsInputs> {
            dgb::ConnJobRequest req;
            req.prev_share_hash = prev;
            req.payout_script = payout;
            req.merged_addrs = merged;
            req.next_block_height = block.height;   // main_dgb's producer
            req.block_bits = block.bits;
            req.block_value = block.value;
            last_block = block;
            req.now = now ? now : chain.tip_ts + 15;
            req.donation = 66;
            req.aux_mm_scriptsig = aux;
            last_payout = payout;
            last_merged = merged;
            last_inputs = dgb::build_conn_job_inputs(chain.tracker, params, req, [this]() {
                return std::pair<int64_t, uint64_t>{mint_version, 36};
            });
            return last_inputs;
        });
        // main_dgb's mint closure: parse the header, mint at the job's frozen fields.
        ws->set_mint_share_fn([this](const dgb::stratum::DGBWorkSource::MintShareInputs& in) -> uint256 {
            auto hdr = dgb::parse_min_header_80(in.header_bytes);
            if (!hdr)
                return uint256();
            minted = dgb::mint_local_share_at_frozen_version(in, *hdr, chain.tracker, params, 66);
            return minted;
        });
    }

    // The job core::StratumServer would freeze from this coinbase result
    // (with `payout`: the payout the stratum server committed the job to).
    core::stratum::JobSnapshot job(const core::stratum::CoinbaseResult& cbr, uint32_t share_bits,
                                   const Bytes* payout = nullptr)
    {
        core::stratum::JobSnapshot j;
        if (payout) {
            j.has_payout = true;
            j.payout_script = *payout;
        }
        j.coinb1 = cbr.coinb1;
        j.coinb2 = cbr.coinb2;
        // The header the job carries: the coinbase's own template
        // (snapshot.has_header), as core::StratumServer takes it.
        EXPECT_TRUE(cbr.snapshot.has_header);
        j.gbt_prevhash = cbr.snapshot.gbt_prevhash;
        j.nbits = cbr.snapshot.block_nbits_hex;   // the header's block bits
        j.version = cbr.snapshot.header_version;
        j.share_bits = share_bits;
        j.block_nbits = "03000001";     // no digest is a block: ShareAccept, never WonBlock
        j.prev_share_hash = chain.tip;
        j.subsidy = cbr.snapshot.subsidy;
        j.frozen_ref = cbr.snapshot.frozen_ref;
        return j;
    }
};

// The 80-byte header the miner hashed (same assembly as mining_submit).
Bytes miner_header(const core::stratum::JobSnapshot& j, const std::string& en1, const std::string& en2,
                   const std::string& ntime, const std::string& nonce, Bytes* coinbase_out)
{
    Bytes cb = ParseHex(j.coinb1 + en1 + en2 + j.coinb2);
    if (coinbase_out)
        *coinbase_out = cb;
    uint256 txid = Hash(std::span<const unsigned char>(cb.data(), cb.size()));
    Bytes h;
    auto u32 = [&h](uint32_t v) { for (int i = 0; i < 4; ++i) h.push_back(static_cast<unsigned char>(v >> (8 * i))); };
    auto be = [](const std::string& s) { return static_cast<uint32_t>(std::stoul(s, nullptr, 16)); };
    u32(j.version);
    auto prev_be = ParseHex(j.gbt_prevhash);
    h.insert(h.end(), prev_be.rbegin(), prev_be.rend());
    h.insert(h.end(), txid.data(), txid.data() + 32);
    u32(be(ntime));
    u32(be(j.nbits));
    u32(be(nonce));
    return h;
}

} // namespace

TEST(DgbMintRoundTrip, JobClassifiesWithTheTrackerShareTarget)
{
    RtRig rig;
    ASSERT_EQ(stratum_payout(miner_login()), miner_script());
    auto cbr = rig.ws->build_connection_coinbase(rig.chain.tip, "cafef00d", stratum_payout(miner_login()), {});
    ASSERT_FALSE(cbr.held);
    ASSERT_FALSE(cbr.coinb1.empty());
    ASSERT_TRUE(rig.last_inputs.has_value());
    // The job freezes the producer's share bits, which are the tracker's
    // share target for the next share at the job's timestamp.
    const auto st = rig.chain.tracker.compute_share_target(
        rig.chain.tip, rig.last_inputs->frozen_timestamp, chain::bits_to_target(0x1b0404cb), rig.mint_version);
    EXPECT_EQ(cbr.snapshot.frozen_ref.bits, st.bits);
    EXPECT_EQ(cbr.snapshot.frozen_ref.max_bits, st.max_bits);
    EXPECT_NE(cbr.snapshot.frozen_ref.bits, 0u) << "a job without frozen bits classifies at diff-1";
    EXPECT_EQ(core::stratum::pool_share_bits(cbr.snapshot.frozen_ref.bits, rig.ws->get_share_bits()), st.bits);

    // At that target a submit whose digest is above it is low difficulty: no mint.
    auto j = rig.job(cbr, core::stratum::pool_share_bits(cbr.snapshot.frozen_ref.bits, 0));
    int rejected = 0;
    for (uint32_t n = 0; n < 4 && rejected == 0; ++n) {
        char nonce[9];
        std::snprintf(nonce, sizeof nonce, "%08x", n);
        auto r = rig.ws->mining_submit(miner_login(), "job", "00000001", "00000002", "6a1b2c3d", nonce, "rid", {}, &j);
        if (r.is_array() && !r.empty() && r[0].is_boolean() && !r[0].get<bool>())
            ++rejected;
    }
    EXPECT_GT(rejected, 0) << "a digest above the real share target was accepted";
    EXPECT_TRUE(rig.minted.IsNull());
}

TEST(DgbMintRoundTrip, MintedShareIsTheHeaderTheMinerHashed)
{
    for (int64_t ver : {int64_t(35), int64_t(36)}) {
        SCOPED_TRACE(ver);
        RtRig rig;
        rig.mint_version = ver;
        auto cbr = rig.ws->build_connection_coinbase(rig.chain.tip, "cafef00d", stratum_payout(miner_login()), {});
        ASSERT_FALSE(cbr.held);
        ASSERT_FALSE(cbr.coinb1.empty());
        EXPECT_EQ(cbr.snapshot.frozen_ref.share_version, ver);

        // Classified as a share (maximal share target; no scrypt fixture).
        auto j = rig.job(cbr, 0x2100ffffu);
        const std::string en1 = "cafef00d", en2 = "0000002a", ntime = "6a1b2c3d", nonce = "00c0ffee";
        Bytes coinbase;
        const Bytes header = miner_header(j, en1, en2, ntime, nonce, &coinbase);
        auto r = rig.ws->mining_submit(miner_login(), "job", en1, en2, ntime, nonce, "rid", {}, &j);
        ASSERT_TRUE(r.is_boolean() && r.get<bool>()) << r.dump();

        // The minted share IS the header the miner hashed.
        ASSERT_FALSE(rig.minted.IsNull()) << "the local share was not credited";
        const uint256 header_hash = Hash(std::span<const unsigned char>(header.data(), header.size()));
        EXPECT_EQ(rig.minted, header_hash);
        ASSERT_TRUE(rig.chain.tracker.chain.contains(rig.minted));

        // A peer re-derives the generation transaction from the share alone and
        // gets the coinbase the miner hashed; the share carries the job's frozen
        // fields.
        const uint256 cb_txid = Hash(std::span<const unsigned char>(coinbase.data(), coinbase.size()));
        rig.chain.tracker.chain.get(rig.minted).share.invoke([&](auto* s) {
            EXPECT_EQ(s->m_prev_hash, rig.chain.tip);
            EXPECT_EQ(s->m_timestamp, j.frozen_ref.timestamp);
            EXPECT_EQ(s->m_bits, j.frozen_ref.bits);
            EXPECT_EQ(s->m_max_bits, j.frozen_ref.max_bits);
            EXPECT_EQ(s->m_absheight, j.frozen_ref.absheight);
            EXPECT_EQ(s->m_far_share_hash, j.frozen_ref.far_share_hash);
            const uint256 expect_txid = dgb::generate_share_transaction(
                *s, rig.chain.tracker, rig.params, false, core::version_gate::is_v36_active(ver));
            EXPECT_EQ(expect_txid, cb_txid) << "a peer would reject this share (gentx mismatch)";
        });
    }
}

// The pre-fix mint (no mined coinbase, no frozen fields: has_frozen=false) on
// the same submit: the share it records is not the header the miner hashed.
// Review 713dc77a0 R2 + #9: the job's coinbase claims the subsidy of the BLOCK
// it is for (the template's height), and the PPLNS walk takes that block's
// bits (the share's own header bits, which the verifier and p2pool
// generate_transaction read). Before, the value was subsidy(share absheight)
// (a share height ~20M below the block's: 72,000 DGB claimed on a block worth
// far less, every won block bad-cb-amount) and the walk used the PREV share's
// header bits. Easy template bits make the walk's cap (65535*SPREAD*
// att(block)) bind inside this chain, so a walk at any other bits pays other
// outputs and a peer's re-derived gentx differs.
TEST(DgbMintRoundTrip, CoinbaseClaimsTheBlockSubsidyAndWalksTheJobsBlockBits)
{
    for (int64_t ver : {int64_t(35), int64_t(36)}) {
        SCOPED_TRACE(ver);
        RtRig rig;
        rig.mint_version = ver;
        rig.tip_bits = "207fffff";
        auto cbr = rig.ws->build_connection_coinbase(rig.chain.tip, "cafef00d", stratum_payout(miner_login()), {});
        ASSERT_FALSE(cbr.held);
        ASSERT_TRUE(rig.last_inputs.has_value());
        EXPECT_EQ(rig.last_block.height, kRtBlockHeight);
        EXPECT_EQ(rig.last_block.bits, 0x207fffffu);
        const uint64_t block_subsidy = dgb::CoinParams::subsidy(kRtBlockHeight);
        EXPECT_EQ(cbr.snapshot.subsidy, block_subsidy);
        EXPECT_EQ(rig.last_inputs->subsidy, block_subsidy);
        EXPECT_NE(cbr.snapshot.subsidy, dgb::CoinParams::subsidy(rig.last_inputs->frozen_absheight))
            << "the coinbase claims the subsidy of the share-chain height";
        EXPECT_EQ(cbr.snapshot.block_nbits_hex, "207fffff");

        auto j = rig.job(cbr, 0x2100ffffu);
        const std::string en1 = "cafef00d", en2 = "0000002b", ntime = "6a1b2c3d", nonce = "00c0ffee";
        Bytes coinbase;
        const Bytes header = miner_header(j, en1, en2, ntime, nonce, &coinbase);
        auto r = rig.ws->mining_submit(miner_login(), "job", en1, en2, ntime, nonce, "rid", {}, &j);
        ASSERT_TRUE(r.is_boolean() && r.get<bool>()) << r.dump();
        ASSERT_FALSE(rig.minted.IsNull()) << "the local share was not credited";
        const uint256 cb_txid = Hash(std::span<const unsigned char>(coinbase.data(), coinbase.size()));
        rig.chain.tracker.chain.get(rig.minted).share.invoke([&](auto* s) {
            EXPECT_EQ(s->m_subsidy, block_subsidy);
            EXPECT_EQ(s->m_min_header.m_bits, 0x207fffffu);
            const uint256 expect_txid = dgb::generate_share_transaction(
                *s, rig.chain.tracker, rig.params, false, core::version_gate::is_v36_active(ver));
            EXPECT_EQ(expect_txid, cb_txid) << "the walk used other block bits than the share's header";
        });
    }
}

TEST(DgbMintRoundTrip, MintWithoutTheMinedCoinbaseAndFrozenFieldsDoesNotCredit)
{
    RtRig rig;
    rig.ws->set_mint_share_fn([&rig](const dgb::stratum::DGBWorkSource::MintShareInputs& got) -> uint256 {
        auto in = got;
        in.actual_coinbase.clear();
        in.has_frozen = false;
        auto hdr = dgb::parse_min_header_80(in.header_bytes);
        if (!hdr)
            return uint256();
        rig.minted = dgb::mint_local_share_at_frozen_version(in, *hdr, rig.chain.tracker, rig.params, 66);
        return rig.minted;
    });
    auto cbr = rig.ws->build_connection_coinbase(rig.chain.tip, "cafef00d", stratum_payout(miner_login()), {});
    ASSERT_FALSE(cbr.coinb1.empty());
    auto j = rig.job(cbr, 0x2100ffffu);
    const std::string en1 = "cafef00d", en2 = "0000002a", ntime = "6a1b2c3d", nonce = "00c0ffee";
    const Bytes header = miner_header(j, en1, en2, ntime, nonce, nullptr);
    (void)rig.ws->mining_submit(miner_login(), "job", en1, en2, ntime, nonce, "rid", {}, &j);
    const uint256 header_hash = Hash(std::span<const unsigned char>(header.data(), header.size()));
    EXPECT_NE(rig.minted, header_hash) << "the old mint path matched the miner's header";
}

// A DGB P2SH "S..." and a "dgb1..." miner are credited: the job payout script
// (core accepted_payout_script, as the stratum server builds it) is the one
// the mint derives from the username, so the round trip matches.
TEST(DgbMintRoundTrip, P2shAndBech32MinersAreCredited)
{
    Bytes key(20, 0x66);
    Bytes p2sh{0xa9, 0x14};
    p2sh.insert(p2sh.end(), key.begin(), key.end());
    p2sh.push_back(0x87);
    Bytes wpkh{0x00, 0x14};
    wpkh.insert(wpkh.end(), key.begin(), key.end());
    const auto acc = dgb::address_acceptance(false, false);
    for (const auto& script : {p2sh, wpkh}) {
        const std::string login = core::script_to_address(script, script.size() == 23 ? "" : "dgb", 30, 63);
        SCOPED_TRACE(login);
        ASSERT_EQ(core::accepted_payout_script(login, acc), script);
        for (int64_t ver : {int64_t(35), int64_t(36)}) {
            SCOPED_TRACE(ver);
            RtRig rig;
            rig.mint_version = ver;
            auto cbr = rig.ws->build_connection_coinbase(rig.chain.tip, "cafef00d",
                                                         core::accepted_payout_script(login, acc), {});
            ASSERT_FALSE(cbr.coinb1.empty());
            auto j = rig.job(cbr, 0x2100ffffu);
            const std::string en1 = "cafef00d", en2 = "0000002a", ntime = "6a1b2c3d", nonce = "00c0ffee";
            Bytes coinbase;
            const Bytes header = miner_header(j, en1, en2, ntime, nonce, &coinbase);
            auto r = rig.ws->mining_submit(login, "job", en1, en2, ntime, nonce, "rid", {}, &j);
            ASSERT_TRUE(r.is_boolean() && r.get<bool>()) << r.dump();
            ASSERT_FALSE(rig.minted.IsNull());
            EXPECT_EQ(rig.minted, Hash(std::span<const unsigned char>(header.data(), header.size())));
            const uint256 cb_txid = Hash(std::span<const unsigned char>(coinbase.data(), coinbase.size()));
            rig.chain.tracker.chain.get(rig.minted).share.invoke([&](auto* s) {
                EXPECT_EQ(dgb::generate_share_transaction(*s, rig.chain.tracker, rig.params, false,
                                                          core::version_gate::is_v36_active(ver)),
                          cb_txid) << "a peer would reject this share (gentx mismatch)";
            });
        }
    }
}

// A v34/v35 share carries its payout as an address string; the verifier reads
// it back with the DGB network's versions, as the oracle does
// (address_to_script2(address, net.PARENT)): "S..." is the P2SH, "dgb1..." the
// witness program, "D..." the P2PKH.
TEST(DgbMintRoundTrip, V35ShareAddressDecodesWithTheDgbNetworkVersions)
{
    Bytes key(20, 0x66);
    Bytes p2pkh{0x76, 0xa9, 0x14};
    p2pkh.insert(p2pkh.end(), key.begin(), key.end());
    p2pkh.push_back(0x88);
    p2pkh.push_back(0xac);
    Bytes p2sh{0xa9, 0x14};
    p2sh.insert(p2sh.end(), key.begin(), key.end());
    p2sh.push_back(0x87);
    Bytes wpkh{0x00, 0x14};
    wpkh.insert(wpkh.end(), key.begin(), key.end());
    for (const auto& script : {p2pkh, p2sh, wpkh}) {
        const std::string addr = core::script_to_address(script, script.size() == 22 ? "dgb" : "", 30, 63);
        SCOPED_TRACE(addr);
        dgb::PaddingBugfixShare s;
        s.m_address.m_data.assign(addr.begin(), addr.end());
        EXPECT_EQ(dgb::get_share_script(&s), script);
    }
}

namespace {

// dgb::NodeImpl's surface for the DOGE payout provider, over the rig's tracker.
struct RtNode {
    dgb::ShareTracker& tracker;
    uint256 best;
    std::shared_mutex mtx;
    struct Guard {
        std::shared_lock<std::shared_mutex> lk;
        dgb::ShareTracker* t;
        explicit operator bool() const { return lk.owns_lock(); }
        dgb::ShareTracker& operator*() { return *t; }
    };
    Guard read_tracker() { return Guard{std::shared_lock<std::shared_mutex>(mtx, std::try_to_lock), &tracker}; }
    uint256 best_share_hash() { return best; }
};

std::string to_hex(const std::vector<unsigned char>& b)
{
    static const char* H = "0123456789abcdef";
    std::string out;
    for (auto c : b) { out += H[c >> 4]; out += H[c & 0xf]; }
    return out;
}

} // namespace

// --merged DOGE on: the DOGE commitment is in the coinbase scriptSig the ref
// commits to, so the local share is still credited and the verifier rebuilds
// the mined coinbase. Before, the commitment was appended after the ref: every
// local share was declined once DOGE was on (the mutant below).
TEST(DgbMintRoundTrip, MergedDogeCommitmentIsInTheRefAndTheShareIsCredited)
{
    for (int64_t ver : {int64_t(35), int64_t(36)}) {
        SCOPED_TRACE(ver);
        RtRig rig;
        rig.mint_version = ver;
        RtNode node{rig.chain.tracker, rig.chain.tip};
        boost::asio::io_context ioc;
        dgb_test::MergedMiningManager mm(ioc);
        dgb_test::add_doge(mm);
        rig.ws->set_merged_mining_manager(&mm);
        ASSERT_TRUE(dgb::coin::wire_doge_merged_payouts(&mm, node, rig.ws.get()));
        mm.refresh_aux_work();
        const auto commitment = mm.get_cached_header_infos_and_commitment().second;
        ASSERT_EQ(commitment.size(), 44u);

        auto cbr = rig.ws->build_connection_coinbase(rig.chain.tip, "cafef00d", stratum_payout(miner_login()), {});
        ASSERT_FALSE(cbr.coinb1.empty());
        EXPECT_NE((cbr.coinb1 + cbr.coinb2).find("2c" + to_hex(std::vector<unsigned char>(commitment.begin(), commitment.end()))),
                  std::string::npos) << "the DGB coinbase does not commit to the DOGE block";
        ASSERT_TRUE(rig.last_inputs.has_value());

        auto j = rig.job(cbr, 0x2100ffffu);
        const std::string en1 = "cafef00d", en2 = "0000002a", ntime = "6a1b2c3d", nonce = "00c0ffee";
        Bytes coinbase;
        const Bytes header = miner_header(j, en1, en2, ntime, nonce, &coinbase);
        auto r = rig.ws->mining_submit(miner_login(), "job", en1, en2, ntime, nonce, "rid", {}, &j);
        ASSERT_TRUE(r.is_boolean() && r.get<bool>()) << r.dump();
        ASSERT_FALSE(rig.minted.IsNull()) << "the local share was not credited with DOGE on";
        EXPECT_EQ(rig.minted, Hash(std::span<const unsigned char>(header.data(), header.size())));
        const uint256 cb_txid = Hash(std::span<const unsigned char>(coinbase.data(), coinbase.size()));
        rig.chain.tracker.chain.get(rig.minted).share.invoke([&](auto* s) {
            EXPECT_EQ(dgb::generate_share_transaction(*s, rig.chain.tracker, rig.params, false,
                                                      core::version_gate::is_v36_active(ver)),
                      cb_txid) << "a peer would reject this share (gentx mismatch)";
        });
    }
}

// The pre-fix order: the producer builds the ref without the commitment and
// the commitment is appended to the scriptSig afterwards. The share does not
// match the coinbase the miner hashed.
TEST(DgbMintRoundTrip, CommitmentAppendedAfterTheRefIsNotCredited)
{
    RtRig rig;
    RtNode node{rig.chain.tracker, rig.chain.tip};
    boost::asio::io_context ioc;
    dgb_test::MergedMiningManager mm(ioc);
    dgb_test::add_doge(mm);
    ASSERT_TRUE(dgb::coin::wire_doge_merged_payouts(&mm, node, rig.ws.get()));
    mm.refresh_aux_work();
    const auto commitment = mm.get_cached_header_infos_and_commitment().second;
    ASSERT_EQ(commitment.size(), 44u);
    Bytes tagged{0x2c};
    tagged.insert(tagged.end(), commitment.begin(), commitment.end());
    // Producer without the commitment, then the old late splice.
    rig.ws->set_pplns_inputs_fn([&rig, tagged](const uint256& prev, const std::string&, const Bytes& payout,
                                               const std::vector<std::pair<uint32_t, Bytes>>& merged, const Bytes&, const dgb::stratum::DGBWorkSource::JobBlock& block)
                                    -> std::optional<dgb::coin::ConnCoinbasePplnsInputs> {
        dgb::ConnJobRequest req;
        req.prev_share_hash = prev;
        req.payout_script = payout;
        req.merged_addrs = merged;
        req.next_block_height = 20000000;
        req.now = rig.chain.tip_ts + 15;
        req.donation = 66;
        auto in = dgb::build_conn_job_inputs(rig.chain.tracker, rig.params, req, []() {
            return std::pair<int64_t, uint64_t>{36, 36};
        });
        if (in)
            in->aux_mm_commitment = tagged;
        return in;
    });
    auto cbr = rig.ws->build_connection_coinbase(rig.chain.tip, "cafef00d", stratum_payout(miner_login()), {});
    ASSERT_FALSE(cbr.coinb1.empty());
    auto j = rig.job(cbr, 0x2100ffffu);
    const std::string en1 = "cafef00d", en2 = "0000002a", ntime = "6a1b2c3d", nonce = "00c0ffee";
    Bytes coinbase;
    (void)miner_header(j, en1, en2, ntime, nonce, &coinbase);
    (void)rig.ws->mining_submit(miner_login(), "job", en1, en2, ntime, nonce, "rid", {}, &j);
    const uint256 cb_txid = Hash(std::span<const unsigned char>(coinbase.data(), coinbase.size()));
    bool matched = false;
    if (!rig.minted.IsNull() && rig.chain.tracker.chain.contains(rig.minted))
        rig.chain.tracker.chain.get(rig.minted).share.invoke([&](auto* s) {
            matched = dgb::generate_share_transaction(*s, rig.chain.tracker, rig.params, false, true) == cb_txid;
        });
    EXPECT_FALSE(matched) << "the late splice matched the share's ref";
}

namespace {

// Submits one share on `j` for `login`; returns the minted share's merged
// addresses and payout script (the share must exist).
struct Minted {
    bool ok = false;
    std::vector<std::pair<uint32_t, Bytes>> merged;
    bool gentx_ok = false;
};

Minted submit_and_read(RtRig& rig, core::stratum::JobSnapshot& j, const std::string& login,
                       const std::map<uint32_t, Bytes>& job_merged, int64_t ver)
{
    Minted m;
    const std::string en1 = "cafef00d", en2 = "0000002a", ntime = "6a1b2c3d", nonce = "00c0ffee";
    Bytes coinbase;
    const Bytes header = miner_header(j, en1, en2, ntime, nonce, &coinbase);
    auto r = rig.ws->mining_submit(login, "job", en1, en2, ntime, nonce, "rid", job_merged, &j);
    if (!(r.is_boolean() && r.get<bool>()) || rig.minted.IsNull())
        return m;
    if (rig.minted != Hash(std::span<const unsigned char>(header.data(), header.size())))
        return m;
    m.ok = true;
    const uint256 cb_txid = Hash(std::span<const unsigned char>(coinbase.data(), coinbase.size()));
    rig.chain.tracker.chain.get(rig.minted).share.invoke([&](auto* s) {
        if constexpr (requires { s->m_merged_addresses; })
            for (const auto& e : s->m_merged_addresses)
                m.merged.emplace_back(e.m_chain_id, e.m_script.m_data);
        m.gentx_ok = dgb::generate_share_transaction(*s, rig.chain.tracker, rig.params, false,
                                                     core::version_gate::is_v36_active(ver)) == cb_txid;
    });
    return m;
}

Bytes doge_x() { Bytes s{0x76, 0xa9, 0x14}; s.insert(s.end(), 20, 0x5c); s.push_back(0x88); s.push_back(0xac); return s; }

} // namespace

// An explicit DOGE address reaches the share: the job's merged scripts are the
// ones the mint stamps (V36 merged_addresses), and the share still matches.
TEST(DgbMintRoundTrip, ExplicitDogeAddressReachesTheShare)
{
    for (int64_t ver : {int64_t(35), int64_t(36)}) {
        SCOPED_TRACE(ver);
        RtRig rig;
        rig.mint_version = ver;
        const Bytes payout = stratum_payout(miner_login());
        const std::vector<std::pair<uint32_t, Bytes>> merged{{98, doge_x()}};
        auto cbr = rig.ws->build_connection_coinbase(rig.chain.tip, "cafef00d", payout, merged);
        ASSERT_FALSE(cbr.coinb1.empty());
        EXPECT_EQ(rig.last_merged, merged);
        auto j = rig.job(cbr, 0x2100ffffu, &payout);
        const auto m = submit_and_read(rig, j, miner_login(), {{98, doge_x()}}, ver);
        ASSERT_TRUE(m.ok) << "the local share was not credited";
        EXPECT_TRUE(m.gentx_ok) << "a peer would reject this share";
        if (ver >= 36)
            EXPECT_EQ(m.merged, merged) << "the explicit DOGE address did not reach the share";
    }
}

// A node-fee job (the owner's payout substituted) carries the owner's merged
// scripts, never the miner's: else the tracker would tie the owner's parent
// script to the miner's DOGE script for every owner share.
TEST(DgbMintRoundTrip, NodeFeeJobCarriesTheOwnersMergedScripts)
{
    Bytes owner{0x76, 0xa9, 0x14};
    owner.insert(owner.end(), 20, 0x0e);
    owner.push_back(0x88);
    owner.push_back(0xac);
    const Bytes owner_doge = owner;   // the owner's key as a DOGE P2PKH
    for (bool with_owner_merged : {true, false}) {
        SCOPED_TRACE(with_owner_merged);
        RtRig rig;
        rig.ws->set_node_owner_fee(100.0, owner);
        if (with_owner_merged)
            rig.ws->set_owner_merged_scripts({{98, owner_doge}});
        const Bytes payout = stratum_payout(miner_login());
        const std::vector<std::pair<uint32_t, Bytes>> miner_merged{{98, doge_x()}};
        auto cbr = rig.ws->build_connection_coinbase(rig.chain.tip, "cafef00d", payout, miner_merged);
        ASSERT_FALSE(cbr.coinb1.empty());
        ASSERT_EQ(rig.last_payout, owner) << "not a node-fee job";
        const std::vector<std::pair<uint32_t, Bytes>> want =
            with_owner_merged ? std::vector<std::pair<uint32_t, Bytes>>{{98, owner_doge}}
                              : std::vector<std::pair<uint32_t, Bytes>>{};
        EXPECT_EQ(rig.last_merged, want);
        auto j = rig.job(cbr, 0x2100ffffu, &payout);
        const auto m = submit_and_read(rig, j, miner_login(), {{98, doge_x()}}, 36);
        ASSERT_TRUE(m.ok);
        EXPECT_TRUE(m.gentx_ok);
        EXPECT_EQ(m.merged, want) << "the miner's DOGE address landed on the owner's share";
    }
}

// A login whose primary is a configured merged chain's address (Case 5, a
// DOGE "A..."): the job pays its key on DGB, and the mint now uses the job's
// payout, so the share is credited (DGB's own classification rejected it).
TEST(DgbMintRoundTrip, DogePrimaryLoginIsCreditedFromTheJobPayout)
{
    Bytes doge_p2sh{0xa9, 0x14};
    doge_p2sh.insert(doge_p2sh.end(), 20, 0x2d);
    doge_p2sh.push_back(0x87);
    const std::string login = core::script_to_address(doge_p2sh, "", 30, 22);
    const Bytes payout = core::address_to_script(login);   // what the stratum server builds for it
    ASSERT_EQ(payout, doge_p2sh);
    RtRig rig;
    auto cbr = rig.ws->build_connection_coinbase(rig.chain.tip, "cafef00d", payout, {});
    ASSERT_FALSE(cbr.coinb1.empty());
    auto j = rig.job(cbr, 0x2100ffffu, &payout);
    const auto m = submit_and_read(rig, j, login, {}, 36);
    ASSERT_TRUE(m.ok) << "the DOGE-primary login was not credited";
    EXPECT_TRUE(m.gentx_ok);
}

// Reviving a dormant chain: the first share minted on a ~90-day-old tip. The
// producer's clock is today; the share's timestamp is "now" (after the old
// tip, so no clip), absheight/abswork follow the tip, and the share target
// moves at most 10% from the tip's max target (p2pool's retarget clamp) and
// never above the network's maximum. The round trip still matches.
TEST(DgbMintRoundTrip, FirstShareOnANinetyDayOldTip)
{
    const uint32_t today = static_cast<uint32_t>(std::time(nullptr));
    for (int64_t ver : {int64_t(35), int64_t(36)}) {
        SCOPED_TRACE(ver);
        RtRig rig(today - 90u * 86400u);
        rig.mint_version = ver;
        rig.now = today;
        const Bytes payout = stratum_payout(miner_login());
        auto cbr = rig.ws->build_connection_coinbase(rig.chain.tip, "cafef00d", payout, {});
        ASSERT_FALSE(cbr.coinb1.empty());
        const auto& f = cbr.snapshot.frozen_ref;
        EXPECT_EQ(f.timestamp, today);
        uint32_t tip_absheight = 0, tip_max_bits = 0;
        uint128 tip_abswork;
        rig.chain.tracker.chain.get(rig.chain.tip).share.invoke([&](auto* s) {
            tip_absheight = s->m_absheight;
            tip_abswork = s->m_abswork;
            tip_max_bits = s->m_max_bits;
        });
        EXPECT_EQ(f.absheight, tip_absheight + 1);
        EXPECT_GT(f.abswork, tip_abswork);
        const uint256 prev_max = chain::bits_to_target(tip_max_bits);
        const uint256 new_max = chain::bits_to_target(f.max_bits);
        EXPECT_LE(new_max, prev_max * 11 / 10) << "the share target jumped more than the clamp";
        EXPECT_GE(new_max, prev_max * 9 / 10);
        EXPECT_LE(new_max, rig.params.max_target) << "above the network's maximum share target";
        EXPECT_LE(chain::bits_to_target(f.bits), new_max);

        auto j = rig.job(cbr, 0x2100ffffu, &payout);
        const auto m = submit_and_read(rig, j, miner_login(), {}, ver);
        ASSERT_TRUE(m.ok) << "the first share on the old tip was not credited";
        EXPECT_TRUE(m.gentx_ok) << "a peer would reject it";
    }
}
