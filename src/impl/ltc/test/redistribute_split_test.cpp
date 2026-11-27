// SPDX-License-Identifier: AGPL-3.0-or-later
//
// --redistribute split: a share minted for work the node cannot attribute to a
// payout address pays the node owner, with donation core::kSplitShareDonation
// (32768 of 65535) in place of --give-author's. PPLNS splits every share's
// weight by its own donation field: (65535 - donation)/65535 to the share's
// address and donation/65535 to the donation script. So such a share gives the
// owner and the donation half of its weight each:
//   - on the parent chain (V36 decayed weights, share_tracker.hpp
//     get_v36_decayed_cumulative_weights; amounts as generate_share_transaction:
//     subsidy * weight / total, the donation the remainder);
//   - on a merged chain (flat merged weights, merged_weights_delta: the share's
//     explicit merged address, Tier 1; amounts merged_payouts_from_weights);
// for a V36 and for a 3601 share. A miner's share beside it keeps its own
// donation. No consensus change: the donation is the share's own uint16 field.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <boost/log/core.hpp>

#include <core/author_fee.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <impl/ltc/config_pool.hpp>
#include <impl/ltc/params.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_check.hpp>
#include <impl/ltc/share_tracker.hpp>

#ifndef C2POOL_IMPL_DIR
#error "C2POOL_IMPL_DIR must be defined by CMake to the path of src/impl"
#endif

namespace {

constexpr uint32_t kBits = 0x1e0fffff;
constexpr uint32_t kTs = 1800000000;
constexpr uint32_t kDoge = 98;
constexpr uint16_t kNodeDonation = 66;   // --give-author 0.1%

uint256 hx(uint64_t n)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llx", static_cast<unsigned long long>(n));
    const std::string t(buf);
    uint256 v;
    v.SetHex(std::string(64 - t.size(), '0') + t);
    return v;
}

uint160 key(unsigned char b)
{
    uint160 h;
    for (int i = 0; i < 20; ++i)
        h.data()[i] = b;
    return h;
}

std::vector<unsigned char> p2pkh(unsigned char b)
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, b);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

template <class S>
uint256 add(ltc::ShareTracker& tr, uint64_t id, const uint256& prev, const uint160& pkh, uint16_t donation,
            const std::vector<unsigned char>& doge_script)
{
    auto* sh = new S();
    sh->m_hash = hx(id);
    sh->m_prev_hash = prev;
    sh->m_desired_version = 36;
    sh->m_bits = kBits;
    sh->m_max_bits = kBits;
    sh->m_timestamp = kTs + static_cast<uint32_t>(id);
    sh->m_donation = donation;
    sh->m_pubkey_hash = pkh;
    sh->m_pubkey_type = 0;
    ltc::MergedAddressEntry e;
    e.m_chain_id = kDoge;
    e.m_script.m_data = doge_script;
    sh->m_merged_addresses.push_back(e);
    sh->m_hash_link.m_state.m_data.assign(32, 0x4c);
    sh->m_hash_link.m_length = 64;
    const uint256 h = sh->m_hash;
    ltc::ShareType st;
    st = sh;
    tr.add(st);
    return h;
}

uint288 unlimited()
{
    uint288 u;
    u.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return u;
}

// generate_share_transaction's V36 amounts: subsidy * weight / total for the
// share's address, the remainder to the donation.
std::pair<uint64_t, uint64_t> parent_amounts(const uint288& weight, const uint288& total, uint64_t subsidy)
{
    const uint64_t addr = (uint288(subsidy) * weight / total).GetLow64();
    return {addr, subsidy - addr};
}

template <class S>
void split_share_pays_owner_and_donation_half_and_half(const char* what)
{
    SCOPED_TRACE(what);
    const uint160 owner = key(0x0a), miner = key(0x22);
    const auto owner_script = ltc::pubkey_hash_to_script(owner, 0);
    const auto miner_script = ltc::pubkey_hash_to_script(miner, 0);
    ASSERT_EQ(owner_script, p2pkh(0x0a));
    const auto owner_doge = p2pkh(0x0c), miner_doge = p2pkh(0x21);
    const std::vector<unsigned char> doge_donation{0xa9, 0x14, 1, 2, 3};
    const uint288 att = chain::target_to_average_attempts(chain::bits_to_target(kBits));
    const uint64_t subsidy = 625000000;            // the parent's coinbase value
    const uint64_t doge_subsidy = 1000000000000;   // the DOGE coinbase value

    // The split share alone: half and half (32767 / 32768 of 65535).
    {
        ltc::ShareTracker tr;
        const uint256 s = add<S>(tr, 1, uint256(), owner, core::kSplitShareDonation, owner_doge);
        const auto w = tr.get_v36_decayed_cumulative_weights(s, 1, unlimited());
        EXPECT_EQ(w.total_weight, att * 65535u);
        ASSERT_EQ(w.weights.size(), 1u);
        EXPECT_EQ(w.weights.at(owner_script), att * 32767u);
        EXPECT_EQ(w.total_donation_weight, att * 32768u);
        // owner = floor(subsidy * 32767 / 65535), the donation the rest: they
        // differ by subsidy/65535 (the odd denominator) plus the floor's
        // remainder, at most 2 satoshi more.
        const auto [owner_amt, don_amt] = parent_amounts(w.weights.at(owner_script), w.total_weight, subsidy);
        EXPECT_EQ(owner_amt, subsidy * 32767 / 65535);
        EXPECT_EQ(owner_amt, 312495231u);
        EXPECT_EQ(don_amt, 312504769u);
        EXPECT_EQ(owner_amt + don_amt, subsidy);
        EXPECT_GE(don_amt, owner_amt);
        EXPECT_LE(don_amt - owner_amt, subsidy / 65535 + 2) << owner_amt << " / " << don_amt;

        const auto mw = tr.get_merged_payout_weights(s, kDoge);
        EXPECT_EQ(mw.total_weight, att * 65535u);
        EXPECT_EQ(mw.donation_weight, att * 32768u);
        ASSERT_EQ(mw.resolved.size(), 1u);
        EXPECT_EQ(mw.resolved[0].first, owner_doge) << "the DOGE side pays the owner's DOGE script";
        EXPECT_EQ(mw.resolved[0].second, att * 32767u);
        const auto m = ltc::ShareTracker::merged_payouts_from_weights(mw, doge_subsidy, doge_donation);
        ASSERT_EQ(m.size(), 2u);
        // donation = floor(subsidy * 32768 / 65535), the owner the rest.
        const uint64_t mo = m.at(owner_doge), md = m.at(doge_donation);
        EXPECT_EQ(md, doge_subsidy * 32768 / 65535);
        EXPECT_EQ(mo + md, doge_subsidy);
        EXPECT_GE(md, mo);
        EXPECT_LE(md - mo, doge_subsidy / 65535 + 2) << mo << " / " << md;
    }

    // Under a miner's share: the split share's weight still goes half to the
    // owner, half to the donation; the miner's share keeps its own donation.
    {
        ltc::ShareTracker tr;
        const uint256 a = add<S>(tr, 1, uint256(), miner, kNodeDonation, miner_doge);
        const uint256 b = add<S>(tr, 2, a, owner, core::kSplitShareDonation, owner_doge);
        const auto w = tr.get_v36_decayed_cumulative_weights(b, 2, unlimited());
        ASSERT_EQ(w.weights.size(), 2u);
        EXPECT_EQ(w.weights.at(owner_script), att * 32767u) << "the split share, at the tip (no decay)";
        const uint288 miner_w = w.weights.at(miner_script);   // decayed * (65535 - 66)
        const uint288 split_don = att * 32768u;
        EXPECT_EQ((w.total_donation_weight - split_don) * uint288(65535 - kNodeDonation), miner_w * uint288(kNodeDonation))
            << "the miner's share: its own donation";

        const auto mw = tr.get_merged_payout_weights(b, kDoge);
        EXPECT_EQ(mw.total_weight, att * 131070u);
        EXPECT_EQ(mw.donation_weight, att * (32768u + kNodeDonation));
        ASSERT_EQ(mw.resolved.size(), 2u);
        for (const auto& [script, weight] : mw.resolved) {
            if (script == owner_doge)
                EXPECT_EQ(weight, att * 32767u);
            else if (script == miner_doge)
                EXPECT_EQ(weight, att * (65535u - kNodeDonation));
            else
                ADD_FAILURE() << "an unexpected merged payee";
        }
    }
}

} // namespace

TEST(RedistributeSplit, PplnsGivesTheOwnerAndTheDonationHalfOfTheShareV36)
{
    split_share_pays_owner_and_donation_half_and_half<ltc::MergedMiningShare>("V36 share");
}

TEST(RedistributeSplit, PplnsGivesTheOwnerAndTheDonationHalfOfTheShare3601)
{
    split_share_pays_owner_and_donation_half_and_half<ltc::MergedMiningShareV3601>("3601 share");
}

// The commit and the reveal of a split share's donation: the job's ref_hash
// (ref_hash_fn: compute_ref_hash_for_work over the share fields the job
// froze, donation core::job_share_donation of the split job: 32768) is in the
// coinbase the miner hashes; the share minted from that job
// (create_local_share with the same job_share_donation, the frozen fields and
// the mined coinbase) must reveal a ref_hash equal to it, or no peer can
// rebuild the coinbase the header commits to. Pinned with share_init_verify,
// the check every peer runs: it rebuilds the coinbase from the share's own
// fields (donation included) and must land on the share's hash. A share
// minted with the node's donation (66) from the same job fails it.
namespace {

struct QuietLog {
    bool was;
    QuietLog() : was(boost::log::core::get()->get_logging_enabled())
    {
        boost::log::core::get()->set_logging_enabled(false);
    }
    ~QuietLog() { boost::log::core::get()->set_logging_enabled(was); }
};

// Testnet share targets (1 in ~20 hashes is a share); PoolConfig is global.
struct TestnetScope {
    bool was;
    TestnetScope() : was(ltc::PoolConfig::is_testnet) { ltc::PoolConfig::is_testnet = true; }
    ~TestnetScope() { ltc::PoolConfig::is_testnet = was; }
};

template <class T>
void put_le(std::vector<unsigned char>& out, T v)
{
    for (size_t i = 0; i < sizeof(T); ++i)
        out.push_back(static_cast<unsigned char>(static_cast<uint64_t>(v) >> (8 * i)));
}

void put_varstr(std::vector<unsigned char>& out, const std::vector<unsigned char>& b)
{
    out.push_back(static_cast<unsigned char>(b.size()));   // < 0xfd here
    out.insert(out.end(), b.begin(), b.end());
}

// A genesis share's coinbase as the miner hashes it: no PPLNS window yet, the
// subsidy to the donation, then the OP_RETURN carrying the job's ref_hash and
// last_txout_nonce (the order generate_share_transaction builds).
std::vector<unsigned char> job_coinbase(const std::vector<unsigned char>& script_sig, uint64_t subsidy,
                                        const std::vector<unsigned char>& donation_script, const uint256& ref,
                                        uint64_t nonce)
{
    std::vector<unsigned char> cb;
    put_le<uint32_t>(cb, 1);
    cb.push_back(1);
    cb.insert(cb.end(), 32, 0x00);
    put_le<uint32_t>(cb, 0xffffffffu);
    put_varstr(cb, script_sig);
    put_le<uint32_t>(cb, 0xffffffffu);
    cb.push_back(2);
    put_le<uint64_t>(cb, subsidy);
    put_varstr(cb, donation_script);
    put_le<uint64_t>(cb, 0);
    std::vector<unsigned char> op{0x6a, 0x28};
    op.insert(op.end(), ref.data(), ref.data() + 32);
    put_le<uint64_t>(op, nonce);
    put_varstr(cb, op);
    put_le<uint32_t>(cb, 0);
    return cb;
}

struct JobMint {
    uint256 job_ref;
    uint256 share;          // minted share hash (null: none in the nonce range)
    uint16_t donation{0};   // the minted share's m_donation
    bool peers_rebuild{false};   // share_init_verify lands on the share's hash
};

// Build the split job (its ref_hash, its coinbase), then mint the share from
// it with `share_donation`, as create_share_fn does.
JobMint mint_from_split_job(uint16_t share_donation)
{
    const auto params = ltc::make_coin_params(true);
    ltc::ShareTracker tracker;
    const uint32_t ts = static_cast<uint32_t>(std::time(nullptr));
    const int64_t ver = ltc::flag_day_share_version(36, ts);
    const uint64_t subsidy = 625000000;
    const std::vector<unsigned char> script_sig{0x03, 0x2a, 0x00, 0x00, 'c', '2', 'p', 'o', 'o', 'l'};
    const uint160 owner = key(0x0a);
    const auto owner_script = ltc::pubkey_hash_to_script(owner, 0);
    const auto [max_bits, bits] = tracker.compute_share_target(uint256(), ts, chain::bits_to_target(0x207fffff));
    const uint128 abswork(chain::target_to_average_attempts(chain::bits_to_target(bits)).GetLow64());

    // The job (ref_hash_fn): the share fields it freezes, the split donation.
    ltc::RefHashParams p;
    p.share_version = ver;
    p.prev_share = uint256();
    p.coinbase_scriptSig = script_sig;
    p.share_nonce = 0;
    p.pubkey_hash = owner;
    p.pubkey_type = 0;
    p.subsidy = subsidy;
    p.donation = core::job_share_donation(core::kSplitShareDonation, /*give_author_pct=*/0.1);
    p.desired_version = 36;
    p.has_segwit = true;
    p.segwit_data.m_txid_merkle_link.m_index = 0;
    p.max_bits = max_bits;
    p.bits = bits;
    p.timestamp = ts;
    p.absheight = 1;
    p.abswork = abswork;
    const auto [job_ref, nonce] = ltc::compute_ref_hash_for_work(p, params);
    const auto cb = job_coinbase(script_sig, subsidy, params.donation_script_func(36), job_ref, nonce);

    JobMint out;
    out.job_ref = job_ref;
    ltc::coin::SmallBlockHeaderType hdr;
    hdr.m_version = 0x20000000;
    hdr.m_previous_block = uint256(0xb10cULL);
    hdr.m_timestamp = ts;
    hdr.m_bits = 0x207fffff;
    BaseScript coinbase;
    coinbase.m_data = script_sig;
    for (uint32_t n = 0; n < 5000 && out.share.IsNull(); ++n) {
        hdr.m_nonce = n;
        out.share = ltc::create_local_share(
            tracker, params, hdr, coinbase, subsidy, uint256(), /*merkle_branches=*/{}, owner_script,
            share_donation, /*merged_addrs=*/{}, ltc::StaleInfo::none, /*segwit_active=*/true,
            /*witness_commitment_hex=*/"aa", /*message_data=*/{}, cb, /*witness_root=*/uint256(), max_bits, bits,
            /*frozen_absheight=*/1, abswork, /*frozen_far_share_hash=*/uint256(), ts,
            /*frozen_merged_payout_hash=*/uint256(), /*has_frozen=*/true, /*frozen_merkle_branches=*/{},
            /*frozen_witness_root=*/uint256(), /*frozen_merged_coinbase_info=*/{}, ver, 36);
    }
    if (out.share.IsNull() || !tracker.chain.contains(out.share))
        return out;
    tracker.chain.get_share(out.share).invoke([&](auto* obj) {
        out.donation = obj->m_donation;
        try {
            out.peers_rebuild = ltc::share_init_verify(*obj, params) == out.share;
        } catch (const std::exception&) {
            out.peers_rebuild = false;
        }
    });
    return out;
}

} // namespace

TEST(RedistributeSplit, TheMintedShareRevealsTheDonationItsJobCommittedTo)
{
    QuietLog quiet;
    TestnetScope testnet;
    const uint16_t job_donation = core::job_share_donation(core::kSplitShareDonation, 0.1);
    ASSERT_EQ(job_donation, 32768);
    const auto split = mint_from_split_job(job_donation);
    ASSERT_FALSE(split.share.IsNull()) << "no share minted in 5000 nonces";
    EXPECT_EQ(split.donation, 32768);
    EXPECT_TRUE(split.peers_rebuild)
        << "the minted share's ref_hash is the job's: peers rebuild the coinbase the header commits to";

    // The same job minted with the node's donation (a site that forgot the
    // job's): the self-check still finds a PoW, but no peer can rebuild it.
    const auto wrong = mint_from_split_job(core::job_share_donation(std::nullopt, 0.1));
    ASSERT_FALSE(wrong.share.IsNull());
    EXPECT_EQ(wrong.donation, 66);
    EXPECT_FALSE(wrong.peers_rebuild) << "a share revealing another donation than its job's ref_hash";
}

// The main_ltc.cpp call sites that hand the job's donation on cannot be run
// here (they are lambdas over the live node), so their text is pinned: the
// ref_hash lambda takes the job's donation and commits the share to
// core::job_share_donation(share_donation, dev_donation) (its share target
// sized with the same), the create_share lambda mints with
// core::job_share_donation(p.share_donation, dev_donation), no site builds
// the --give-author formula by hand or passes std::nullopt for the job's
// donation, and the startup passes --node-owner-address before --address
// (ltc::setup_split_owner, whose precedence TheStartupSetupSplitsOnlyASplit
// SpecAndPicksTheOwner pins) and runs the spec's fallback weights.
TEST(RedistributeSplit, MainLtcHandsTheJobsDonationToTheRefHashAndTheShare)
{
    std::ifstream in(std::string(C2POOL_IMPL_DIR) + "/../c2pool/main_ltc.cpp");
    ASSERT_TRUE(in.good());
    std::stringstream ss;
    ss << in.rdbuf();
    std::string src;   // whitespace runs collapsed to one space
    for (const char ch : ss.str()) {
        const bool space = ch == ' ' || ch == '\n' || ch == '\t' || ch == '\r';
        if (space) {
            if (!src.empty() && src.back() != ' ')
                src += ' ';
        } else {
            src += ch;
        }
    }
    const auto count = [&src](const std::string& needle) {
        size_t n = 0;
        for (size_t at = src.find(needle); at != std::string::npos; at = src.find(needle, at + 1))
            ++n;
        return n;
    };
    EXPECT_EQ(count("const std::vector<uint256>& merkle_branches, const std::optional<uint16_t>& share_donation) "
                    "-> core::MiningInterface::RefHashResult"), 1u)
        << "the ref_hash lambda receives the job's donation";
    EXPECT_EQ(count("params.donation = core::job_share_donation(share_donation, dev_donation);"), 1u);
    EXPECT_EQ(count("target_in.donation_percent = core::job_share_donation_pct(share_donation, dev_donation);"), 1u);
    EXPECT_EQ(count("core::job_share_donation(p.share_donation, dev_donation),"), 1u)
        << "the create_share lambda mints with the job's donation";
    EXPECT_EQ(count("job_share_donation(std::nullopt"), 0u);
    EXPECT_EQ(count("job_share_donation_pct(std::nullopt"), 0u);
    EXPECT_EQ(count("65535.0 * dev_donation"), 0u) << "the --give-author formula is core::job_share_donation's";
    EXPECT_EQ(count("ltc::setup_split_owner( *web_server.get_mining_interface(), redistribute_mode_str, "
                    "node_owner_address, payout_address,"), 1u)
        << "--node-owner-address, then --address";
    EXPECT_EQ(count("auto hybrid_weights = ltc::split_fallback_weights(ltc::parse_redistribute_spec("
                    "redistribute_mode_str));"), 1u);
}
