// SPDX-License-Identifier: AGPL-3.0-or-later
// #884 (ruled 2026-10-02): DGB minting follows the AutoRatchet, as LTC does --
// no hardcoded v36. The producer asks the ratchet ONCE per template and stamps
// that {mint, vote} pair on the coinbase (PPLNS formula, finder fee, donation
// script) and on the ref preimage; the pair rides the job to the mint, which
// stamps it verbatim.
//
// These KATs drive the production pieces main_dgb binds, end to end:
//   dgb_select_mint_versions  -> the ONE ratchet query
//   apply_conn_mint_version   -> version-dependent coinbase fields
//   make_conn_pplns_inputs    -> carries the version to the job snapshot
//   mint_local_share_at_frozen_version -> the share minted into the tracker
// and pin both sides of the crossing:
//   VOTING   (v35 side) -> coinbase built for v35, share minted as v35, votes 36
//   CONFIRMED (crossed) -> coinbase built for v36, share minted as v36
// plus the "ask ONCE" rule: a job frozen at v35 still mints v35 after the
// ratchet has crossed, because the mint never re-asks.
//
// Before #884 the mint stamped share_version=36 unconditionally, so the VOTING
// cases below minted a v36 share (RED on master); the producer likewise built a
// v36 coinbase (P2SH donation, V36 PPLNS) regardless of ratchet state.

#include <gtest/gtest.h>

#include <impl/dgb/auto_ratchet_wire.hpp>   // make_dgb_ratchet, dgb_select_mint_versions
#include <impl/dgb/conn_pplns_producer.hpp> // apply_conn_mint_version, make_conn_pplns_inputs
#include <impl/dgb/run_loop_mint.hpp>       // mint_local_share_at_frozen_version
#include <impl/dgb/config_pool.hpp>         // PoolConfig donation scripts
#include <impl/dgb/params.hpp>              // make_coin_params
#include <impl/dgb/share_tracker.hpp>
#include <impl/dgb/coin/block.hpp>

#include <core/pack.hpp>
#include <core/pow.hpp>
#include <core/uint256.hpp>
#include <core/version_gate.hpp>

#include <nlohmann/json.hpp>

#include <cstdio>
#include <fstream>
#include <span>
#include <string>
#include <vector>
#include <unistd.h>                         // getpid (ratchet state temp file)

namespace {

using Script = std::vector<unsigned char>;

// Finder P2PKH scriptPubKey (OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG).
Script finder_p2pkh()
{
    Script s{0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(static_cast<unsigned char>(0x10 + i));
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

// Mirrors DGBWorkSource::MintShareInputs (the mint helper is duck-typed, so this
// TU need not pull the stratum work source in).
struct MintInputs {
    std::vector<unsigned char> header_bytes;
    std::vector<unsigned char> coinbase_bytes;
    uint64_t                   subsidy = 0;
    uint256                    prev_share;
    std::vector<uint256>       merkle_branches;
    std::vector<unsigned char> payout_script;
    bool                       segwit_active = false;
    int64_t                    share_version = 36;
    uint64_t                   desired_version = 36;
};

std::vector<unsigned char> header80()
{
    dgb::coin::BlockHeaderType hdr;
    hdr.m_version   = 0x20000002u;          // Scrypt algo bits
    hdr.m_previous_block = uint256S(
        "00000000000000000000000000000000000000000000000000000000deadbeef");
    hdr.m_merkle_root = uint256S(
        "00000000000000000000000000000000000000000000000000000000cafef00d");
    hdr.m_timestamp = 1718700000u;
    hdr.m_bits      = 0x1e0ffff0u;
    hdr.m_nonce     = 0x12345678u;
    PackStream packed = pack<dgb::coin::BlockHeaderType>(hdr);
    return {reinterpret_cast<unsigned char*>(packed.data()),
            reinterpret_cast<unsigned char*>(packed.data()) + packed.size()};
}

// Producer half: what main_dgb's set_pplns_inputs_fn does with the ONE ratchet
// answer -- version-dependent coinbase fields + ref preimage version -- then
// make_conn_pplns_inputs, whose output feeds the job snapshot.
dgb::coin::ConnCoinbasePplnsInputs produce(int64_t mint_version, uint64_t vote_version,
                                           const core::CoinParams& params)
{
    dgb::ConnPplnsAssemblyInputs ain;
    ain.weights      = {{finder_p2pkh(), uint288(1)}};
    ain.total_weight = uint288(1);
    ain.subsidy      = 72000000000ULL;
    ain.coinbase_script = Script{0x03, 0x01, 0x02, 0x03};
    dgb::apply_conn_mint_version(ain, mint_version, finder_p2pkh());

    dgb::RefHashParams rp;
    rp.share_version   = mint_version;
    rp.desired_version = vote_version;
    rp.coinbase_scriptSig = ain.coinbase_script;
    rp.subsidy   = ain.subsidy;
    rp.max_bits  = 0x1e0fffff;
    rp.bits      = 0x1e0fffff;
    rp.timestamp = 1718700000;
    rp.absheight = 1;
    ain.ref_params = rp;
    return dgb::make_conn_pplns_inputs(ain, params);
}

// Mint half: the job's frozen pair -> mint_local_share_at_frozen_version ->
// read back the version actually stored in the tracker.
struct Minted { bool ok = false; int64_t version = -1; uint64_t desired = 0; };

Minted mint(int64_t share_version, uint64_t desired_version,
            dgb::ShareTracker& tracker, const core::CoinParams& params)
{
    MintInputs in;
    in.header_bytes    = header80();
    in.coinbase_bytes  = Script{0x03, 0x01, 0x02, 0x03, 0x2f, 0x63, 0x32, 0x2f};
    in.subsidy         = 72000000000ULL;
    in.payout_script   = finder_p2pkh();
    in.share_version   = share_version;
    in.desired_version = desired_version;

    auto hdr = dgb::parse_min_header_80(in.header_bytes);
    EXPECT_TRUE(hdr.has_value());
    if (!hdr) return {};

    const uint256 h = dgb::mint_local_share_at_frozen_version(
        in, *hdr, tracker, params, /*donation=*/66);
    Minted m;
    if (h.IsNull() || !tracker.chain.contains(h))
        return m;
    m.ok = true;
    tracker.chain.get(h).share.invoke([&](auto* s) {
        m.version = static_cast<int64_t>(std::remove_pointer_t<decltype(s)>::version);
        m.desired = static_cast<uint64_t>(s->m_desired_version);
    });
    return m;
}

// Production CoinParams with the PoW function stubbed to the all-zero digest, so
// the fixture header always clears the share target. The subject here is the
// version the share is minted at, not PoW (covered by the scrypt KATs); without
// the stub create_local_share declines the unground header as a pseudoshare.
core::CoinParams kat_params()
{
    auto params = dgb::make_coin_params(/*testnet=*/false);
    params.pow_func = [](std::span<const unsigned char>) { return uint256(); };
    return params;
}

// A ratchet that has crossed: CONFIRMED persisted state (survives restart).
std::string write_confirmed_state()
{
    const std::string path = std::string("/tmp/dgb_884_ratchet_kat_") +
                             std::to_string(::getpid()) + ".json";
    nlohmann::json j;
    j["state"] = "confirmed";
    j["activated_at"] = 1;
    j["activated_height"] = 2;
    j["confirmed_at"] = 3;
    j["confirm_count"] = 4;
    std::ofstream(path) << j.dump(2);
    return path;
}

} // namespace

// v35 side of the ratchet: VOTING node builds a v35 coinbase and mints v35,
// voting 36.
TEST(DGB_884_MintFollowsAutoRatchet, VotingSideBuildsAndMintsV35)
{
    const auto params = kat_params();
    auto ratchet = dgb::make_dgb_ratchet();
    dgb::ShareTracker tracker;

    auto [mv, vv] = dgb::dgb_select_mint_versions(ratchet, tracker, uint256{});
    ASSERT_EQ(ratchet.state(), dgb::RatchetState::VOTING);
    ASSERT_EQ(mv, 35);
    ASSERT_EQ(vv, 36);

    // Producer: v35 coinbase shape (pre-V36 PPLNS, finder fee, P2PK donation).
    const auto job = produce(mv, static_cast<uint64_t>(vv), params);
    EXPECT_FALSE(job.use_v36_pplns);
    EXPECT_EQ(job.finder_script, finder_p2pkh());
    EXPECT_EQ(job.donation_script, dgb::PoolConfig::get_donation_script(35));
    EXPECT_NE(job.donation_script, dgb::PoolConfig::get_donation_script(36));
    EXPECT_EQ(job.share_version, 35);      // frozen onto the job
    EXPECT_EQ(job.desired_version, 36u);

    // Mint: stamps the job's frozen pair.
    const auto m = mint(job.share_version, job.desired_version, tracker, params);
    ASSERT_TRUE(m.ok);
    EXPECT_EQ(m.version, 35);
    EXPECT_EQ(m.desired, 36u);
}

// After the crossing: CONFIRMED node builds a v36 coinbase and mints v36.
TEST(DGB_884_MintFollowsAutoRatchet, CrossedSideBuildsAndMintsV36)
{
    const auto params = kat_params();
    const std::string path = write_confirmed_state();
    auto ratchet = dgb::make_dgb_ratchet(path);
    dgb::ShareTracker tracker;

    auto [mv, vv] = dgb::dgb_select_mint_versions(ratchet, tracker, uint256{});
    ASSERT_EQ(ratchet.state(), dgb::RatchetState::CONFIRMED);
    ASSERT_EQ(mv, 36);
    ASSERT_EQ(vv, 36);

    const auto job = produce(mv, static_cast<uint64_t>(vv), params);
    EXPECT_TRUE(job.use_v36_pplns);
    EXPECT_TRUE(job.finder_script.empty());
    EXPECT_EQ(job.donation_script, dgb::PoolConfig::get_donation_script(36));
    EXPECT_EQ(job.share_version, 36);
    EXPECT_EQ(job.desired_version, 36u);

    const auto m = mint(job.share_version, job.desired_version, tracker, params);
    ASSERT_TRUE(m.ok);
    EXPECT_EQ(m.version, 36);
    EXPECT_EQ(m.desired, 36u);
    std::remove(path.c_str());
}

// Ask ONCE: a job frozen while VOTING (v35) still mints v35 even if the ratchet
// has crossed by the time the miner submits -- the mint never re-asks, so the
// share matches the v35 coinbase the miner hashed.
TEST(DGB_884_MintFollowsAutoRatchet, MintUsesFrozenVersionNotALaterRatchetAnswer)
{
    const auto params = kat_params();
    dgb::ShareTracker tracker;

    auto voting = dgb::make_dgb_ratchet();
    auto [mv, vv] = dgb::dgb_select_mint_versions(voting, tracker, uint256{});
    const auto job = produce(mv, static_cast<uint64_t>(vv), params);
    ASSERT_EQ(job.share_version, 35);

    const std::string path = write_confirmed_state();
    auto crossed = dgb::make_dgb_ratchet(path);
    auto [later_mv, later_vv] = dgb::dgb_select_mint_versions(crossed, tracker, uint256{});
    ASSERT_EQ(later_mv, 36);   // the ratchet would now say 36...
    (void)later_vv;

    const auto m = mint(job.share_version, job.desired_version, tracker, params);
    ASSERT_TRUE(m.ok);
    EXPECT_EQ(m.version, 35);  // ...but the job was built for 35, so 35 is minted
    std::remove(path.c_str());
}
