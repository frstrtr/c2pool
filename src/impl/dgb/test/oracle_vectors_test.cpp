// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// Cross-implementation vectors for the python DGB oracle (rides
// dgb_work_source_test). Review 713dc77a0, C2POOL's gate before any canary.
//
// Mints a genesis-rooted chain of V35 shares the way a c2pool-dgb node does:
// the first two shares by create_local_share_v35 (the job producer builds on a
// non-empty PPLNS window only), every later one through the real
// producer (build_conn_job_inputs on the job template), a DGBWorkSource job, a
// miner's header, mining_submit and the frozen-field mint. The chain has more
// than TARGET_LOOKBEHIND shares, gaps over 300 s (R4), equal-amount ties
// between D/S/dgb1 payouts (#6) and a P2WPKH with a leading-zero program
// (#7). Every share must pass this node's own checks (share_init_verify,
// check_v35_share_info, the generation transaction). Mutated copies (wrong
// max_bits, bits outside the clip range, timestamp) must fail them.
//
// With DGB_ORACLE_VECTORS=<file> it writes the packed shares, their hashes
// and generation transactions as JSON for scripts/dgb_oracle_harness/
// check_vectors.py, which runs them through the python oracle's
// Share.check / generate_transaction (python2 + twisted; not in CI).
// ---------------------------------------------------------------------------

#include <impl/dgb/address_encoding.hpp>
#include <impl/dgb/coin/coinbase_scriptsig.hpp>
#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/config_coin.hpp>
#include <impl/dgb/config_pool.hpp>
#include <impl/dgb/conn_job_producer.hpp>
#include <impl/dgb/params.hpp>
#include <impl/dgb/run_loop_mint.hpp>
#include <impl/dgb/share.hpp>
#include <impl/dgb/share_check.hpp>
#include <impl/dgb/share_tracker.hpp>
#include <impl/dgb/stratum/work_source.hpp>

#include <btclibs/util/strencodings.h>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;

constexpr uint32_t kHeight = 20000000;   // the DGB block the jobs are for
constexpr int kShares = 130;

std::string hex(const Bytes& b) { return HexStr(Span<const unsigned char>(b.data(), b.size())); }

Bytes p2pkh(unsigned char f) { Bytes s{0x76, 0xa9, 0x14}; s.insert(s.end(), 20, f); s.push_back(0x88); s.push_back(0xac); return s; }
Bytes p2sh(unsigned char f) { Bytes s{0xa9, 0x14}; s.insert(s.end(), 20, f); s.push_back(0x87); return s; }
Bytes p2wpkh(const Bytes& prog) { Bytes s{0x00, 0x14}; s.insert(s.end(), prog.begin(), prog.end()); return s; }

// The payout of share i: D, S, dgb1q, and a dgb1q whose program starts 0x00.
Bytes payout_of(int i)
{
    switch (i % 4) {
    case 0: return p2pkh(0xa1);
    case 1: return p2sh(0xb2);
    case 2: return p2wpkh(Bytes(20, 0xc3));
    default: {
        Bytes prog(20, 0xd4);
        prog[0] = 0x00;
        return p2wpkh(prog);
    }
    }
}

// The gap before share i: 15 s, with two long ones (R4: no V35 decay).
uint32_t gap_before(int i) { return i == 60 ? 400u : i == 100 ? 5000u : 15u; }

core::CoinParams oracle_params()
{
    auto p = dgb::make_coin_params(/*testnet=*/false);
    p.pow_func = [](std::span<const unsigned char>) { return uint256(); };   // PoW is not under test
    return p;
}

struct OracleRig {
    core::CoinParams params = oracle_params();
    dgb::ShareTracker tracker;
    c2pool::dgb::HeaderChain hc;
    dgb::coin::Mempool mempool;
    std::unique_ptr<dgb::stratum::DGBWorkSource> ws;
    uint32_t now = 0;
    uint256 minted;
    std::vector<uint256> order;   // shares in chain order

    OracleRig()
    {
        hc.set_base_height(kHeight);
        auto submit = [](const std::vector<unsigned char>&, uint32_t) -> bool { return false; };
        ws = std::make_unique<dgb::stratum::DGBWorkSource>(
            hc, mempool, false, submit, [](uint32_t h) -> uint64_t { return dgb::CoinParams::subsidy(h); });
        ws->set_gbt_tip_fn([]() -> std::optional<dgb::stratum::DGBWorkSource::GbtTip> {
            return dgb::stratum::DGBWorkSource::GbtTip{std::string(56, '0') + "0badf00d", "1b0404cb", kHeight};
        });
        // main_dgb's producer, held at V35 (DgbVersionPolicy without --v36-ratchet).
        ws->set_pplns_inputs_fn([this](const uint256& prev, const std::string&, const Bytes& payout,
                                       const std::vector<std::pair<uint32_t, Bytes>>& merged, const Bytes& aux,
                                       const dgb::stratum::DGBWorkSource::JobBlock& block)
                                    -> std::optional<dgb::coin::ConnCoinbasePplnsInputs> {
            dgb::ConnJobRequest req;
            req.prev_share_hash = prev;
            req.payout_script = payout;
            req.merged_addrs = merged;
            req.next_block_height = block.height;
            req.block_bits = block.bits;
            req.block_value = block.value;
            req.local_hash_rate = block.local_hash_rate;
            req.now = now;
            req.donation = 66;
            req.aux_mm_scriptsig = aux;
            return dgb::build_conn_job_inputs(tracker, params, req, []() {
                return std::pair<int64_t, uint64_t>{35, 35};
            });
        });
        ws->set_mint_share_fn([this](const dgb::stratum::DGBWorkSource::MintShareInputs& in) -> uint256 {
            auto hdr = dgb::parse_min_header_80(in.header_bytes);
            if (!hdr)
                return uint256();
            minted = dgb::mint_local_share_at_frozen_version(in, *hdr, tracker, params, 66);
            return minted;
        });
    }

    uint32_t tip_ts()
    {
        uint32_t ts = 0;
        tracker.chain.get(order.back()).share.invoke([&](auto* s) { ts = s->m_timestamp; });
        return ts;
    }

    void genesis(uint32_t t0)
    {
        dgb::coin::SmallBlockHeaderType h;
        h.m_version = 0x20000202;
        h.m_previous_block.SetHex(std::string(56, '0') + "0badf00d");
        h.m_timestamp = t0;
        h.m_bits = 0x1b0404cb;
        h.m_nonce = 7;
        BaseScript cb;
        cb.m_data = dgb::coin::build_coinbase_scriptsig(kHeight);
        // V35 is segwit-activated: the genesis share carries the coinbase-only
        // segwit_data and the P2Pool witness commitment, as every V35 share.
        const auto commit = dgb::p2pool_witness_commitment_script(uint256());
        const uint256 g = dgb::create_local_share_v35(tracker, params, h, cb, dgb::CoinParams::subsidy(kHeight),
                                                      uint256(), {}, payout_of(0), 66, dgb::StaleInfo::none,
                                                      /*segwit_active=*/true, hex(commit), {}, uint256(), 0, 0, 0,
                                                      uint128(), uint256(), 0, false, {}, uint256(),
                                                      /*desired_version=*/35);
        ASSERT_FALSE(g.IsNull());
        order.push_back(g);
    }

    // A share made directly by create_local_share_v35 on the tip (no stratum
    // job): the second share of a new chain, which the job producer does not
    // build (its PPLNS walk starts at the grandparent: empty there).
    void direct(int i)
    {
        const uint32_t ts = tip_ts() + gap_before(i);
        dgb::coin::SmallBlockHeaderType h;
        h.m_version = 0x20000202;
        h.m_previous_block.SetHex(std::string(56, '0') + "0badf00d");
        h.m_timestamp = ts;
        h.m_bits = 0x1b0404cb;
        h.m_nonce = static_cast<uint32_t>(7 + i);
        BaseScript cb;
        cb.m_data = dgb::coin::build_coinbase_scriptsig(kHeight);
        const auto commit = dgb::p2pool_witness_commitment_script(uint256());
        const uint256 s = dgb::create_local_share_v35(tracker, params, h, cb, dgb::CoinParams::subsidy(kHeight),
                                                      order.back(), {}, payout_of(i), 66, dgb::StaleInfo::none,
                                                      /*segwit_active=*/true, hex(commit), {}, uint256(), 0, 0, 0,
                                                      uint128(), uint256(), 0, false, {}, uint256(),
                                                      /*desired_version=*/35);
        ASSERT_FALSE(s.IsNull());
        order.push_back(s);
    }

    // One share by the stratum path; returns false if it was not minted.
    bool mine(int i)
    {
        now = tip_ts() + gap_before(i);
        auto cbr = ws->build_connection_coinbase(order.back(), "cafef00d", payout_of(i), {});
        if (cbr.held || cbr.coinb1.empty())
            return false;
        core::stratum::JobSnapshot j;
        j.has_payout = true;
        j.payout_script = payout_of(i);
        j.coinb1 = cbr.coinb1;
        j.coinb2 = cbr.coinb2;
        j.gbt_prevhash = cbr.snapshot.gbt_prevhash;
        j.nbits = cbr.snapshot.block_nbits_hex;
        j.version = cbr.snapshot.header_version;
        j.share_bits = 0x2100ffffu;          // every hash is a share (PoW stubbed)
        j.block_nbits = "03000001";          // never a block
        j.prev_share_hash = order.back();
        j.subsidy = cbr.snapshot.subsidy;
        j.frozen_ref = cbr.snapshot.frozen_ref;
        char en2[9], ntime[9];
        std::snprintf(en2, sizeof en2, "%08x", static_cast<unsigned>(i));
        std::snprintf(ntime, sizeof ntime, "%08x", cbr.snapshot.frozen_ref.timestamp);
        minted = uint256();
        // The job carries its payout (has_payout): the username only labels the log.
        auto r = ws->mining_submit("oracle-miner", "job", "cafef00d", en2, ntime, "00c0ffee", "rid", {}, &j);
        if (!(r.is_boolean() && r.get<bool>()) || minted.IsNull())
            return false;
        order.push_back(minted);
        return true;
    }
};

// This node's checks of one share, as a peer receiving it runs them.
std::string own_check(OracleRig& rig, const dgb::PaddingBugfixShare& s)
{
    try {
        dgb::share_init_verify(s, rig.params, /*check_pow=*/false);
        dgb::check_v35_share_info(s, rig.tracker, rig.params);
    } catch (const std::exception& e) {
        return e.what();
    }
    return {};
}

std::string packed_hex(const dgb::PaddingBugfixShare& s)
{
    dgb::ShareType st;
    st = new dgb::PaddingBugfixShare(s);
    auto ps = pack(st);
    Bytes b(reinterpret_cast<const unsigned char*>(ps.data()),
            reinterpret_cast<const unsigned char*>(ps.data()) + ps.size());
    return hex(b);
}

} // namespace

TEST(DgbOracleVectors, MintedChainPassesOwnChecksAndIsDumped)
{
    OracleRig rig;
    const uint32_t t0 = static_cast<uint32_t>(std::time(nullptr)) - 4u * 3600u;
    rig.genesis(t0);
    rig.direct(1);
    for (int i = 2; i < kShares; ++i)
        ASSERT_TRUE(rig.mine(i)) << "share " << i << " was not minted";
    ASSERT_EQ(rig.order.size(), static_cast<size_t>(kShares));

    nlohmann::json out;
    out["oracle"] = "frstrtr/p2pool-dgb-scrypt 22761e7";
    out["net"] = "digibyte";
    out["shares"] = nlohmann::json::array();
    out["negatives"] = nlohmann::json::array();
    for (size_t k = 0; k < rig.order.size(); ++k) {
        const uint256 h = rig.order[k];
        rig.tracker.chain.get(h).share.invoke([&](auto* s) {
            using S = std::remove_pointer_t<decltype(s)>;
            if constexpr (std::is_same_v<S, dgb::PaddingBugfixShare>) {
                // Own checks of the share against the chain before it.
                EXPECT_EQ(own_check(rig, *s), "") << "share " << k;
                dgb::coin::GentxCoinbase gentx;
                const uint256 txid = dgb::generate_share_transaction(*s, rig.tracker, rig.params, false, false, &gentx);
                nlohmann::json v;
                v["type"] = 35;
                v["contents"] = packed_hex(*s);
                v["hash"] = h.GetHex();
                v["gentx"] = hex(gentx.bytes);
                v["gentx_txid"] = txid.GetHex();
                v["address"] = std::string(s->m_address.m_data.begin(), s->m_address.m_data.end());
                out["shares"].push_back(v);
                // Mutated copies of later shares: both implementations must reject them.
                if (k == 105 || k == 120) {
                    struct Mut { const char* name; std::function<void(dgb::PaddingBugfixShare&)> f; };
                    const std::vector<Mut> muts = {
                        {"max_bits+1", [](auto& m) { m.m_max_bits += 1; }},
                        {"bits easier than the pool target", [](auto& m) {
                             m.m_bits = chain::target_to_bits_upper_bound(chain::bits_to_target(m.m_max_bits) * 2);
                         }},
                        {"timestamp = previous", [&](auto& m) {
                             rig.tracker.chain.get(m.m_prev_hash).share.invoke([&](auto* p) { m.m_timestamp = p->m_timestamp; });
                         }},
                    };
                    for (const auto& mu : muts) {
                        auto m = *s;
                        mu.f(m);
                        EXPECT_NE(own_check(rig, m), "") << mu.name << " at " << k << " passed this node's checks";
                        nlohmann::json n;
                        n["name"] = mu.name;
                        n["before"] = k;   // checked with shares [0, k) in the tracker
                        n["type"] = 35;
                        n["contents"] = packed_hex(m);
                        out["negatives"].push_back(n);
                    }
                }
            } else {
                ADD_FAILURE() << "share " << k << " is not V35";
            }
        });
    }

    if (const char* path = std::getenv("DGB_ORACLE_VECTORS")) {
        std::ofstream f(path);
        ASSERT_TRUE(f.good()) << path;
        f << out.dump(1);
        std::printf("[oracle-vectors] wrote %zu shares + %zu negatives to %s\n", out["shares"].size(),
                    out["negatives"].size(), path);
    }
}
