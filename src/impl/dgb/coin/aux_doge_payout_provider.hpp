// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// DGB+DOGE merged mining: the DOGE payout provider and the DOGE fallback
// payout address, for the DGB-as-parent lane (main_dgb.cpp, --merged DOGE).
//
// PROVIDER. The merged-mining manager builds the DOGE block's coinbase
// itself (multiaddress mode) from the payouts a provider returns. Without a
// provider every rebuild records "no_provider" (merged_mining.cpp
// rebuild_cached_blocks), the commitment stays empty, the DGB coinbase never
// carries the fabe6d6d marker and no DOGE block can be found. This provider
// is the BTC parent lane's (main_btc.cpp set_payout_provider) on the DGB
// tracker: the PPLNS split of the DOGE coinbase value at the best share,
// from dgb::ShareTracker::get_merged_expected_payouts (the share chain's
// merged weights: a share's explicit merged address for the chain, else its
// parent script, with the V36 combined donation getting the donation weight
// and the rounding remainder).
//
// FALLBACK ADDRESS. AuxChainConfig::aux_payout_address is what
// createauxblock gets (the createauxblock / non-multiaddress path, and the
// RPC fallback backend): any DOGE value c2pool does not split itself goes
// there. It is the single P2PKH donation key c2pool-dash pays its donation
// output to (dash share_check.hpp DONATION_SCRIPT, XdgF55wEHBRWwbuBniNYH4G
// vvaoYMgL84u), rendered with DOGE's own P2PKH version byte, never a
// placeholder.
//
// Header-only and templated on the node so the KATs drive the real function
// on a populated tracker (dgb_work_source_test).
// ---------------------------------------------------------------------------

#include <impl/dgb/config_pool.hpp>          // dgb::PoolConfig::get_donation_script

#include <c2pool/merged/aux_chain_params.hpp> // find_aux_chain_params (DOGE version bytes)
#include <c2pool/merged/merged_mining.hpp>    // MergedMiningManager::PayoutProvider, note_payout_*

#include <core/address_utils.hpp>             // core::script_to_address
#include <core/log.hpp>
#include <core/target_utils.hpp>              // chain::bits_to_target
#include <core/uint256.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace dgb::coin {

using DogePayouts = std::vector<std::pair<std::vector<unsigned char>, uint64_t>>;

/// The DOGE AuxPoW chain id (dogecoin chainparams; the --merged DOGE:98 spec).
inline constexpr uint32_t DOGE_AUX_CHAIN_ID = 98;

/// hash160 of the single donation P2PKH c2pool-dash pays its donation output
/// to (dash share_check.hpp DONATION_SCRIPT = 76a914 <this> 88ac).
inline constexpr std::array<uint8_t, 20> DONATION_P2PKH_HASH160 = {
    0x20, 0xcb, 0x5c, 0x22, 0xb1, 0xe4, 0xd5, 0x94, 0x7e, 0x5c,
    0x11, 0x2c, 0x76, 0x96, 0xb5, 0x1a, 0xd9, 0xaf, 0x3c, 0x61,
};

/// OP_DUP OP_HASH160 <DONATION_P2PKH_HASH160> OP_EQUALVERIFY OP_CHECKSIG.
inline std::vector<unsigned char> doge_fallback_payout_script()
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    s.insert(s.end(), DONATION_P2PKH_HASH160.begin(), DONATION_P2PKH_HASH160.end());
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

/// The DOGE address of doge_fallback_payout_script() on the node's network
/// (DOGE P2PKH 30 "D..." mainnet, 113 "n..." testnet, from
/// aux_chain_params_table). "" only if c2pool had no DOGE address parameters.
inline std::string doge_fallback_payout_address(bool testnet)
{
    const auto* p = c2pool::merged::find_aux_chain_params("DOGE");
    if (!p)
        return {};
    const auto& v = testnet ? p->test : p->main;
    if (v.p2pkh.empty() || v.p2sh.empty())
        return {};
    return core::script_to_address(doge_fallback_payout_script(), std::string(),
                                   v.p2pkh.front(), v.p2sh.front());
}

/// The DOGE coinbase split at `best` for `chain_id`: the share chain's PPLNS
/// merged payouts, sorted, zero-amount entries dropped. Empty (with `miss`
/// set) when there is nothing to split at.
template <typename TrackerT>
DogePayouts doge_merged_payouts(TrackerT& tracker, const uint256& best, uint32_t chain_id,
                                uint64_t coinbase_value, std::string& miss)
{
    if (best.IsNull()) {
        miss = "no_best_share";
        return {};
    }
    if (!tracker.chain.contains(best)) {
        miss = "best_not_in_chain";
        return {};
    }
    // The aux block_target is the parent block target (p2pool: the best
    // share's min_header bits), not the share target.
    uint256 block_target;
    tracker.chain.get(best).share.invoke([&](auto* s) {
        block_target = chain::bits_to_target(s->m_min_header.m_bits);
    });
    // Merged chains commit the V36 combined donation (P2SH) whatever the
    // parent share version (p2pool data.py:303; the manager's coinbase
    // builder puts that script last).
    const auto donation_script = dgb::PoolConfig::get_donation_script(36);
    std::map<std::vector<unsigned char>, uint64_t> payouts_map;
    try {
        payouts_map = tracker.get_merged_expected_payouts(best, block_target, coinbase_value, chain_id,
                                                          donation_script, {}, {});
    } catch (const std::exception& e) {
        LOG_WARNING << "[DGB-MM] get_merged_expected_payouts threw: " << e.what();
        miss = "payouts_threw";
        return {};
    }
    // Map order: sorted by script, each script once (the sorted list the
    // provider contract asks for, without a re-sort).
    DogePayouts result;
    result.reserve(payouts_map.size());
    for (auto& [script, amount] : payouts_map)
        if (amount >= 1)
            result.emplace_back(script, amount);
    if (result.empty())
        miss = "empty";
    return result;
}

/// The provider main_dgb registers with the merged-mining manager. NodeT is
/// dgb::NodeImpl (best_share_hash(), read_tracker()); the tracker lock is
/// only tried, never waited for: a busy tracker is a "tracker_busy" miss
/// and the manager keeps the last block built on the same parent.
///
/// No payout basis is noted (as on the BTC parent lane): a DGB share carries
/// no merged_coinbase_info, so no peer re-derives the DOGE payouts from its
/// prev share, and a basis would make a busy-tracker rebuild after a best
/// share move drop the DOGE commitment instead of keeping the last block.
template <typename NodeT>
c2pool::merged::MergedMiningManager::PayoutProvider make_doge_payout_provider(NodeT* node)
{
    return [node](uint32_t chain_id, uint64_t coinbase_value) -> DogePayouts {
        using c2pool::merged::MergedMiningManager;
        if (!node) {
            MergedMiningManager::note_payout_miss("no_node");
            return {};
        }
        const uint256 best = node->best_share_hash();
        if (best.IsNull()) {
            MergedMiningManager::note_payout_miss("no_best_share");
            return {};
        }
        auto guard = node->read_tracker();
        if (!guard) {
            MergedMiningManager::note_payout_miss("tracker_busy");
            return {};
        }
        std::string miss;
        auto result = doge_merged_payouts(*guard, best, chain_id, coinbase_value, miss);
        if (result.empty())
            MergedMiningManager::note_payout_miss(miss.empty() ? "empty" : miss);
        return result;
    };
}

/// main_dgb's --merged DOGE wiring (the BTC parent lane's, main_btc.cpp
/// set_payout_provider / set_on_work_changed / mark_pplns_dirty), on the DGB
/// node and work source. A null manager (no --merged) binds NOTHING: no
/// provider, no best-share callback, no work-change hook, so a standalone DGB
/// node's coinbase and job pushes stay byte-identical. Returns whether it
/// bound.
///   - provider: the PPLNS split at the best share (above);
///   - on_work_changed: a fresh aux tip or commitment re-pushes stratum jobs,
///     so miners never mine a stale DOGE commitment;
///   - best share changed (NodeImpl IO phase, no tracker lock held): marks
///     the payouts dirty; the next poll or coinbase build rebuilds the DOGE
///     block for the new best share (MergedMiningManager::is_pplns_dirty);
///   - one initial mark so the first job build populates the commitment.
template <typename NodeT, typename WorkSourceT>
bool wire_doge_merged_payouts(c2pool::merged::MergedMiningManager* mm, NodeT& node, WorkSourceT* ws)
{
    if (!mm)
        return false;
    mm->set_payout_provider(make_doge_payout_provider(&node));
    mm->set_on_work_changed([ws]() {
        if (ws)
            ws->bump_work_generation();
    });
    node.set_on_best_share_changed([mm]() { mm->mark_pplns_dirty(); });
    mm->mark_pplns_dirty();
    return true;
}

} // namespace dgb::coin
