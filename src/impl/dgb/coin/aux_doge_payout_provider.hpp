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
#include <impl/dgb/address_encoding.hpp>     // dgb::address_acceptance (owner's DGB address)
#include <impl/dgb/share_check.hpp>          // resolve_merged_payout_script, is_merged_key

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
#include <memory>
#include <mutex>
#include <functional>
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
/// (DOGE P2PKH 30 "D..." mainnet, 113 "n..." testnet, 111 "m..." regtest,
/// from aux_chain_params_table). "" only if c2pool had no DOGE address
/// parameters.
inline std::string doge_fallback_payout_address(bool testnet, bool regtest = false)
{
    const auto* p = c2pool::merged::find_aux_chain_params("DOGE");
    if (!p)
        return {};
    const auto& v = regtest ? p->regtest : testnet ? p->test : p->main;
    if (v.p2pkh.empty() || v.p2sh.empty())
        return {};
    return core::script_to_address(doge_fallback_payout_script(), std::string(),
                                   v.p2pkh.front(), v.p2sh.front());
}

/// Operator rule, 2026-11-27 ("honest split + warning"). Node-local, on the
/// DOGE payout path only; DGB consensus, share content and merged_payout_hash
/// are unchanged.
///
/// Rule: a share whose DGB payout key is a P2SH (any "S...") and that names no
/// DOGE address of its own (no Tier-1 merged address) is not paid as the same
/// P2SH on DOGE. A DigiByte Core p2sh-segwit address is P2SH(0014<keyhash>),
/// which becomes spendable by anyone on DOGE (no segwit) once a DGB spend
/// reveals the redeem script. That key's DOGE amount `a` is paid as:
///   - owner    = floor(a / 2) to the node owner's DOGE script;
///   - donation = a - owner (the odd satoshi) to the donation script;
///   - all of it to the donation when no owner script is set, or when the
///     owner part rounds to 0 (a == 1): never a 0-value output.
/// Both parts merge into existing outputs for the same scripts. The >= 1 sat
/// donation rule holds after the split: the core rule is skipped when a P2SH
/// amount >= 1 is to be split (its donation part is >= 1), and applies as
/// before otherwise. The sum is unchanged. An explicit DOGE address always wins; P2PKH, P2WPKH and every
/// other key are paid as before.
struct DogeP2shSplit {
    std::vector<unsigned char> owner_script;   // empty: the whole amount to the donation
};

namespace detail {
// A P2SH weight key's internal placeholder while the split is computed (never
// a script: the leading 0xff opcode is invalid, and the key follows).
inline const std::vector<unsigned char>& p2sh_split_tag()
{
    static const std::vector<unsigned char> t{0xff, 'p', '2', 's', 'h', '-', 's', 'p', 'l', 'i', 't'};
    return t;
}
inline bool is_p2sh_script(const std::vector<unsigned char>& s)
{
    return s.size() == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87;
}
} // namespace detail

/// Applies the split to the payouts of get_merged_expected_payouts called with
/// the split resolver (keys tagged by detail::p2sh_split_tag).
inline void apply_doge_p2sh_split(std::map<std::vector<unsigned char>, uint64_t>& payouts,
                                  const DogeP2shSplit& rule,
                                  const std::vector<unsigned char>& donation_script)
{
    const auto& tag = detail::p2sh_split_tag();
    uint64_t to_donation = 0;
    std::map<std::vector<unsigned char>, uint64_t> to_owner;
    for (auto it = payouts.begin(); it != payouts.end();) {
        if (it->first.size() > tag.size() && std::equal(tag.begin(), tag.end(), it->first.begin())) {
            const uint64_t a = it->second;
            const uint64_t owner = rule.owner_script.empty() ? 0 : a / 2;
            if (owner > 0)
                to_owner[rule.owner_script] += owner;
            to_donation += a - owner;
            it = payouts.erase(it);
        } else {
            ++it;
        }
    }
    for (const auto& [script, amount] : to_owner)
        payouts[script] += amount;
    if (to_donation > 0)
        payouts[donation_script] += to_donation;
}

/// The DOGE coinbase split at `best` for `chain_id`: the share chain's PPLNS
/// merged payouts, sorted, zero-amount entries dropped. Empty (with `miss`
/// set) when there is nothing to split at. With `p2sh_split`, the operator's
/// P2SH rule above applies.
template <typename TrackerT>
DogePayouts doge_merged_payouts(TrackerT& tracker, const uint256& best, uint32_t chain_id,
                                uint64_t coinbase_value, std::string& miss,
                                const DogeP2shSplit* p2sh_split = nullptr)
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
    // The split rule's resolver: a P2SH parent key (not a Tier-1 merged
    // address) gets a placeholder of its own, so its amount is never merged
    // with an explicit DOGE address's before the split.
    std::function<std::vector<unsigned char>(const std::vector<unsigned char>&)> resolve;
    if (p2sh_split)
        resolve = [](const std::vector<unsigned char>& key) -> std::vector<unsigned char> {
            if (!is_merged_key(key) && detail::is_p2sh_script(key)) {
                std::vector<unsigned char> t = detail::p2sh_split_tag();
                t.insert(t.end(), key.begin(), key.end());
                return t;
            }
            return resolve_merged_payout_script(key);
        };
    // The split routes a - floor(a/2) >= 1 of every placeholder amount a >= 1 to
    // the donation, so the core's >= 1 sat donation rule (which would take
    // that sat from the largest entry, possibly a placeholder, and make the
    // split 49/51) is left to the split: exactly 50/50, the odd sat to the
    // donation, and the donation still >= 1.
    std::function<bool(const std::vector<unsigned char>&)> donation_sink;
    if (p2sh_split)
        donation_sink = [](const std::vector<unsigned char>& s) {
            const auto& tag = detail::p2sh_split_tag();
            return s.size() > tag.size() && std::equal(tag.begin(), tag.end(), s.begin());
        };
    try {
        payouts_map = tracker.get_merged_expected_payouts(best, block_target, coinbase_value, chain_id,
                                                          donation_script, {}, {}, resolve, donation_sink);
    } catch (const std::exception& e) {
        LOG_WARNING << "[DGB-MM] get_merged_expected_payouts threw: " << e.what();
        miss = "payouts_threw";
        return {};
    }
    if (p2sh_split)
        apply_doge_p2sh_split(payouts_map, *p2sh_split, donation_script);
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

/// The node owner's DOGE script, for the P2SH split's owner half (and the
/// operator's own shares). The rule C2POOL gave the LTC lane:
///   - an explicit DOGE address (--node-owner-merged-address /
///     --merged-operator-address) when it is a DOGE address of this network;
///   - else the owner's DGB key as a DOGE P2PKH, when --node-owner-address is
///     a DGB P2PKH or P2WPKH (the same hash160);
///   - else (P2SH owner, no owner, unusable address) empty: the donation.
/// `source` names the choice for the log.
inline std::vector<unsigned char> doge_owner_script(const std::string& owner_dgb_address,
                                                    const std::string& owner_doge_address,
                                                    bool testnet, bool regtest, std::string& source)
{
    if (!owner_doge_address.empty()) {
        if (const auto* p = c2pool::merged::find_aux_chain_params("DOGE")) {
            const auto v = c2pool::merged::aux_accepted_versions(
                *p, testnet || regtest ? c2pool::merged::AuxNetwork::testnet : c2pool::merged::AuxNetwork::mainnet);
            std::vector<unsigned char> script;
            if (core::classify_address_for_coin(owner_doge_address, v.p2pkh, v.p2sh, v.hrps, script)
                    == core::AddressCoinMatch::Own
                && !script.empty()) {
                source = "--node-owner-merged-address";
                return script;
            }
        }
        source = "donation (--node-owner-merged-address " + owner_doge_address
                 + " is not a DOGE address of this network)";
        return {};
    }
    std::vector<unsigned char> dgb_script;
    if (!owner_dgb_address.empty()
        && core::classify_address_for_coin(owner_dgb_address, dgb::address_acceptance(testnet, regtest), dgb_script)
               == core::AddressCoinMatch::Own) {
        const bool p2pkh = dgb_script.size() == 25 && dgb_script[0] == 0x76 && dgb_script[1] == 0xa9;
        const bool p2wpkh = dgb_script.size() == 22 && dgb_script[0] == 0x00 && dgb_script[1] == 0x14;
        if (p2pkh) {
            source = "--node-owner-address key (P2PKH)";
            return dgb_script;
        }
        if (p2wpkh) {
            std::vector<unsigned char> s{0x76, 0xa9, 0x14};
            s.insert(s.end(), dgb_script.begin() + 2, dgb_script.end());
            s.push_back(0x88);
            s.push_back(0xac);
            source = "--node-owner-address key (P2WPKH as P2PKH)";
            return s;
        }
        source = "donation (the --node-owner-address is not P2PKH/P2WPKH; set --node-owner-merged-address)";
        return {};
    }
    source = owner_dgb_address.empty() ? "donation (no --node-owner-address)"
                                       : "donation (--node-owner-address is not a DGB address)";
    return {};
}

/// The provider main_dgb registers with the merged-mining manager. NodeT is
/// dgb::NodeImpl (read_tracker()); the tracker lock is only tried, never
/// waited for. The tracker guard is taken FIRST and the best share is read
/// while it is held, from `best_fn` (main_dgb: the stratum best-share cell,
/// refreshed on the IO thread under the guard; best_share_cell.hpp), else
/// from node->best_share_hash(). NodeImpl::best_share_hash reads the tracker
/// and the peer set unlocked, so it must not be called off the IO thread
/// without the guard; this runs on the merged-mining RPC thread and the
/// stratum IO thread.
/// A busy tracker is a "tracker_busy" miss: the manager keeps the last block
/// built on the same parent, and `on_busy` (main_dgb: mark the payouts dirty
/// again) makes the next poll retry instead of keeping the old split until
/// the next best-share change or DOGE tip.
///
/// No payout basis is noted (as on the BTC parent lane): a DGB share carries
/// no merged_coinbase_info, so no peer re-derives the DOGE payouts from its
/// prev share, and a basis would make a busy-tracker rebuild after a best
/// share move drop the DOGE commitment instead of keeping the last block.
template <typename NodeT>
c2pool::merged::MergedMiningManager::PayoutProvider make_doge_payout_provider(
    NodeT* node, std::shared_ptr<const DogeP2shSplit> p2sh_split = std::make_shared<const DogeP2shSplit>(),
    std::function<uint256()> best_fn = {}, std::function<void()> on_busy = {})
{
    return [node, p2sh_split, best_fn, on_busy](uint32_t chain_id, uint64_t coinbase_value) -> DogePayouts {
        using c2pool::merged::MergedMiningManager;
        if (!node) {
            MergedMiningManager::note_payout_miss("no_node");
            return {};
        }
        auto guard = node->read_tracker();
        if (!guard) {
            MergedMiningManager::note_payout_miss("tracker_busy");
            if (on_busy)
                on_busy();
            return {};
        }
        const uint256 best = best_fn ? best_fn() : node->best_share_hash();
        if (best.IsNull()) {
            MergedMiningManager::note_payout_miss("no_best_share");
            return {};
        }
        std::string miss;
        auto result = doge_merged_payouts(*guard, best, chain_id, coinbase_value, miss, p2sh_split.get());
        if (result.empty()) {
            MergedMiningManager::note_payout_miss(miss.empty() ? "empty" : miss);
            return result;
        }
        // One line per new split (best share, DOGE value): what the DOGE
        // coinbase pays, for the operator (and the canary) to compare with the
        // share chain's PPLNS ([DOGE-PPLNS] weight lines).
        uint64_t sum = 0, largest = 0;
        for (const auto& [_, v] : result) {
            sum += v;
            largest = std::max(largest, v);
        }
        static std::mutex log_mu;
        static uint256 last_best;
        static uint64_t last_value = 0;
        std::lock_guard<std::mutex> lk(log_mu);
        if (best != last_best || coinbase_value != last_value) {
            last_best = best;
            last_value = coinbase_value;
            LOG_INFO << "[DGB-MM] DOGE payouts chain_id=" << chain_id << " best=" << best.GetHex().substr(0, 16)
                     << " value=" << coinbase_value << " outputs=" << result.size() << " sum=" << sum
                     << " largest=" << largest << (sum == coinbase_value ? "" : " SUM-MISMATCH");
        }
        return result;
    };
}

/// main_dgb's --merged DOGE wiring (the BTC parent lane's, main_btc.cpp
/// set_payout_provider / set_on_work_changed / mark_pplns_dirty), on the DGB
/// node and work source. A null manager (no --merged) binds NOTHING: no
/// provider, no work-change hook, so a standalone DGB node's coinbase stays
/// byte-identical. Returns whether it bound.
///   - provider: the PPLNS split at the best share (above);
///   - on_work_changed: a fresh aux tip or commitment re-pushes stratum jobs,
///     so miners never mine a stale DOGE commitment;
///   - one initial mark so the first job build populates the commitment.
/// The best-share change marks the payouts dirty through the node's ONE
/// best-change hook (best_share_cell.hpp wire_best_share, also_on_best), not
/// here: on_best_share_changed is a single slot.
template <typename NodeT, typename WorkSourceT>
bool wire_doge_merged_payouts(c2pool::merged::MergedMiningManager* mm, NodeT& node, WorkSourceT* ws,
                              std::shared_ptr<const DogeP2shSplit> p2sh_split = nullptr,
                              std::function<uint256()> best_fn = {})
{
    if (!mm)
        return false;
    // The work-change hook first: the merged-mining poll thread is already
    // running, so the hook must be in place before a provider can make it fire.
    mm->set_on_work_changed([ws]() {
        if (ws)
            ws->bump_work_generation();
    });
    mm->set_payout_provider(make_doge_payout_provider(
        &node, p2sh_split ? std::move(p2sh_split) : std::make_shared<const DogeP2shSplit>(),
        std::move(best_fn), [mm]() { mm->mark_pplns_dirty(); }));
    mm->mark_pplns_dirty();
    return true;
}

} // namespace dgb::coin
