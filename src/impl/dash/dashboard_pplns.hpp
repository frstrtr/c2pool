// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH dashboard PPLNS read-model.
//
// Answers two questions with ONE code path:
//   1. "who does the pool owe right now?"  -> /current_payouts,
//      /current_merged_payouts (the main dashboard treemap) and the miners[]
//      array of /pplns/current.
//   2. "what did THIS share's window pay?" -> the per-share PPLNS treemap on
//      web-static/share.html (which reads window["pplns"][<short hash>], with
//      window["pplns_current"] as its fallback).
//
// Why DASH could not simply reuse the LTC route
// ---------------------------------------------
// LTC lights both from MiningInterface's own PPLNS cache:
//   set_pplns_fn  -> refresh_work() (web_server.cpp:1360) stores
//   m_cached_pplns_outputs, which rest_current_payouts() reads (:2401); and
//   start_pplns_precompute() (:2921) walks the window in a background thread,
//   calling m_pplns_fn once per share to fill m_pplns_per_tip.
// BOTH depend on refresh_work() having run: the precompute loop refuses to
// start until m_cached_template carries "bits" + "coinbasevalue" (:2947-2963).
// refresh_work() NEVER runs on the DASH lane — MiningInterface's own stratum
// acceptor is switched off (main_dash.cpp set_stratum_port(0)) and DASHWorkSource
// owns the coinbase; web_server.cpp:3902 states the invariant outright. So the
// LTC path would have wired green and stayed inert. That is the same class of
// bug this whole change is fixing, so it is not repeated here.
//
// Instead the payouts are computed DIRECTLY from the two SSOTs the DASH
// coinbase itself uses, which means the dashboard shows the same split a block
// found now would actually pay:
//   * dash::mint::pplns_weights_for  (mint_runloop.hpp:504) — the ORACLE window
//     walk (start at the grandparent, max(0, min(height, RCL)-1) shares).
//   * dash::coinbase::compute_dash_payouts (coinbase_builder.hpp:83) — the
//     payout allocator, including the pre-v36 49/50 split and the donation
//     remainder.
// No payout arithmetic is re-implemented here.
//
// Finder fee: compute_dash_payouts credits the pre-v36 2% block-finder fee to
// the caller-supplied pubkey hash. A pool-wide "current payouts" view has no
// finder (the next block's winner is unknown), so it is computed with a ZERO
// pubkey hash and the 2% slice is then held OUT of the rendered split. Since
// #1369 a zero pubkey hash emits no finder output at all (it used to emit an
// unspendable P2PKH(0x00..00) burn); the allocator sweeps the slice into the
// donation tail instead, so pplns_payouts_at subtracts it back out of the
// donation before rendering (see the guard at the render loop). Either way the
// pool-wide view sums to ~98% of the worker payout. This matches LTC exactly —
// share_tracker.hpp:2058 documents get_v35_expected_payouts as "amounts WITHOUT
// finder fee — caller adds subsidy/200", and main_ltc.cpp's pplns_fn returns it
// unmodified for the pre-v36 arm. The per-share view has a real finder (the
// share's own miner) and passes it.

#include "share_chain.hpp"
#include "share_check.hpp"       // DONATION_SCRIPT, decode_payee_script
#include "coinbase_builder.hpp"  // dash::coinbase::compute_dash_payouts
#include "mint_runloop.hpp"      // dash::mint::pplns_weights_for
#include "dashboard_views.hpp"   // script_to_dash_address
#include "coin/rpc_data.hpp"     // dash::coin::PackedPayment

#include <core/coin_params.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace dash {
namespace dashboard {

// ── Late-bound live template source ─────────────────────────────────────────
// The dashboard seams are bound while the WebServer is stood up
// (main_dash.cpp), which is BEFORE DASHWorkSource exists and before
// web_server->start() — so the window/payout callbacks cannot capture the work
// source directly, and a bare std::function assigned afterwards would be a data
// race against the already-serving IO thread. This holder publishes the peek
// under a mutex and COPIES IT OUT before calling, so the (tracker-locking)
// callee never runs with this mutex held.
//
// Unbound is a first-class state: it means "no template yet", and every caller
// answers an empty document rather than inventing a subsidy.
class TemplateSource
{
public:
    using PeekFn = std::function<std::shared_ptr<const dash::coin::DashWorkData>()>;

    void bind(PeekFn fn)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_peek = std::move(fn);
    }

    std::shared_ptr<const dash::coin::DashWorkData> peek() const
    {
        PeekFn fn;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            fn = m_peek;
        }
        if (!fn) return nullptr;
        return fn();
    }

private:
    mutable std::mutex m_mutex;
    PeekFn             m_peek;
};

// ── Result ──────────────────────────────────────────────────────────────────
struct PplnsView
{
    bool     ok{false};
    /// {address: amount in DASH} — PPLNS workers plus the donation output.
    /// Masternode / superblock / platform payments are EXCLUDED: they are
    /// consensus-mandated block outputs, not pool payouts, and folding them in
    /// would overstate what the pool distributes.
    nlohmann::json payouts = nlohmann::json::object();
    uint64_t subsidy{0};          ///< full block reward the split was taken from
    uint64_t payments_total{0};   ///< masternode + superblock + platform, satoshi
    uint64_t worker_payout{0};    ///< subsidy - payments_total
    int      recipients{0};
};

// ── Core builder ────────────────────────────────────────────────────────────
// `prev_share_hash` is the share the window is anchored on — i.e. the PARENT of
// the (hypothetical or real) share being paid, exactly as
// DASHWorkSource::build_connection_coinbase passes it.
//
// `block_bits` is the COIN block nBits for the difficulty epoch the payout
// belongs to; the caller takes it from the same place the mint does.
template <typename ChainT>
inline PplnsView pplns_payouts_at(
    ChainT& chain,
    const core::CoinParams& params,
    const uint256& prev_share_hash,
    uint32_t block_bits,
    uint64_t subsidy,
    const std::vector<dash::coin::PackedPayment>& packed_payments,
    const uint160& finder_pubkey_hash,
    bool drop_finder_output,
    bool testnet)
{
    PplnsView view;
    if (subsidy == 0 || prev_share_hash.IsNull() || !chain.contains(prev_share_hash))
        return view;

    auto weights = dash::mint::pplns_weights_for(chain, params, prev_share_hash, block_bits);
    if (!weights)
        return view;   // cold / too-short chain — honest miss, never a fake row

    std::vector<dash::coinbase::MinerPayout> outs;
    try {
        outs = dash::coinbase::compute_dash_payouts(
            subsidy, packed_payments, finder_pubkey_hash,
            weights->weights, weights->total_weight, params);
    } catch (const std::exception&) {
        return view;   // allocator sum-invariant tripped: report nothing, not a guess
    }

    // compute_dash_payouts emits, in this exact order (coinbase_builder.hpp:212):
    //     worker_tx (sorted by script) || payments_tx (GBT order) || donation_tx
    // so the masternode block is identified by COUNT, not by guessing which
    // scripts "look like" a payee — a masternode that also mines would otherwise
    // have its worker row misfiled. The count is step 1 of the same function:
    // zero-amount and undecodable payees are dropped.
    size_t n_payments = 0;
    for (const auto& p : packed_payments) {
        if (p.amount == 0) continue;
        if (dash::decode_payee_script(p.payee, params.address_version,
                                      params.address_p2sh_version).empty())
            continue;
        ++n_payments;
        view.payments_total += p.amount;
    }

    view.subsidy       = subsidy;
    view.worker_payout = (subsidy > view.payments_total)
                       ? (subsidy - view.payments_total) : 0;

    if (outs.size() < n_payments + 1)
        return view;   // shape violated — do not slice blind
    const size_t n_workers = outs.size() - n_payments - 1;

    const std::vector<unsigned char> finder_script =
        dash::pubkey_hash_to_script2(finder_pubkey_hash);

    auto add = [&](const dash::coinbase::MinerPayout& o) {
        if (o.amount == 0) return;
        if (drop_finder_output && o.script == finder_script) return;
        std::string addr = script_to_dash_address(o.script, testnet);
        if (addr.empty()) addr = HexStr(o.script);
        const double amt = static_cast<double>(o.amount) / 1e8;
        if (view.payouts.contains(addr))
            view.payouts[addr] = view.payouts[addr].get<double>() + amt;
        else
            view.payouts[addr] = amt;
    };

    // #1369 follow-up (money-path DISPLAY parity). Before #1369 an ownerless
    // coinbase (zero finder pubkey hash) still emitted a P2PKH(0x00..00) burn
    // output carrying the pre-v36 2% block-finder slice, and this pool-wide
    // view dropped exactly that zero-pkh output (the `add` lambda's
    // finder_script match), so it summed to ~98% of worker_payout — the LTC
    // contract in the header note (finder fee omitted; the next block's winner
    // is unknown). #1369 stopped the burn: compute_dash_payouts now emits NO
    // zero-pkh output and step 5's remainder sweeps the slice into the donation
    // tail instead, so there is nothing left for the drop to match and the view
    // sums to the full 100%. Subtract the swept slice back out of the donation
    // here so the rendered pool-wide split is byte-for-byte the pre-#1369
    // number. This fires ONLY on the zero-finder pool-wide arm; the per-share
    // view (real, non-null finder — drop_finder_output=false) and the v36 arm
    // (no finder fee at all) are untouched. Display only: no mint/serve/coinbase
    // path reads this view.
    if (drop_finder_output && finder_pubkey_hash.IsNull()
        && !core::version_gate::is_v36_active(params.current_share_version)
        && !outs.empty()) {
        const uint64_t finder_slice = view.worker_payout / 50;  // == coinbase_builder step 4
        dash::coinbase::MinerPayout& donation = outs.back();
        const std::vector<unsigned char> donation_script(
            dash::DONATION_SCRIPT.begin(), dash::DONATION_SCRIPT.end());
        if (donation.script == donation_script && donation.amount >= finder_slice)
            donation.amount -= finder_slice;
    }

    for (size_t i = 0; i < n_workers; ++i)
        add(outs[i]);
    add(outs.back());   // donation

    view.recipients = static_cast<int>(view.payouts.size());
    view.ok = !view.payouts.empty();
    return view;
}

// ── Per-share convenience wrapper ───────────────────────────────────────────
// The PPLNS breakdown carried BY a share: its own recorded block reward
// (m_subsidy), its own masternode payment set (m_packed_payments), its own
// difficulty epoch (m_min_header.m_bits) and its own miner as the 2% finder —
// i.e. the coinbase that share's gentx actually committed to. The window is
// anchored on the share's PARENT, which is what
// DASHWorkSource::build_connection_coinbase / mint_runloop's producer path pass
// as prev_share_hash when building this very share (mint_runloop.hpp:181).
template <typename ChainT>
inline PplnsView pplns_payouts_for_share(ChainT& chain,
                                         const core::CoinParams& params,
                                         const uint256& share_hash,
                                         bool testnet)
{
    if (share_hash.IsNull() || !chain.contains(share_hash))
        return {};

    uint256  parent;
    uint32_t block_bits = 0;
    uint64_t subsidy    = 0;
    uint160  finder;
    std::vector<dash::coin::PackedPayment> payments;

    chain.get_share(share_hash).invoke([&](auto* obj) {
        parent     = obj->m_prev_hash;
        block_bits = obj->m_min_header.m_bits;
        subsidy    = obj->m_subsidy;
        finder     = obj->m_pubkey_hash;
        payments.reserve(obj->m_packed_payments.size());
        for (const auto& p : obj->m_packed_payments)
            payments.push_back({p.m_payee, p.m_amount});
    });

    return pplns_payouts_at(chain, params, parent, block_bits, subsidy, payments,
                            finder, /*drop_finder_output=*/false, testnet);
}

// ── Pool-wide convenience wrapper ───────────────────────────────────────────
// "What would a block found RIGHT NOW pay?" — the pool-wide PPLNS split over the
// window anchored on the node's current best share. Finder fee omitted (see the
// header note).
//
// Two param sources, in strict precedence:
//   1. LIVE TEMPLATE (preferred): the GBT template's reward + masternode payment
//      set. This is the freshest possible answer — the exact split a block found
//      now would pay — and is what a node WITH miners (a stratum session pumped
//      the template cache) always takes.
//   2. BEST-SHARE SNAPSHOT (fallback): when no template is cached — a fully
//      daemonless node with ZERO local miners never pumps the template cache, so
//      tmpl.peek() is permanently null there — derive the block params from the
//      BEST SHARE's own recorded fields (m_subsidy, m_min_header.m_bits,
//      m_packed_payments), exactly as pplns_payouts_for_share reads them for the
//      per-share view. The window walk (pplns_weights_for) and the allocation
//      (compute_dash_payouts) are identical; only the subsidy/bits/payee source
//      differs. This is p2pool parity: get_expected_payouts (data.py:3273) takes
//      subsidy + block_target as PARAMETERS and its only empty guard is a
//      missing best share — there is no live-template coupling. The pool-wide
//      PPLNS view therefore renders from the sharechain alone, with no local
//      hashrate, which is the whole point of the dashboard on a bootstrap node.
//
// The snapshot subsidy/payees are the best SHARE's epoch, so on a reward-
// reduction boundary or a masternode-payee rotation they lag the next block by
// at most one federation share; acceptable for a DISPLAY view and never fed back
// into any mint/coinbase path. Empty best share -> {} (the one legitimate p2pool
// empty guard) is retained.
template <typename ChainT>
inline PplnsView pplns_payouts_current(ChainT& chain,
                                       const core::CoinParams& params,
                                       const uint256& best_share_hash,
                                       const TemplateSource& tmpl,
                                       bool testnet)
{
    // 1. Live template — the fresh, preferred source (nodes WITH miners).
    if (auto t = tmpl.peek(); t && t->m_coinbase_value != 0)
        return pplns_payouts_at(chain, params, best_share_hash, t->m_bits,
                                t->m_coinbase_value, t->m_packed_payments,
                                uint160(), /*drop_finder_output=*/true, testnet);

    // 2. Best-share snapshot — no template cached (zero-local-miner node). Read
    //    the block params the best share itself committed to and split over the
    //    SAME window (anchored on best_share_hash). Read-only: the best share's
    //    bytes are untouched; nothing here can change a served coinbase.
    if (best_share_hash.IsNull() || !chain.contains(best_share_hash))
        return {};   // empty sharechain — p2pool's one legitimate empty guard

    uint32_t block_bits = 0;
    uint64_t subsidy    = 0;
    std::vector<dash::coin::PackedPayment> payments;
    chain.get_share(best_share_hash).invoke([&](auto* obj) {
        block_bits = obj->m_min_header.m_bits;
        subsidy    = obj->m_subsidy;
        payments.reserve(obj->m_packed_payments.size());
        for (const auto& p : obj->m_packed_payments)
            payments.push_back({p.m_payee, p.m_amount});
    });
    if (subsidy == 0)
        return {};   // share carried no recorded reward — no honest claim

    return pplns_payouts_at(chain, params, best_share_hash, block_bits, subsidy,
                            payments, uint160(), /*drop_finder_output=*/true,
                            testnet);
}

} // namespace dashboard
} // namespace dash
