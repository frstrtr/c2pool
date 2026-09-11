// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_native_template_backend.hpp   (M2)
//
// THE M2 REBIND, from the consumer side: the option-B K_fair settlement
// coinbase, built from the NATIVE Monero node instead of from a daemon RPC.
//
// M0 assembled the native node and proved it follows a live tip over levin. M1
// proved its transaction pool equals monerod's, per transaction. C4 landed the
// IMinerDataSource seam and both of its arms. What was left -- and what this
// file is -- is the wire between them: a running NativeNode, its serving arm
// resolved per refresh, handed to the UNMODIFIED XmrSettlementTemplateProvider
// so the assembler above the seam builds the same coinbase it always did from
// numbers no daemon supplied.
//
//   NativeNode (C1 levin + C2 chain index + C3 txpool)
//        |                                   |
//        |  IChainView                       |  ITxpoolSnapshot / ITxBlobSource
//        v                                   v
//   C4 NativeMinerDataSource  ── ArmResolver ──> ResolvedMinerDataSource
//        (MonerodMinerDataSource is the SHADOW arm, read only by C6)
//                                                       |
//                                                       v  IMinerDataSource
//                             XmrSettlementTemplateProvider  (UNCHANGED)
//                                                       |
//                                                       v
//                             the K_fair settlement coinbase, in a block
//
// WHAT "NATIVE" MEANS HERE, precisely. With `--xmr-template-source native` and
// the fallback off, the template path performs ZERO monerod calls: height,
// prev_id, seed_hash, difficulty, median weight, already_generated_coins and
// the major version all come out of the C2 index, and the backlog out of the C3
// pool. The daemon endpoint is still configured, because M2 keeps monerod as
// the PARITY JUDGE (C6 reads it as the shadow arm) and as the submit arm
// (R-ARMORDER DaemonFirst on bring-up) -- but neither of those is the template
// path, and rpc_calls() is reported next to the template counters so the claim
// is falsifiable rather than asserted.
//
// FAIL-CLOSED, twice over. The native arm's readiness is per-input (tip, seed
// reach, difficulty window, weight window, coins, hard fork); until every one of
// them is true, resolve() returns false and no template is built. And with
// fallback disabled there is no second answer: a native arm that loses its
// window stops serving rather than quietly serving monerod's numbers under a
// "native" label.
//
// THREADING. start() spins the node's own io / verify / pool threads. Everything
// this class exposes is called from the MAIN thread (the provider's refresh
// cadence); the node's status()/parity_sample() do their own thread hops.
//
// SCOPE FENCE: consumer tree. No consensus digest is defined and
// src/sharechain/v37 is not touched.
// ===========================================================================
#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "impl/xmr/native/node/xmr_native_node.hpp"
#include "impl/xmr/native/template/xmr_resolved_miner_data.hpp"

namespace c2pool::v37n::xmr::o2 {

namespace native = ::c2pool::xmr::native;
namespace ntmpl  = ::c2pool::xmr::native::tmpl;
namespace nrt    = ::c2pool::xmr::native::rt;

// Everything the operator picks for the native template path. Deliberately a
// flat struct rather than a second copy of NativeNodeConfig: these are the
// fields main_v37_xmr's flags set, and the rest of the node's configuration is
// derived (below) so a new node knob does not silently become a daemon flag.
struct NativeTemplateConfig {
    nrt::NativeNet           net = nrt::NativeNet::Stagenet;
    std::vector<std::string> connect;        // pinned "ip:port" levin peers
    std::string              p2p_bind_ip;    // source address for outbound dials
    bool                     use_seeds = false;

    nrt::BootMode            boot = nrt::BootMode::Genesis;
    std::string              anchor_path;

    // The PARITY / SUBMIT daemon. Not the template path; see the banner.
    std::string              monerod_rpc_host;
    std::uint16_t            monerod_rpc_port = 0;

    // Serve from the native arm, shadow the other one. Flipping `serve` to
    // Monerod is the M2 ladder's first rung (serve=monerod / shadow=native).
    native::TemplateArm      serve = native::TemplateArm::Native;

    // M3 (R-ARMORDER): which arm a FOUND block goes out on. DaemonFirst is the
    // default and is what M0..M2h ran -- though under it the POOL, not this
    // node, does the submitting (the node's own daemon sink is empty), so C5
    // is simply not on the path at all. P2pOnly is --arm-order p2p-first: the
    // block goes out as a levin 2008 and monerod is never asked.
    native::ArmOrder         relay_order = native::ArmOrder::DaemonFirst;

    // Fall back to the other arm when the serving arm is not ready. ON is the
    // production posture; the M2 evidence run turns it OFF so that "no monerod
    // call on the template path" cannot be satisfied by a silent fallback.
    bool                     fallback = true;

    // A private chain with one pinned peer cannot tell "at the tip" from
    // "alone", so the publication gate is set rather than inferred (OR-C2-8).
    bool                     force_synced = false;

    // Rebuild the served template when the POOL moves, not only when the tip
    // does, at most once per this many seconds. 0 = tip-only, which is what
    // shipped and is byte-identical to it. See NativeNodeConfig for why a
    // tip-only native arm collects almost no fees.
    std::uint64_t            backlog_refresh_s = 0;

    // A build without librandomx cannot check proof of work. Opt-in, loud.
    bool                     allow_unverified_pow = false;

    bool                     parity = true;
    std::string              parity_ledger_path;
    std::string              c2pool_commit;

    // How long start_and_wait() gives the node to reach a ready native arm.
    std::uint32_t            ready_timeout_s = 120;

    // D-14 / c2pool#1551: the fork choice's rule at EQUAL cumulative difficulty
    // at the same height. Driven from the same --same-height-tiebreak flag the
    // settlement accounting reads, so "what we build on" and "what we nominate"
    // cannot be configured apart.
    native::TieBreak         fork_tie = native::TieBreak::PreferOwn;
};

class NativeTemplateBackend {
public:
    explicit NativeTemplateBackend(NativeTemplateConfig cfg) : cfg_(std::move(cfg)) {}

    NativeTemplateBackend(const NativeTemplateBackend&)            = delete;
    NativeTemplateBackend& operator=(const NativeTemplateBackend&) = delete;

    ~NativeTemplateBackend() { stop(); }

    // Start the native node and build the resolved source over its arms.
    bool start(std::string& why) {
        nrt::NativeNodeConfig nc;
        nc.net                  = cfg_.net;
        nc.connect              = cfg_.connect;
        nc.p2p_bind_ip          = cfg_.p2p_bind_ip;
        nc.use_seeds            = cfg_.use_seeds;
        nc.boot                 = cfg_.boot;
        nc.anchor_path          = cfg_.anchor_path;
        nc.allow_unverified_pow = cfg_.allow_unverified_pow;
        nc.monerod_rpc_host     = cfg_.monerod_rpc_host;
        nc.monerod_rpc_port     = cfg_.monerod_rpc_port;
        nc.parity               = cfg_.parity;
        nc.parity_ledger_path   = cfg_.parity_ledger_path;
        nc.c2pool_commit        = cfg_.c2pool_commit;
        nc.serve_arm            = cfg_.serve;
        nc.relay_order          = cfg_.relay_order;
        nc.template_fallback    = cfg_.fallback;
        nc.force_synced         = cfg_.force_synced;
        nc.backlog_refresh_s    = cfg_.backlog_refresh_s;
        nc.fork_tie             = cfg_.fork_tie;

        node_ = std::make_unique<nrt::NativeNode>(std::move(nc));
        if (!node_->start(why)) { node_.reset(); return false; }

        ntmpl::ArmResolver* arms = node_->arms();
        if (!arms) { why = "native node built no template arms"; stop(); return false; }
        arms_ = arms;

        ntmpl::MonerodMinerDataSource* daemon = node_->monerod_source();
        ntmpl::ResolvedMinerDataSource::ArmPump pump;
        if (daemon) pump = [daemon](std::string* w) { return daemon->poll(w); };
        resolved_ = std::make_unique<ntmpl::ResolvedMinerDataSource>(*arms_, std::move(pump));
        return true;
    }

    // Start, then wait for the configured serving arm to be ready. The wait is
    // what makes a cold start honest: a provider bound before the difficulty
    // window exists would log a readiness refusal every poll and look broken.
    bool start_and_wait(std::string& why,
                        const std::function<void(const std::string&)>& progress = {}) {
        if (!start(why)) return false;

        const auto deadline = std::chrono::steady_clock::now()
                            + std::chrono::seconds(cfg_.ready_timeout_s);
        std::string last;
        while (std::chrono::steady_clock::now() < deadline) {
            native::IMinerDataSource* want = arms_->arm(cfg_.serve);
            const native::MinerDataReadiness r =
                want ? want->readiness() : native::MinerDataReadiness{};
            if (r.ok()) { why.clear(); return true; }
            if (progress && r.why != last) { progress(r.why); last = r.why; }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        why = "the " + std::string(native::to_string(cfg_.serve)) + " template arm did not become ready in "
            + std::to_string(cfg_.ready_timeout_s) + "s (" + last + ")";
        return false;
    }

    void stop() {
        resolved_.reset();
        arms_ = nullptr;
        if (node_) { node_->stop(); node_.reset(); }
    }

    // --- what the provider is bound to ---------------------------------------
    ntmpl::ResolvedMinerDataSource& source() { return *resolved_; }

    // The provider's RefreshPump: ONE arm resolution per refresh, and the daemon
    // round trip only when the daemon arm was the one resolved to.
    std::function<bool(std::string*)> pump() {
        ntmpl::ResolvedMinerDataSource* r = resolved_.get();
        return [r](std::string* why) { return r->resolve(why); };
    }

    // Refresh the SHADOW arm so the parity oracle compares against something
    // current. Nothing else polls it: the node reads the daemon only for the
    // tip observation, and a shadow arm nobody pumped would make every template
    // sample VOID -- which the oracle would correctly refuse to call agreement.
    // This is a PARITY call, made from the status cadence, never from the
    // template path; it is exactly the round trip the native arm removed, kept
    // deliberately so the two can still be diffed.
    bool poll_shadow(std::string* why = nullptr) {
        if (!arms_ || !arms_->shadow()) return false;
        if (arms_->shadow() != static_cast<native::IMinerDataSource*>(node_->monerod_source()))
            return true;                       // a native shadow needs no round trip
        ntmpl::MonerodMinerDataSource* daemon = node_->monerod_source();
        return daemon && daemon->poll(why);
    }

    // --- observation ---------------------------------------------------------
    nrt::NativeNode*      node()  noexcept { return node_.get(); }
    ntmpl::ArmResolver*   arms()  noexcept { return arms_; }
    native::parity::ParityOracle* oracle() noexcept { return node_ ? node_->oracle() : nullptr; }

    // Total monerod RPC calls the NODE has made, for every reason (parity tip
    // observation, the shadow arm, boot). The template-path claim is checked
    // against the DELTA of this across refreshes, which is why it is exposed.
    std::uint64_t rpc_calls() { return node_ ? node_->status().rpc_calls : 0; }

    const NativeTemplateConfig& config() const noexcept { return cfg_; }

private:
    NativeTemplateConfig                             cfg_;
    std::unique_ptr<nrt::NativeNode>                 node_;
    ntmpl::ArmResolver*                              arms_ = nullptr;
    std::unique_ptr<ntmpl::ResolvedMinerDataSource>  resolved_;
};

} // namespace c2pool::v37n::xmr::o2
