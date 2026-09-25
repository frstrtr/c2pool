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
#include "xmr_node_config.hpp"

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
    std::string              output_set_path;   // format-2 O-backfill snapshot

    // GATE 4's bound, forwarded verbatim. The pool binary sets it from
    // --anchor-confirm-peers / --anchor-confirm-peer-ms /
    // --anchor-confirm-timeout-ms; the defaults here are the node's own, so a
    // consumer that names none of them gets exactly the behaviour that shipped.
    // There is no field that disarms the gate, by construction.
    nrt::AnchorConfirmConfig anchor_confirm{};

    // The chain-index resume file. Empty = no persistence (a restart re-walks
    // from the anchor). See node/xmr_chain_snapshot_store.hpp for why the image
    // is bound to the anchor identity gate 4 confirmed rather than trusted on
    // its own.
    std::string              snapshot_path;
    std::uint64_t            snapshot_every_s = 300;
    std::uint64_t            consumer_window = 0;   // COLD-BOOT-2 (NativeNodeConfig::consumer_window)
    bool                     chain_event_backpressure = false;   // COLD-BOOT-3 (NativeNodeConfig::chain_event_backpressure)

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
    // does, at most once per this many seconds. Default 3 s (good-citizen: txs
    // arriving mid-interval must reach the served template). 0 = legacy tip-only.
    // See NativeNodeConfig for why a tip-only native arm collects almost no fees.
    std::uint64_t            backlog_refresh_s = 3;

    // #1680 lever. Cap on outstanding solicited-reply DoS credits, handed to
    // NativeNodeConfig::dos_solicited_credits (which sets DosConfig::
    // max_solicited_credits). Default 8 = fix #1 armed; 0 disables the credit
    // path (pre-#1680 behaviour), which the live fix-2 proof leans on.
    std::uint32_t            dos_solicited_credits = 8;

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
    // Own-fork liveness guard bound (--own-fork-bound-s); 0 disables.
    std::uint64_t            own_fork_bound_ms = 240'000;

    // OPERATOR TX-INJECTION (2026-09-19 ruling), default OFF. When on, the node
    // accepts operator-submitted signed txs through submit_operator_inject() and
    // places them FIRST at highest priority in the served template (mined even
    // at 0 fee), bounded by the block-weight cap; the good-citizen take-all tail
    // fills the rest. See NativeNodeConfig::operator_inject.
    bool                     operator_inject = false;
    std::uint64_t            operator_inject_ttl_blocks = 720;
};

// ---------------------------------------------------------------------------
// XmrNodeConfig -> NativeTemplateConfig, as a PURE function.
//
// This is the FORWARD, and it is a function for the same reason
// arm_order_refusal() is: every knob the pool binary parses has to arrive at
// the node, and the only way to keep that honest is for a test to be able to
// call the real derivation rather than a copy of it. The three gate 4 knobs
// and --native-seeds both went missing here before this existed -- the fields
// were parsed into XmrNodeConfig, the struct below had no home for them, and
// nothing anywhere said so.
//
// It deliberately does NOT start anything, print anything, or decide whether
// the configuration is coherent; main's start_native_backend() does the first
// two and arm_order_refusal() the third.
// ---------------------------------------------------------------------------
inline nrt::NativeNet native_net_of(MoneroNetwork n) {
    switch (n) {
        case MoneroNetwork::Mainnet:  return nrt::NativeNet::Mainnet;
        case MoneroNetwork::Testnet:  return nrt::NativeNet::Testnet;
        case MoneroNetwork::Stagenet: return nrt::NativeNet::Stagenet;
        case MoneroNetwork::Regtest:  return nrt::NativeNet::Regtest;
    }
    return nrt::NativeNet::Stagenet;
}

inline NativeTemplateConfig native_template_config_of(const XmrNodeConfig& cfg) {
    const bool p2p_first = (cfg.arm_order == ArmOrderMode::P2PFirst);

    NativeTemplateConfig n;
    n.net         = native_net_of(cfg.network);
    n.connect     = cfg.native_connect;
    n.p2p_bind_ip = cfg.native_p2p_bind_ip;
    n.use_seeds   = cfg.native_use_seeds;
    // THE TRUST ROOT. Solo has no peer to ask for the genesis blob, so it
    // assembles the blob locally and feeds it to the same id-checking gate;
    // otherwise an anchor path selects Anchor and its absence selects Genesis.
    n.boot        = cfg.native_solo
                        ? nrt::BootMode::LocalGenesis
                        : (cfg.native_anchor_path.empty() ? nrt::BootMode::Genesis
                                                          : nrt::BootMode::Anchor);
    n.anchor_path = cfg.native_anchor_path;
    n.output_set_path = cfg.native_output_set_path;   // format-2 O-backfill

    // GATE 4's window, widened only. `sane()` is what AnchorConfirmDriver
    // requires; the flag parser already refuses a zero, and this is the second
    // guard so a programmatic caller cannot disarm the gate by building a
    // config with zeros in it.
    n.anchor_confirm.peers       = cfg.anchor_confirm_peers ? cfg.anchor_confirm_peers : 1;
    n.anchor_confirm.timeout_ms  = cfg.anchor_confirm_timeout_ms ? cfg.anchor_confirm_timeout_ms
                                                                 : 1;
    n.anchor_confirm.per_peer_ms = cfg.anchor_confirm_peer_ms ? cfg.anchor_confirm_peer_ms : 1;

    n.snapshot_path    = cfg.native_snapshot_path;
    n.snapshot_every_s = cfg.native_snapshot_every_s;
    // COLD-BOOT-2: the settlement paces the catch-up download (p2p-first anchor boot only).
    n.consumer_window  = (p2p_first && !cfg.native_solo && !cfg.native_anchor_path.empty()) ? cfg.native_catchup_window : 0;
    // COLD-BOOT-3: the p2p-first serve loop drains the node's event queue every
    // pass, so the bulk download may wait on it (never a silent overflow).
    n.chain_event_backpressure = p2p_first;

    // The daemon endpoint is the C6 PARITY judge, and under daemon-first also
    // the submit arm. Under p2p-first it is the parity judge and nothing else:
    // the oracle reads it off the status cadence, which is not the find path.
    // --no-daemon-rpc withholds it entirely, and then the node has no daemon
    // arm to make a call with -- the strongest form of the claim, at the cost
    // of the parity judge.
    // Solo implies no daemon: there is no endpoint to configure, and leaving one
    // wired would have the C6 parity judge dial a dead port every status tick.
    //
    // D6d: p2p-first withholds it too unless --native-parity-monerod asks for the
    // judge. The native chain index already answers everything that judge read
    // (tip, RandomX seed hash/height, difficulty/height), so leaving it wired by
    // default kept a get_miner_data + get_info + get_last_block_header trio on
    // the wire every status tick for nothing but a comparison. The judge is now
    // an explicit, compare-only oracle under p2p-first; daemon-first is unchanged.
    const bool want_daemon_judge = !p2p_first || cfg.native_parity_monerod;
    if (!cfg.no_daemon_rpc && !cfg.native_solo && want_daemon_judge) {
        n.monerod_rpc_host = cfg.monerod.rpc_host;
        n.monerod_rpc_port = cfg.monerod.rpc_port;
    }
    n.serve       = native::TemplateArm::Native;
    n.relay_order = p2p_first ? native::ArmOrder::P2pOnly : native::ArmOrder::DaemonFirst;
    // p2p-first pins the fallback OFF whatever the flag said: a daemonless find
    // whose template silently came from the daemon is not a daemonless find,
    // and the operator should not be able to weaken the claim by accident.
    n.fallback             = p2p_first ? false : cfg.native_template_fallback;
    // "synced" is defined against a PEER COHORT. A solo node has no cohort, so
    // the flag is not an operator convenience there but the only way the
    // readiness gate can ever open.
    n.force_synced         = cfg.native_force_synced || cfg.native_solo;
    n.allow_unverified_pow = cfg.native_allow_unverified_pow;
    n.parity               = true;
    // parity_ledger_path and c2pool_commit are NOT set here: the first resolves
    // through config_path() and the second is a build macro, and neither is a
    // function of the configuration VALUE. main fills them in, which is also
    // what keeps this function linkable from a test that has no core config.
    n.ready_timeout_s      = cfg.native_ready_timeout_s;
    n.backlog_refresh_s    = cfg.native_backlog_refresh_s;
    // D-14 lever (1): what the fork choice adopts at EQUAL work at the same
    // height. Same flag as the accounting tiebreak -- see xmr_same_height_race.hpp.
    n.fork_tie = (cfg.same_height_tiebreak == SameHeightTieBreak::PreferOwn)
                     ? native::TieBreak::PreferOwn
                     : native::TieBreak::FirstSeen;
    n.own_fork_bound_ms = static_cast<std::uint64_t>(cfg.own_fork_bound_s) * 1000;
    // #1680 lever, and OPERATOR TX-INJECTION (default OFF): forwarded here so a
    // consumer that builds its config through this function -- main and the
    // mainnet-readiness KAT -- does not silently drop them on the way to the node.
    n.dos_solicited_credits        = cfg.native_dos_solicited_credits;
    n.operator_inject              = cfg.native_inject;
    n.operator_inject_ttl_blocks   = cfg.native_inject_ttl_blocks;
    return n;
}

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
        nc.output_set_path      = cfg_.output_set_path;
        nc.anchor_confirm       = cfg_.anchor_confirm;
        nc.snapshot_path        = cfg_.snapshot_path;
        nc.snapshot_every_s     = cfg_.snapshot_every_s;
        nc.consumer_window      = cfg_.consumer_window;   // COLD-BOOT-2
        nc.chain_event_backpressure = cfg_.chain_event_backpressure;   // COLD-BOOT-3
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
        nc.dos_solicited_credits = cfg_.dos_solicited_credits;   // #1680 lever
        nc.fork_tie             = cfg_.fork_tie;
        nc.own_fork_bound_ms    = cfg_.own_fork_bound_ms;
        nc.operator_inject            = cfg_.operator_inject;
        nc.operator_inject_ttl_blocks = cfg_.operator_inject_ttl_blocks;

        node_ = std::make_unique<nrt::NativeNode>(std::move(nc));
        if (!node_->start(why)) {
            // The node is about to be destroyed and its log with it -- and that
            // log is where gate 4 wrote WHICH gate fired and what the peers
            // said. `why` carries one line; an operator staring at a refused
            // mainnet start needs the rest, so it is taken before the reset.
            start_log_ = node_->take_log();
            node_.reset();
            return false;
        }

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
            // COLD-BOOT-2: the catch-up download is paused at the settlement's
            // ceiling (anchor + window before the settlement exists): the index
            // cannot sync until the settlement books, and the settlement books
            // from the serve loop. Proceed; the arm becomes ready as the gap is
            // booked (the serve loop parks miners until the first template).
            if (node_ && node_->index().consumer_held()) {
                why = "catch-up held at the settlement ceiling h=" + std::to_string(node_->index().consumer_ceiling()) +
                      " (tip " + std::to_string(node_->index().sync_state().header_frontier) + "; " + r.why + ")";
                return true;
            }
            // COLD-BOOT-3: the download waits for the serve loop to drain the
            // event queue (backpressure); only the serve loop drains it.
            if (node_ && cfg_.chain_event_backpressure && node_->chain_events_backpressured()) {
                why = "catch-up waiting for the serve loop to drain the chain-event queue (tip " +
                      std::to_string(node_->index().sync_state().header_frontier) + "; " + r.why + ")";
                return true;
            }
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

    // The node's log lines from a start that REFUSED, kept after the node
    // itself is gone. Empty on a successful start (the node still owns its log
    // then, and node()->take_log() is the live drain).
    const std::vector<std::string>& start_log() const noexcept { return start_log_; }

private:
    NativeTemplateConfig                             cfg_;
    std::unique_ptr<nrt::NativeNode>                 node_;
    ntmpl::ArmResolver*                              arms_ = nullptr;
    std::unique_ptr<ntmpl::ResolvedMinerDataSource>  resolved_;
    std::vector<std::string>                         start_log_;
};

} // namespace c2pool::v37n::xmr::o2
