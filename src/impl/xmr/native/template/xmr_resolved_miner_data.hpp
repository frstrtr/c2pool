// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/template/xmr_resolved_miner_data.hpp   (C4, used by M2)
//
// ONE IMinerDataSource that IS whichever arm the resolver picked.
//
// The seam the option-B provider is rebound through takes a single source
// reference for the life of the provider, and that is deliberate: the provider
// must not be in the business of choosing which component builds the pool's
// blocks. But the resolver's whole job is that the choice can change -- the
// native arm loses its difficulty window, the daemon arm goes away. This
// adapter reconciles the two: it satisfies IMinerDataSource, and every value it
// reports comes from the arm the resolver last resolved to.
//
// THE LATCH, and why the adapter is not simply a call-through. Resolving inside
// each accessor would let one refresh read `epoch()` from the native arm and
// `snapshot()` from the daemon arm -- a template whose bytes come from one
// source and whose rebuild trigger comes from another. So the arm is resolved
// EXACTLY ONCE per refresh, by resolve(), which is the provider's existing
// RefreshPump seam, and every accessor afterwards reads the latched pointer.
// A provider constructed with this adapter and no pump would never resolve at
// all; resolve() therefore latches on its first call too, and readiness()
// answers fail-closed until it has run.
//
// FAIL-CLOSED. No arm ready => resolve() returns false with the reason the
// resolver recorded, the provider refuses to build, and the listener serves no
// job. It never falls through to a stale arm on its own.
//
// SCOPE FENCE: src/impl/xmr/ only. No consensus digest, no src/sharechain/v37.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/native/contracts/miner_data.hpp"
#include "impl/xmr/native/template/xmr_template_arm.hpp"

namespace c2pool::xmr::native::tmpl {

class ResolvedMinerDataSource final : public IMinerDataSource {
public:
    // A pump for an arm that needs a round trip before it can answer. Called by
    // resolve() ONLY when that arm is the one resolved to, so a native-only
    // configuration makes no daemon call at all -- which is the property M2
    // exists to prove.
    using ArmPump = std::function<bool(std::string*)>;

    explicit ResolvedMinerDataSource(ArmResolver& resolver, ArmPump monerod_pump = {})
        : resolver_(&resolver), monerod_pump_(std::move(monerod_pump)) {}

    ResolvedMinerDataSource(const ResolvedMinerDataSource&)            = delete;
    ResolvedMinerDataSource& operator=(const ResolvedMinerDataSource&) = delete;

    // THE PUMP. Resolve the arm for this refresh and latch it. Returns false
    // (fail-closed) when no arm can serve.
    //
    // ORDER MATTERS, and it is not the obvious one. The daemon arm's readiness
    // is a property of its CACHE: MonerodMinerDataSource has nothing to report
    // until poll() has filled it once. So "resolve, then pump whatever was
    // resolved to" can never reach the daemon arm at all -- the resolver would
    // find it unready, every time, forever. The rule below is therefore:
    //
    //   * the daemon arm is polled ONLY when it might actually serve -- it is
    //     the configured arm, or the configured arm just failed and falling
    //     back is allowed;
    //   * a ready native arm is resolved FIRST and costs nothing, which is the
    //     whole point of M2 and is why the native-only path's pump counter
    //     stays at zero for the life of the process;
    //   * a failed poll is not fatal on its own -- the resolver is asked again
    //     anyway, so a dead daemon with a live native arm still serves.
    bool resolve(std::string* why = nullptr) {
        const TemplateArmConfig& cfg = resolver_->config();
        const bool daemon_is_configured = (cfg.serve == TemplateArm::Monerod);

        IMinerDataSource* picked = nullptr;
        if (!daemon_is_configured) picked = resolver_->serving();   // free

        if (!picked && monerod_pump_ && (daemon_is_configured || cfg.fallback)) {
            { std::lock_guard<std::mutex> lk(mtx_); ++daemon_pumps_; }
            std::string pump_why;
            const bool pumped = monerod_pump_(&pump_why);
            picked = resolver_->serving();
            if (!picked && !pumped) {
                std::lock_guard<std::mutex> lk(mtx_);
                cur_ = nullptr;
                ++resolves_;
                if (why) *why = pump_why.empty() ? "miner data source: no response" : pump_why;
                return false;
            }
        }

        {
            std::lock_guard<std::mutex> lk(mtx_);
            cur_ = picked;
            ++resolves_;
        }
        if (!picked) {
            const std::string r = resolver_->last_reason();
            if (why) *why = r.empty() ? "no template arm is ready" : ("no template arm is ready: " + r);
            return false;
        }
        return true;
    }

    std::uint64_t resolves() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return resolves_;
    }

    // How many of those resolutions cost a get_miner_data round trip. This is
    // the M2 claim as a NUMBER: a native-only template path leaves it at zero
    // for the life of the process, and no amount of parity or submit traffic
    // against the same daemon can move it, because only resolving TO the daemon
    // arm does.
    std::uint64_t daemon_pumps() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return daemon_pumps_;
    }

    // --- IMinerDataSource ----------------------------------------------------
    const char* name() const override {
        IMinerDataSource* s = latched_();
        return s ? s->name() : "none";
    }

    MinerDataReadiness readiness() const override {
        IMinerDataSource* s = latched_();
        if (!s) {
            MinerDataReadiness r;
            r.why = "no arm resolved yet";
            return r;
        }
        return s->readiness();
    }

    MinerDataEpoch epoch() const override {
        IMinerDataSource* s = latched_();
        return s ? s->epoch() : MinerDataEpoch{};
    }

    std::optional<node::MinerData> snapshot(std::string* why) const override {
        IMinerDataSource* s = latched_();
        if (!s) {
            if (why) *why = "no template arm is ready";
            return std::nullopt;
        }
        return s->snapshot(why);
    }

    const std::vector<std::uint8_t>* tx_body(const Hash& id) const override {
        IMinerDataSource* s = latched_();
        return s ? s->tx_body(id) : nullptr;
    }

private:
    IMinerDataSource* latched_() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return cur_;
    }

    ArmResolver*      resolver_;
    ArmPump           monerod_pump_;
    mutable std::mutex mtx_;
    IMinerDataSource* cur_ = nullptr;
    std::uint64_t     resolves_ = 0;
    std::uint64_t     daemon_pumps_ = 0;
};

} // namespace c2pool::xmr::native::tmpl
