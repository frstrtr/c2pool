// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/template/xmr_template_arm.hpp
//
// C4, the resolver: which IMinerDataSource SERVES the miners, which one only
// SHADOWS for the parity oracle, and what happens when the serving arm stops
// being ready.
//
// This is the DASH arm_resolution.hpp posture, translated. Two rules carry over
// verbatim because they were learned the hard way there:
//
//   1. Falling back is LOUD and COUNTED. A pool that quietly switches which
//      component builds its blocks has no way to explain a later divergence.
//      Every fallback bumps a counter and records the reason the native arm
//      gave, so the status line can say "serving monerod (native: no tip)"
//      rather than just "serving monerod".
//   2. Falling FORWARD is not automatic on the same breath. Once the native arm
//      recovers, resolve() returns to it -- but the counter and last_reason()
//      stay, so a flapping arm is visible as a rising number rather than as an
//      instantaneous "everything is fine".
//
// The SHADOW arm is never served from. It exists so C6 can build the same
// template twice, from two independent sources, and diff the result. Reading a
// shadow source must therefore never influence what the serving source does,
// which is why shadow() hands back a plain pointer and nothing here calls it.
//
// SCOPE FENCE: src/impl/xmr/ only. No consensus digest, no src/sharechain/v37.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "impl/xmr/native/contracts/miner_data.hpp"

namespace c2pool::xmr::native::tmpl {

// --xmr-template-source / --xmr-template-shadow, as a value.
struct TemplateArmConfig {
    // Which arm the miners are served from when it is ready.
    TemplateArm serve = TemplateArm::Monerod;

    // Which arm the parity oracle reads. nullopt = no shadow. Setting it equal
    // to `serve` is a configuration error and is rejected by validate().
    std::optional<TemplateArm> shadow;

    // When the serving arm is not ready and the OTHER arm is, serve from the
    // other arm anyway. Default on: a pool that stops serving templates stops
    // paying its miners, and an armed daemon is a strictly better answer than
    // no answer. Turn it off to prove a native-only configuration really is
    // native-only (which is what the M5 soak does).
    bool fallback = true;

    bool validate(std::string* why = nullptr) const {
        if (shadow && *shadow == serve) {
            if (why) *why = "template shadow arm must differ from the serving arm";
            return false;
        }
        return true;
    }
};

// ---------------------------------------------------------------------------
// ArmResolver
//
// Either pointer may be null: a node with no daemon endpoint has no monerod
// arm, and a node before the native index is built has no native arm. A
// resolver with no usable arm resolves to nullptr and says why, which is the
// fail-closed answer the provider turns into "no template".
// ---------------------------------------------------------------------------
class ArmResolver {
public:
    ArmResolver(IMinerDataSource* monerod, IMinerDataSource* native,
                TemplateArmConfig cfg = {})
        : monerod_(monerod), native_(native), cfg_(cfg) {}

    const TemplateArmConfig& config() const noexcept { return cfg_; }

    IMinerDataSource* arm(TemplateArm a) const noexcept {
        return a == TemplateArm::Native ? native_ : monerod_;
    }

    // The source the miners are served from right now, applying the fallback
    // rule. Returns nullptr when no arm can serve.
    IMinerDataSource* serving() {
        IMinerDataSource* preferred = arm(cfg_.serve);
        if (preferred) {
            const MinerDataReadiness r = preferred->readiness();
            if (r.ok()) {
                effective_ = cfg_.serve;
                fell_back_ = false;
                return preferred;
            }
            last_reason_ = r.why;
        } else {
            last_reason_ = std::string("configured arm '") + to_string(cfg_.serve)
                         + "' is not present on this node";
        }

        if (!cfg_.fallback) {
            effective_ = cfg_.serve;
            fell_back_ = false;
            return nullptr;
        }

        const TemplateArm other = (cfg_.serve == TemplateArm::Native)
                                      ? TemplateArm::Monerod : TemplateArm::Native;
        IMinerDataSource* alt = arm(other);
        if (alt && alt->readiness().ok()) {
            if (!fell_back_ || effective_ != other) ++fallbacks_;
            effective_ = other;
            fell_back_ = true;
            return alt;
        }

        effective_ = cfg_.serve;
        fell_back_ = false;
        return nullptr;
    }

    // The source the parity oracle reads. Never affects serving().
    IMinerDataSource* shadow() const {
        if (!cfg_.shadow) return nullptr;
        return arm(*cfg_.shadow);
    }

    // Which arm serving() last handed back. Meaningful after a serving() call.
    TemplateArm   effective_arm() const noexcept { return effective_; }
    bool          fell_back()     const noexcept { return fell_back_; }
    std::uint64_t fallbacks()     const noexcept { return fallbacks_; }
    // Why the configured arm was not used, in that arm's own words.
    const std::string& last_reason() const noexcept { return last_reason_; }

    // One line for the status page / log: "native" or "monerod (fallback from
    // native: no tip)".
    std::string describe() {
        IMinerDataSource* s = serving();
        if (!s) {
            return std::string("none (") + to_string(cfg_.serve) + ": "
                 + (last_reason_.empty() ? "not ready" : last_reason_) + ")";
        }
        if (!fell_back_) return s->name();
        return std::string(s->name()) + " (fallback from " + to_string(cfg_.serve)
             + ": " + (last_reason_.empty() ? "not ready" : last_reason_) + ")";
    }

private:
    IMinerDataSource* monerod_ = nullptr;
    IMinerDataSource* native_  = nullptr;
    TemplateArmConfig cfg_{};

    TemplateArm   effective_ = TemplateArm::Monerod;
    bool          fell_back_ = false;
    std::uint64_t fallbacks_ = 0;
    std::string   last_reason_;
};

} // namespace c2pool::xmr::native::tmpl
