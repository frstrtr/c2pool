// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/inject/xmr_inject_sandbox.hpp
//
// SANDBOXED-VET / bounded-work guard for injected transactions, mirroring the
// Dash InjectSandbox (src/impl/dash/coin/inject_sandbox.hpp, #157 M3).
//
// The injection runtime never signs (design §9.1 -- the isolated-signer seam:
// the blob arrives already-signed and is never mutated). What it DOES do is
// re-VALIDATE every injected blob against the non-input consensus checks (range
// proofs, commitment balance) once at admission and, because the inject stays
// pinned, its body is re-selected on every template build. This header BOUNDS
// the work the verify surface can be asked to do, run ONCE at the gate BEFORE
// the tx is decoded-and-verified into C3.
//
// HONEST NOTE (why this is thinner than Dash's). Monero consensus already caps
// the verify surface hard: ring size is exactly 16, outputs are 2..16, the
// transaction weight is <= 149400, and tx_extra is <= 1060 bytes -- all checked
// in C3's admit_locked. Dash re-runs a Turing-ish script interpreter per input
// on every build and must cap script size / sigops / input fan-out itself; XMR
// has no scripts. So the real value of this sandbox is (1) the charged-FREE
// oversize refusal and (2) a pre-decode structural gate applied BEFORE the rate
// limiter is charged and before the heavy BP+ verify runs, catching a malformed
// or out-of-envelope inject cheaply. Every bound here is a DoS ceiling set at
// or below what C3 will enforce anyway, so a realistic operator inject passes
// untouched and a breach is refused BY NAME (fail-closed).
//
// MONEY-SAFETY: a bound placed IN FRONT OF the C3 validity gate. It only ever
// REFUSES; it can never admit a tx C3 would refuse, never loosens a consensus
// check, and touches NO coinbase / subsidy / settlement / fee state.
//
// PURE + HEADER-ONLY: vets a DecodedTx's TxWeightInfo, no node/pool state.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>

#include "impl/xmr/native/consensus/xmr_tx_weight.hpp"   // TxWeightInfo, RCT_TYPE_BULLETPROOF_PLUS

namespace c2pool::xmr::native {

struct InjectSandbox {
    // Bounds, each at or below C3's own consensus/policy limit so this never
    // binds before C3 on a valid tx; it is the cheap pre-decode envelope.
    //
    // Inputs: a CLSAG-verified tx fans out one ring check per input. 256 bounds
    // that generously; a weight-legal tx (<= 149400) cannot approach it, so this
    // never binds on a valid tx -- it caps a malformed decode that claimed a
    // huge input count.
    static constexpr std::size_t   kMaxInputs      = 256;
    // Consensus BULLETPROOF_PLUS_MAX_OUTPUTS.
    static constexpr std::size_t   kMaxOutputs     = 16;
    // MAX_TX_EXTRA_SIZE (monero PR #8733), C3's max_extra_size.
    static constexpr std::size_t   kMaxExtraBytes  = 1060;
    // The consensus tx-weight limit (TxpoolConfig::max_tx_weight): a blob above
    // it can never be a valid XMR tx. Refused charged-free at the gate.
    static constexpr std::uint64_t kMaxBlobBytes   = 149400;

    enum class Verdict : std::uint8_t {
        Ok = 0,
        TooManyInputs,
        TooManyOutputs,
        ExtraTooLarge,
        NotBulletproofPlus,
        Oversize,
    };
    static const char* verdict_name(Verdict v) {
        switch (v) {
            case Verdict::Ok:                 return "ok";
            case Verdict::TooManyInputs:      return "inject-sandbox-too-many-inputs";
            case Verdict::TooManyOutputs:     return "inject-sandbox-too-many-outputs";
            case Verdict::ExtraTooLarge:      return "inject-sandbox-extra-too-large";
            case Verdict::NotBulletproofPlus: return "inject-sandbox-not-bulletproof-plus";
            case Verdict::Oversize:           return "inject-sandbox-oversize";
        }
        return "inject-sandbox-unknown";
    }

    struct Report {
        Verdict       verdict{Verdict::Ok};
        std::uint64_t value{0};
        std::uint64_t threshold{0};
        bool ok() const { return verdict == Verdict::Ok; }
        const char* name() const { return verdict_name(verdict); }
    };

    // Vet a decoded tx's envelope. Cheapest checks first; returns on the FIRST
    // breach (fail-closed). Chain-state-independent -- reads only the weight
    // info the decoder already produced.
    static Report vet(const TxWeightInfo& w) {
        Report r;
        if (w.blob_size > kMaxBlobBytes) {
            r.verdict = Verdict::Oversize;
            r.value = w.blob_size; r.threshold = kMaxBlobBytes; return r;
        }
        if (w.rct_type != RCT_TYPE_BULLETPROOF_PLUS) {
            r.verdict = Verdict::NotBulletproofPlus;
            r.value = w.rct_type; r.threshold = RCT_TYPE_BULLETPROOF_PLUS; return r;
        }
        if (w.n_inputs > kMaxInputs) {
            r.verdict = Verdict::TooManyInputs;
            r.value = w.n_inputs; r.threshold = kMaxInputs; return r;
        }
        if (w.n_outputs > kMaxOutputs) {
            r.verdict = Verdict::TooManyOutputs;
            r.value = w.n_outputs; r.threshold = kMaxOutputs; return r;
        }
        if (w.extra_size > kMaxExtraBytes) {
            r.verdict = Verdict::ExtraTooLarge;
            r.value = w.extra_size; r.threshold = kMaxExtraBytes; return r;
        }
        return r;   // Ok
    }
};

} // namespace c2pool::xmr::native
