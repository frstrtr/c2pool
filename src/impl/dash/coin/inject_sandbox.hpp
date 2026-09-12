// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// #157 M3 — SANDBOXED SIGNER / bounded-work guard for injected transactions.
//
// WHAT THIS IS
// ------------
// The injection runtime never signs (design §9.1 — the "isolated-signer SEAM":
// tx_bytes arrive already-signed and are never mutated). What it DOES do is
// re-VALIDATE every injected blob against the consensus-exact script interpreter
// (dash_scriptcheck.so VerifyScript, wired as Mempool::m_script_check) — once at
// admission's price-fold and again at EVERY template build for as long as the
// inject stays in the pool. That script-verify path is the attack surface a
// malicious inject targets: a single 100 KB blob stuffed with thousands of
// minimal inputs, or a pathological scriptSig, forces the interpreter to do
// unbounded work on every build.
//
// This header is the runtime-side realization of design §10 ("bound the blast
// radius of a signing/validation bug to the blob itself"): a pure, cheap,
// chain-state-INDEPENDENT vetting pass that BOUNDS the work the interpreter can
// be asked to do, run ONCE at submit_inject BEFORE the tx is ever admitted to
// the pool. It caps:
//   * input count       — each vin is one VerifyScript call per build
//   * output count      — bounds vout iteration / sigop surface
//   * per-scriptSig size — bounds interpreter stack/alloc for one input
//   * total scriptSig bytes — bounds aggregate interpreter work / allocation
//   * legacy sigops     — bounds the CHECKSIG/CHECKMULTISIG work (dashd's own
//                         MAX_BLOCK_SIGOPS accounting, reused via sigops.hpp)
//
// FAIL-CLOSED: any tx that breaches a bound is REFUSED BY NAME here and never
// reaches the interpreter, the pool, or a template. No unbounded recursion, no
// unbounded allocation, no partial admission.
//
// MONEY-SAFETY: this is a DoS bound placed IN FRONT OF the M1 validity gate
// (Mempool::add_inject). It only ever REFUSES; it can never admit a tx the gate
// would refuse, never loosen a consensus check, and touches NO coinbase /
// subsidy / PPLNS / payee / fee state. The set of txs that reach add_inject is a
// strict subset of before. Bounds are set generously (see the constants) so any
// realistic operator/miner inject passes untouched.
//
// PURE + HEADER-ONLY: no node.hpp, no NodeCoinState — drivable from a rig-free
// KAT over a MutableTransaction.

#include <impl/dash/coin/transaction.hpp>   // MutableTransaction, TxIn, TxOut
#include <impl/dash/coin/sigops.hpp>        // count_script_sigops, DASH_MAX_BLOCK_SIGOPS

#include <cstddef>
#include <cstdint>

namespace dash {
namespace coin {

// Bounded-work sandbox for the injected-tx script-verify surface. All caps are
// DoS ceilings, chosen well above any realistic inject; a normal spend (a
// handful of inputs, standard scripts) clears every one.
struct InjectSandbox {
    // A consensus-valid tx can have many inputs, but an inject is a rare
    // operator/miner action, not a chain-history sweep. 1000 inputs bounds the
    // per-build VerifyScript fan-out while clearing any realistic consolidation.
    static constexpr std::size_t kMaxInputs  = 1000;
    static constexpr std::size_t kMaxOutputs = 1000;
    // dashd/dashcore MAX_SCRIPT_SIZE = 10000 bytes: the interpreter refuses a
    // larger script outright, so a scriptSig above it can never verify — refuse
    // it here before the interpreter allocates for it.
    static constexpr std::size_t kMaxScriptSigBytes = 10000;
    // Aggregate scriptSig budget across all inputs — bounds total interpreter
    // allocation/work independent of how the bytes split across inputs. Sits at
    // the pool's per-tx byte cap (Mempool::kMaxInjectTxBytes) so it never binds
    // before the size gate but caps a size-legal blob that is all-scriptSig.
    static constexpr std::size_t kMaxTotalScriptSigBytes = 100000;
    // Legacy sigops for ONE tx. dashd's whole-block ceiling is 40'000
    // (DASH_MAX_BLOCK_SIGOPS); a single injected tx that alone approached the
    // block ceiling would crowd out every other tx, so cap one inject at a tenth
    // of the block budget. Generous for any standard multi-input spend.
    static constexpr uint32_t kMaxLegacySigOps = 4000;

    // Every breach is NAMED (DEF3 discipline — no silent drops), carrying the
    // observed value and the threshold at the call site.
    enum class Verdict : uint8_t {
        Ok = 0,
        TooManyInputs,
        TooManyOutputs,
        ScriptSigTooLarge,
        TotalScriptSigTooLarge,
        TooManySigOps,
    };

    static const char* verdict_name(Verdict v) {
        switch (v) {
            case Verdict::Ok:                     return "ok";
            case Verdict::TooManyInputs:          return "inject-sandbox-too-many-inputs";
            case Verdict::TooManyOutputs:         return "inject-sandbox-too-many-outputs";
            case Verdict::ScriptSigTooLarge:      return "inject-sandbox-scriptsig-too-large";
            case Verdict::TotalScriptSigTooLarge: return "inject-sandbox-total-scriptsig-too-large";
            case Verdict::TooManySigOps:          return "inject-sandbox-too-many-sigops";
        }
        return "inject-sandbox-unknown";
    }

    // The observed value and threshold that produced a non-Ok verdict, so the
    // caller can log cause/value/threshold in the repo's convention.
    struct Report {
        Verdict     verdict{Verdict::Ok};
        uint64_t    value{0};      // the observed quantity that breached
        uint64_t    threshold{0};  // the cap it breached
        bool ok() const { return verdict == Verdict::Ok; }
        const char* name() const { return verdict_name(verdict); }
    };

    // Vet a tx's script-verify surface. Cheapest checks first; returns on the
    // FIRST breach (fail-closed). Chain-state-independent — reads only the tx.
    static Report vet(const MutableTransaction& tx) {
        Report r;

        if (tx.vin.size() > kMaxInputs) {
            r.verdict = Verdict::TooManyInputs;
            r.value = tx.vin.size(); r.threshold = kMaxInputs; return r;
        }
        if (tx.vout.size() > kMaxOutputs) {
            r.verdict = Verdict::TooManyOutputs;
            r.value = tx.vout.size(); r.threshold = kMaxOutputs; return r;
        }

        uint64_t total_scriptsig = 0;
        for (const auto& vin : tx.vin) {
            const std::size_t n = vin.scriptSig.m_data.size();
            if (n > kMaxScriptSigBytes) {
                r.verdict = Verdict::ScriptSigTooLarge;
                r.value = n; r.threshold = kMaxScriptSigBytes; return r;
            }
            total_scriptsig += n;
            if (total_scriptsig > kMaxTotalScriptSigBytes) {
                r.verdict = Verdict::TotalScriptSigTooLarge;
                r.value = total_scriptsig; r.threshold = kMaxTotalScriptSigBytes; return r;
            }
        }

        // Legacy sigop bound — reuse dashd's own counting rules (sigops.hpp)
        // over every scriptSig and every scriptPubKey, fAccurate=false, exactly
        // as the G2 selector counts. Saturating accumulate so a crafted tx
        // cannot wrap the counter past the cap.
        uint64_t sigops = 0;
        for (const auto& vin : tx.vin) {
            sigops += count_script_sigops(vin.scriptSig.m_data, /*accurate=*/false);
            if (sigops > kMaxLegacySigOps) {
                r.verdict = Verdict::TooManySigOps;
                r.value = sigops; r.threshold = kMaxLegacySigOps; return r;
            }
        }
        for (const auto& vout : tx.vout) {
            sigops += count_script_sigops(vout.scriptPubKey.m_data, /*accurate=*/false);
            if (sigops > kMaxLegacySigOps) {
                r.verdict = Verdict::TooManySigOps;
                r.value = sigops; r.threshold = kMaxLegacySigOps; return r;
            }
        }

        return r;  // Ok
    }
};

} // namespace coin
} // namespace dash
