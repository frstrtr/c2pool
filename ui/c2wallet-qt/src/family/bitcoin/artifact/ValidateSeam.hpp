// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// M5-A the c2pool validation seam — CONTRACT ONLY (design
// docs/design/c2wallet-qt.md §5.4 "The validation seam").
//
// The design corrects the original task premise: there is NO off-host HTTP
// submit route. The proven seam is FILE-BASED (a file is what crosses the air
// gap anyway) — the online gate is NodeCoinState::submit_inject ->
// Mempool::add_inject, cheapest-checks-first, with NAMED verdicts and no silent
// drops. This header defines the transport-agnostic request/response the wallet
// marshals, mirrors the online node's named cause vocabulary so the UI can
// surface it, and leaves the actual online call as a clearly-named UNWIRED
// seam: the file/QR artifact is what crosses the gap; the online companion
// (NodeCoinState::submit_inject) lives in a SEPARATE LANE. This binary is
// network-incapable and never makes that call.

#include <cstdint>
#include <optional>
#include <string>

namespace c2w::artifact {

// The named verdicts c2pool emits, mirrored from the online source so the
// wallet recognises and displays them (design §5.4; surface
// InjectSubmitResult.cause in the UI). Kept in lockstep with:
//   src/impl/dash/coin/node_coin_state.hpp   (submit_inject)
//   src/impl/dash/coin/mempool.hpp           (inject_gate_name)
//   src/impl/dash/coin/tx_inject_pool.hpp    (admit_name)
namespace inject_cause {
    inline constexpr const char* Ok                 = "ok";
    inline constexpr const char* Disabled           = "inject-disabled";
    inline constexpr const char* TypeUnsupported    = "inject-type-unsupported";
    // mempool add_inject gate:
    inline constexpr const char* Oversize           = "inject-oversize";
    inline constexpr const char* ScriptCheckUnarmed = "inject-script-check-unarmed";
    inline constexpr const char* AlreadyKnown       = "inject-already-known";
    inline constexpr const char* AlreadyConfirmed   = "inject-already-confirmed";
    inline constexpr const char* Unpriceable        = "inject-unpriceable";
    inline constexpr const char* Bip68Unsupported   = "inject-bip68-unsupported";
    inline constexpr const char* BadVoutRange       = "inject-bad-txns-vout-range";
    // DoS pool caps (tx_inject_pool admit):
    inline constexpr const char* PoolDuplicate      = "inject-pool-duplicate";
    inline constexpr const char* PoolFull           = "inject-pool-full";
    inline constexpr const char* PoolTotalBytes     = "inject-pool-total-bytes-exceeded";
    inline constexpr const char* PoolOversize       = "inject-pool-oversize";
} // namespace inject_cause

enum class SeamOp : uint8_t { Validate, Submit };

// Design §5.4 contract:
//   { "op": "validate"|"submit", "coin": "...", "tx_hex": "...",
//     "flags": 0, "expiry_height": 0 }
// `flags` (uint32_t) and `expiry_height` (int32_t) mirror
// NodeCoinState::submit_inject's wire fields exactly. `dry_run` selects the
// recommended validate_inject dry-run (a testmempoolaccept analog: validate
// WITHOUT admit, so the wallet can pre-flight BEFORE the operator signs).
struct SeamRequest {
    SeamOp      op = SeamOp::Validate;
    std::string coin;
    std::string tx_hex;
    uint32_t    flags = 0;
    int32_t     expiry_height = 0;
    bool        dry_run = false;

    std::string to_json() const;
    static std::optional<SeamRequest> from_json(const std::string& s, std::string& err);

    // The validate_inject dry-run shape: op=validate, dry_run=true (§5.4). This
    // is the tap-free pre-flight (money-path discipline §5.5: read-only).
    static SeamRequest validate_inject(const std::string& coin, const std::string& tx_hex);
};

// Design §5.4 contract:
//   { "ok": true|false, "cause": "ok"|"inject-...", "txid": "<sha256d>" }
struct SeamResponse {
    bool        ok = false;
    std::string cause = inject_cause::Ok;
    std::string txid; // sha256d display

    std::string to_json() const;
    static std::optional<SeamResponse> from_json(const std::string& s, std::string& err);
};

// The cross-gap comparison digest: sha256d of the tx bytes rendered as a
// display txid (design §5.4: "Both sides show sha256d + a human-readable
// render"). Empty string if tx_hex is not valid hex.
std::string crossgap_txid(const std::string& tx_hex);

// The UNWIRED online seam. Deliberately performs NO I/O: this binary is
// network-incapable, and the real transport is the file/QR artifact the
// operator carries. The online companion that actually calls
// NodeCoinState::submit_inject is a SEPARATE LANE (cross-lane dependency). This
// type documents the boundary and refuses loudly with a named cause.
class UnwiredOnlineSeam {
public:
    static constexpr const char* kUnwiredCause = "seam-unwired-cross-lane";

    // Always ok=false, cause=kUnwiredCause, txid = the cross-gap digest of the
    // request's tx (so the caller still gets the value to compare by hand).
    SeamResponse call(const SeamRequest& req) const;
};

} // namespace c2w::artifact
