// SPDX-License-Identifier: AGPL-3.0-or-later
//
// TxInjectArmFlow — the #157 Slice A two-phase arm/disarm state machine for
// embedded.tx_inject, expressed WITHOUT any Qt dependency so it is unit-testable
// on its own (test_tx_inject_arm_flow.cpp) and cannot smuggle UI state into the
// money path.
//
// The node's money gate (config_endpoint::apply_config) binds a single-use nonce
// to the EXACT money diff:
//   Phase 1 (issue):   POST /api/config/apply {control_token, changes:{...}}   ->
//                      200 {status:"need_confirm", need_confirm:true, money_nonce, money_keys}
//   Phase 2 (confirm): POST the SAME changes + that money_nonce               ->
//                      200 {status:"applied", applied_keys:[...]}
// Any edit to the diff yields a different digest, so the issued nonce can never
// confirm a changed diff. A 409 (nonce missing/mismatched) is a hard refusal and
// is NEVER auto-retried — a retried money POST is a replay.
//
// This class owns ONLY the protocol logic: it produces request payloads and
// consumes already-parsed responses. The caller (PageTxInject) does the HTTP via
// ApiClient::postJson and the JSON (de)serialization; the two Request helpers
// below give a deterministic textual form so a test can assert the confirm diff
// is byte-for-byte the issued diff.
#pragma once

#include <map>
#include <string>

namespace c2pool_qt {

class TxInjectArmFlow {
public:
    enum class State {
        Idle,      // nothing in flight
        Issued,    // phase-1 nonce received, awaiting phase-2 confirm
        Applied,   // node reported the change applied
        Refused,   // any refusal (validation/token/gate/409) — terminal until reset
    };

    // A request payload to hand to the transport. `money_nonce` is empty on the
    // issue request and carries the server nonce on the confirm request. The
    // `changes` map is the diff the nonce is bound to — it is IDENTICAL between
    // issue and confirm (only the nonce field differs).
    struct Request {
        std::string                        control_token;
        std::map<std::string, std::string> changes;   // sorted (std::map)
        std::string                        money_nonce; // empty => issue phase

        // Deterministic serialization of just the diff the nonce binds to.
        // Used by the KAT to prove confirm.changes == issue.changes byte-exact.
        std::string changes_canon() const {
            std::string out = "{";
            bool first = true;
            for (const auto& [k, v] : changes) {   // std::map => sorted, stable
                if (!first) out += ",";
                first = false;
                out += "\"" + k + "\":\"" + v + "\"";
            }
            out += "}";
            return out;
        }
    };

    // A parsed response (the caller fills this from the JSON body + HTTP status).
    struct Response {
        int         http_status = 0;
        std::string status;        // "need_confirm" | "applied" | "validation" | ...
        std::string money_nonce;   // set on need_confirm
        bool        need_confirm = false;
        std::string error;         // human cause, echoed to the user verbatim
    };

    State state() const { return state_; }
    const std::string& last_error() const { return last_error_; }
    const std::string& nonce() const { return nonce_; }

    // Begin an arm (enable=true) or disarm (enable=false). Captures the desired
    // diff and returns the phase-1 issue request (no nonce). Resets any prior
    // in-flight state.
    Request begin(const std::string& control_token, bool enable) {
        control_token_ = control_token;
        desired_       = {{"embedded.tx_inject", enable ? "true" : "false"}};
        nonce_.clear();
        last_error_.clear();
        state_ = State::Idle;

        Request r;
        r.control_token = control_token_;
        r.changes       = desired_;    // issue diff
        r.money_nonce.clear();
        return r;
    }

    // Consume the phase-1 (issue) response. On a well-formed need_confirm with a
    // non-empty nonce, transitions to Issued and returns the confirm request
    // (the SAME diff + the nonce). On anything else -> Refused, returns false.
    //
    // `confirm_out` is only written when the function returns true.
    bool on_issue_response(const Response& resp, Request* confirm_out) {
        if (resp.http_status == 200 && resp.need_confirm &&
            !resp.money_nonce.empty()) {
            nonce_ = resp.money_nonce;
            state_ = State::Issued;
            if (confirm_out) {
                confirm_out->control_token = control_token_;
                confirm_out->changes       = desired_;   // byte-identical diff
                confirm_out->money_nonce   = nonce_;
            }
            return true;
        }
        last_error_ = resp.error.empty()
            ? std::string("arm request refused (no confirmation nonce issued)")
            : resp.error;
        nonce_.clear();
        state_ = State::Refused;
        return false;
    }

    // Consume the phase-2 (confirm) response. Applied only on 200 status
    // "applied". A 409 (or any other status) is a terminal refusal that is NEVER
    // auto-retried here.
    void on_confirm_response(const Response& resp) {
        nonce_.clear();  // single-use: the nonce is spent either way
        if (resp.http_status == 200 && resp.status == "applied") {
            state_ = State::Applied;
            last_error_.clear();
            return;
        }
        last_error_ = resp.error.empty()
            ? std::string("arm confirmation refused (status ")
                  + std::to_string(resp.http_status) + ")"
            : resp.error;
        state_ = State::Refused;
    }

    // If the operator edits the desired target while a nonce is outstanding, the
    // issued nonce is bound to the OLD diff and must be dropped — the flow falls
    // back to Idle so a fresh issue is required. Returns true if the edit
    // invalidated an outstanding nonce.
    bool note_desired_edit(bool enable) {
        std::map<std::string, std::string> next{
            {"embedded.tx_inject", enable ? "true" : "false"}};
        if (state_ == State::Issued && next != desired_) {
            desired_ = next;
            nonce_.clear();
            state_ = State::Idle;
            return true;
        }
        desired_ = next;
        return false;
    }

    void reset() {
        control_token_.clear();
        desired_.clear();
        nonce_.clear();
        last_error_.clear();
        state_ = State::Idle;
    }

private:
    State                              state_ = State::Idle;
    std::string                        control_token_;
    std::map<std::string, std::string> desired_;
    std::string                        nonce_;
    std::string                        last_error_;
};

}  // namespace c2pool_qt
