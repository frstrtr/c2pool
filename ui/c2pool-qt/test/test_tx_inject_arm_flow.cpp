// SPDX-License-Identifier: AGPL-3.0-or-later
//
// test_tx_inject_arm_flow — Qt-free KAT for the #157 Slice A two-phase arm/disarm
// state machine (TxInjectArmFlow.hpp). Proves:
//   * begin() -> issue request has the diff and NO nonce;
//   * a well-formed need_confirm advances to Issued and yields a confirm request
//     whose diff is BYTE-FOR-BYTE the issue diff (the nonce binds the exact diff);
//   * the confirm carries the server nonce;
//   * status "applied" (200) reaches Applied;
//   * a 409 confirm is a terminal Refused and is NEVER auto-retried (the flow
//     produces no further request);
//   * editing the desired target while a nonce is outstanding DROPS the nonce
//     (falls back to Idle) so a stale nonce can never confirm a changed diff;
//   * a phase-1 refusal (no nonce) -> Refused.
//
// Builds with a plain C++17 compiler (no Qt, no display).

#include "../src/TxInjectArmFlow.hpp"

#include <cstdio>
#include <string>

using c2pool_qt::TxInjectArmFlow;
using State = c2pool_qt::TxInjectArmFlow::State;
using Response = c2pool_qt::TxInjectArmFlow::Response;
using Request = c2pool_qt::TxInjectArmFlow::Request;

static int failures = 0;
static void check(bool cond, const char* what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) ++failures;
}

int main() {
    std::printf("test_tx_inject_arm_flow\n");

    // 1) Happy path: arm true -> issue -> need_confirm -> confirm -> applied.
    {
        TxInjectArmFlow f;
        Request issue = f.begin("tok-abc", /*enable=*/true);
        check(f.state() == State::Idle, "state Idle before issue response");
        check(issue.money_nonce.empty(), "issue request carries no nonce");
        check(issue.control_token == "tok-abc", "issue carries the control token");
        check(issue.changes.size() == 1 &&
                  issue.changes.at("embedded.tx_inject") == "true",
              "issue diff is embedded.tx_inject=true");
        const std::string issue_diff = issue.changes_canon();

        Response r1;
        r1.http_status = 200;
        r1.need_confirm = true;
        r1.status = "need_confirm";
        r1.money_nonce = "NONCE123";
        Request confirm;
        const bool advanced = f.on_issue_response(r1, &confirm);
        check(advanced && f.state() == State::Issued,
              "need_confirm advances to Issued");
        check(confirm.money_nonce == "NONCE123",
              "confirm carries the server-issued nonce");
        check(confirm.changes_canon() == issue_diff,
              "confirm diff is BYTE-FOR-BYTE the issue diff (nonce binds exact diff)");

        Response r2;
        r2.http_status = 200;
        r2.status = "applied";
        f.on_confirm_response(r2);
        check(f.state() == State::Applied, "status applied (200) reaches Applied");
        check(f.nonce().empty(), "nonce is spent after confirm");
    }

    // 2) Disarm path: arm false -> diff is embedded.tx_inject=false.
    {
        TxInjectArmFlow f;
        Request issue = f.begin("tok", /*enable=*/false);
        check(issue.changes.at("embedded.tx_inject") == "false",
              "disarm issue diff is embedded.tx_inject=false");
    }

    // 3) 409 on confirm is a terminal refusal, never auto-retried.
    {
        TxInjectArmFlow f;
        f.begin("tok", true);
        Response r1; r1.http_status = 200; r1.need_confirm = true;
        r1.status = "need_confirm"; r1.money_nonce = "N";
        Request confirm;
        f.on_issue_response(r1, &confirm);
        Response r409;
        r409.http_status = 409;
        r409.status = "money_gate";
        r409.error = "money nonce missing or mismatched for this diff; refused";
        f.on_confirm_response(r409);
        check(f.state() == State::Refused, "409 confirm -> Refused (terminal)");
        check(f.nonce().empty(), "nonce dropped after 409 (no replay material kept)");
        check(f.last_error().find("refused") != std::string::npos,
              "409 error surfaced verbatim");
        // The flow exposes NO method that re-emits a confirm from Refused; the
        // only way forward is a fresh begin() (a new nonce), never a silent retry.
    }

    // 4) Editing the desired target while a nonce is outstanding DROPS the nonce.
    {
        TxInjectArmFlow f;
        f.begin("tok", /*enable=*/true);
        Response r1; r1.http_status = 200; r1.need_confirm = true;
        r1.status = "need_confirm"; r1.money_nonce = "N2";
        Request confirm;
        f.on_issue_response(r1, &confirm);
        check(f.state() == State::Issued && f.nonce() == "N2",
              "nonce held in Issued");
        const bool invalidated = f.note_desired_edit(/*enable=*/false);
        check(invalidated, "editing target reports the outstanding nonce invalidated");
        check(f.state() == State::Idle && f.nonce().empty(),
              "edit drops the nonce and returns to Idle");
    }

    // 5) A phase-1 refusal (no nonce, e.g. 403 wrong token / 503 not armed) -> Refused.
    {
        TxInjectArmFlow f;
        f.begin("bad-tok", true);
        Response r;
        r.http_status = 403;
        r.status = "no_token";
        r.error = "missing or invalid control token";
        Request confirm;
        const bool advanced = f.on_issue_response(r, &confirm);
        check(!advanced && f.state() == State::Refused,
              "403 issue -> Refused, no confirm produced");
        check(f.last_error().find("control token") != std::string::npos,
              "issue refusal surfaces the server error verbatim");
    }

    // 6) need_confirm with an EMPTY nonce is malformed -> Refused (fail-closed).
    {
        TxInjectArmFlow f;
        f.begin("tok", true);
        Response r; r.http_status = 200; r.need_confirm = true; r.money_nonce = "";
        Request confirm;
        const bool advanced = f.on_issue_response(r, &confirm);
        check(!advanced && f.state() == State::Refused,
              "need_confirm without a nonce is refused (fail-closed)");
    }

    std::printf(failures == 0 ? "ALL PASS\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
