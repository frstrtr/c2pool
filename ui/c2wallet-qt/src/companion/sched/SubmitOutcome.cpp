// SPDX-License-Identifier: AGPL-3.0-or-later
#include "SubmitOutcome.hpp"

#include "Json.hpp"

namespace c2w::companion::sched {

namespace {

bool starts_with(const std::string& s, const char* p)
{
    return s.rfind(p, 0) == 0;
}

// The tx itself is wrong: only a rebuilt (re-signed) tx can pass.
bool is_rebuild_cause(const std::string& c)
{
    return c == cause::Oversize || c == cause::PoolOversize || c == cause::TypeUnsupported ||
           c == cause::BadVersionOrType || c == cause::Bip68Unsupported || c == cause::BadVoutRange ||
           c == cause::SpentShapedOutput || c == cause::SandboxTooManyInputs ||
           c == cause::SandboxTooManyOutputs || c == cause::SandboxScriptsigTooLarge ||
           c == cause::SandboxTotalScriptsigTooLarge || c == cause::SandboxTooManySigops ||
           c == cause::ScriptInvalid;
}

// The node's own unreachable switch defaults.
bool is_node_unknown_default(const std::string& c)
{
    return c == cause::GateUnknown || c == cause::PoolUnknown || c == cause::RateLimitedUnknown ||
           c == cause::RateLimitedPeersUnknown || c == cause::SandboxUnknown;
}

const char* const kNodeCauses[] = {
    cause::Ok,
    cause::Disabled,
    cause::TypeUnsupported,
    cause::Oversize,
    cause::ScriptCheckUnarmed,
    cause::AlreadyKnown,
    cause::AlreadyConfirmed,
    cause::Unpriceable,
    cause::Bip68Unsupported,
    cause::BadVoutRange,
    cause::BadVersionOrType,
    cause::FeeAboveMax,
    cause::ScriptInvalid,
    cause::SpentShapedOutput,
    cause::GateUnknown,
    cause::PoolDuplicate,
    cause::PoolFull,
    cause::PoolTotalBytes,
    cause::PoolOversize,
    cause::PoolUnknown,
    cause::RateLimitedCount,
    cause::RateLimitedBytes,
    cause::RateLimitedUnknown,
    cause::RateLimitedPeersCount,
    cause::RateLimitedPeersBytes,
    cause::RateLimitedPeersUnknown,
    cause::SandboxTooManyInputs,
    cause::SandboxTooManyOutputs,
    cause::SandboxScriptsigTooLarge,
    cause::SandboxTotalScriptsigTooLarge,
    cause::SandboxTooManySigops,
    cause::SandboxUnknown,
};

Outcome make(State s, RetryClass r, const std::string& c, const std::string& why, int http)
{
    Outcome o;
    o.next = s;
    o.retry = r;
    o.cause = c;
    o.why = why;
    o.http = http;
    return o;
}

} // namespace

Outcome classify_cause(const std::string& c, int http)
{
    if (c == cause::Ok)
        return make(State::Admitted, RetryClass::None, c, "admitted by the node", http);
    if (c == cause::AlreadyKnown || c == cause::PoolDuplicate)
        return make(State::Admitted, RetryClass::None, c,
                    "already in the node's inject pool (" + c + "): idempotent success", http);
    if (c == cause::AlreadyConfirmed)
        return make(State::Mined, RetryClass::None, c,
                    "node answered inject-already-confirmed: the tx is already mined", http);
    if (c == cause::Disabled)
        return make(State::BlockedNotArmed, RetryClass::Arm, c,
                    "blocked: node not armed (inject-disabled). Standing arm: add --embedded-tx-inject to "
                    "the unit; or enable auto-arm (consent) in the arm policy",
                    http);
    if (c == cause::RateLimitedCount || c == cause::RateLimitedBytes || c == cause::RateLimitedPeersCount ||
        c == cause::RateLimitedPeersBytes)
        return make(State::Ready, RetryClass::RateWindow, c,
                    "node rate budget spent (" + c + "); retry after the window", http);
    if (c == cause::PoolFull || c == cause::PoolTotalBytes)
        return make(State::Ready, RetryClass::PoolFull, c,
                    "node inject pool full (" + c + "): other injects occupy it; retry in 5 min", http);
    if (c == cause::ScriptCheckUnarmed)
        return make(State::BlockedNode, RetryClass::Slow, c,
                    "node cannot script-check injects (no UTXO view or --embedded-fold-checkscripts=false); "
                    "fix the node, retry every 5 min",
                    http);
    if (c == cause::Unpriceable)
        return make(State::Ready, RetryClass::Unpriceable, c,
                    "node cannot price an input (UTXO lane withheld or behind, or the input is spent); "
                    "retry in 10 min",
                    http);
    if (is_rebuild_cause(c))
        return make(State::Refused, RetryClass::None, c,
                    "refused by the node (" + c + "): the tx itself is wrong; the signer must rebuild it", http);
    if (c == cause::FeeAboveMax)
        return make(State::Refused, RetryClass::None, c,
                    "refused by the node (" + c + "): the tx pays a fee above this item's submit.max_fee (0 for a "
                    "zero-fee inject unless the manifest's fee_mode is relay). No re-sign is needed: if the fee is "
                    "intended, raise submit.max_fee and re-queue",
                    http);
    if (is_node_unknown_default(c)) {
        Outcome o = make(State::BlockedNode, RetryClass::Operator, c,
                         "node answered its own unreachable default '" + c + "' (a node bug); operator Retry only",
                         http);
        o.alert = true;
        return o;
    }
    if (c == cause::ImmatureCoinbaseInput) {
        Outcome o = make(State::Waiting, RetryClass::None, c,
                         "node refused an immature coinbase input: the scheduler fired early (bug); waiting",
                         http);
        o.alert = true;
        o.scheduler_bug = true;
        return o;
    }
    if (starts_with(c, cause::PrevoutPrefix))
        return make(State::Refused, RetryClass::None, c,
                    "refused by the node (" + c + "): an input is missing or spent", http);
    if (starts_with(c, cause::OraclePrefix))
        return make(State::Ready, RetryClass::Retry5m, c, "node input oracle unavailable (" + c + "); retry in 5 min",
                    http);
    Outcome o = make(State::BlockedNode, RetryClass::Operator, c,
                     "node answered an unknown cause '" + c + "'; operator Retry only", http);
    o.alert = true;
    o.recognized = false;
    return o;
}

const char* const* node_cause_names(size_t& count)
{
    count = sizeof(kNodeCauses) / sizeof(kNodeCauses[0]);
    return kNodeCauses;
}

Outcome classify_submit(const HttpReply& r, const std::string& our_txid)
{
    if (!r.transport_ok)
        return make(State::Ready, RetryClass::Backoff, "transport-error",
                    "node unreachable (" + (r.error.empty() ? std::string("no reply") : r.error) +
                        "): node or tunnel down",
                    0);

    json::J body;
    std::string perr;
    const bool parsed = json::parse_bounded(r.body, body, perr) && body.is_object();
    json::Reader rd;
    const std::string c = parsed ? rd.str(body, "cause", "reply") : std::string();
    const std::string err = parsed ? rd.str(body, "error", "reply") : std::string();

    if (r.status == 403) {
        if (c == cause::BadToken)
            return make(State::BlockedToken, RetryClass::TokenChange, "http-403",
                        "blocked: node refused the control token (no --control-plane-token-file on the node, "
                        "or a different token file); retries when the token file changes",
                        403);
        return make(State::BlockedNode, RetryClass::Operator, "http-403",
                    "blocked: node refused the request as not local (" + (err.empty() ? c : err) +
                        "); is a proxy in the path?",
                    403);
    }
    if (r.status == 503)
        return make(State::BlockedNode, RetryClass::Slow, "http-503",
                    "blocked: node tx-inject submit not wired (" + (err.empty() ? std::string("503") : err) +
                        "); retry every 5 min",
                    503);
    if (r.status == 504) {
        Outcome o = make(State::SubmittedUnknown, RetryClass::MempoolPoll, "http-504",
                         "504 submit dispatch timed out: the node may still accept it; polling the mempool", 504);
        return o;
    }
    if (r.status == 400) {
        Outcome o = make(State::Refused, RetryClass::None, c.empty() ? "http-400" : c,
                         "node refused the request body (" + (c.empty() ? err : c) +
                             "): unreachable after the local pre-flight, a scheduler bug",
                         400);
        o.scheduler_bug = true;
        o.alert = true;
        return o;
    }
    if ((r.status == 200 || r.status == 409 || r.status == 422) && parsed && !c.empty()) {
        Outcome o = classify_cause(c, r.status);
        if (body.contains("armed") && body["armed"].is_boolean()) o.armed = body["armed"].get<bool>();
        const std::string txid = rd.str(body, "txid", "reply");
        if (!txid.empty()) o.txid_echo = txid;
        if (c == cause::Ok) {
            const bool ok_flag = body.contains("ok") && body["ok"].is_boolean() && body["ok"].get<bool>();
            if (!ok_flag || r.status != 200) {
                o = make(State::BlockedNode, RetryClass::Operator, c,
                         "node answered cause ok without ok:true / HTTP 200; operator Retry only", r.status);
                o.alert = true;
            } else if (txid != our_txid) {
                o = make(State::Refused, RetryClass::None, "txid-mismatch",
                         "node admitted txid " + txid + " but this item is " + our_txid + " (txid mismatch)", 200);
                o.alert = true;
                o.txid_echo = txid;
            }
        }
        return o;
    }
    Outcome o = make(State::BlockedNode, RetryClass::Operator, "http-" + std::to_string(r.status),
                     "unexpected reply HTTP " + std::to_string(r.status) +
                         (c.empty() ? (err.empty() ? std::string() : " (" + err + ")") : " (" + c + ")") +
                         "; operator Retry only",
                     r.status);
    o.alert = true;
    return o;
}

int64_t backoff_seconds(RetryClass c, int64_t count, int64_t window_sec)
{
    switch (c) {
    case RetryClass::Backoff: {
        static const int64_t seq[] = {30, 60, 120, 300};
        if (count < 1) count = 1;
        return count >= 4 ? 300 : seq[count - 1];
    }
    case RetryClass::Slow:
    case RetryClass::PoolFull:
    case RetryClass::Retry5m: return 300;
    case RetryClass::RateWindow: return (window_sec > 0 ? window_sec : 60) + 15;
    case RetryClass::Unpriceable: return 600;
    default: return 0;
    }
}

} // namespace c2w::companion::sched
