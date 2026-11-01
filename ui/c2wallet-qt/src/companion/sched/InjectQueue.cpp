// SPDX-License-Identifier: AGPL-3.0-or-later
#include "InjectQueue.hpp"

#include "ArmPolicy.hpp"
#include "Clock.hpp"
#include "Config.hpp"
#include "Json.hpp"

#include "../Submit.hpp" // parse_signed_artifact

#include "../../family/bitcoin/dash/InjectCaps.hpp"
#include "../../family/bitcoin/dash/InjectMaturity.hpp"

#include "Digest.hpp"
#include "TxIntrospect.hpp"
#include "ValidateSeam.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace c2w::companion::sched {

using json::J;

// ── names ────────────────────────────────────────────────────────────────────

namespace {

struct StateName {
    State s;
    const char* n;
};
constexpr StateName kStates[] = {
    {State::Waiting, "waiting"},
    {State::Ready, "ready"},
    {State::Submitting, "submitting"},
    {State::BlockedNotArmed, "blocked_not_armed"},
    {State::BlockedToken, "blocked_token"},
    {State::BlockedNode, "blocked_node"},
    {State::SubmittedUnknown, "submitted_unknown"},
    {State::Admitted, "admitted"},
    {State::IsHold, "is_hold"},
    {State::Riding, "riding"},
    {State::Mined, "mined"},
    {State::Confirmed, "confirmed"},
    {State::Dropped, "dropped"},
    {State::Expired, "expired"},
    {State::Refused, "refused"},
    {State::Paused, "paused"},
};

struct RetryName {
    RetryClass c;
    const char* n;
};
constexpr RetryName kRetries[] = {
    {RetryClass::None, "none"},
    {RetryClass::Backoff, "backoff"},
    {RetryClass::Slow, "slow"},
    {RetryClass::RateWindow, "rate_window"},
    {RetryClass::PoolFull, "pool_full"},
    {RetryClass::Unpriceable, "unpriceable"},
    {RetryClass::Retry5m, "retry_5m"},
    {RetryClass::TokenChange, "token_change"},
    {RetryClass::Arm, "arm"},
    {RetryClass::Operator, "operator"},
    {RetryClass::MempoolPoll, "mempool_poll"},
};

bool is_hex64(const std::string& s)
{
    if (s.size() != 64) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

} // namespace

const char* state_name(State s)
{
    for (const auto& e : kStates)
        if (e.s == s) return e.n;
    return "?";
}

std::optional<State> state_from_name(const std::string& s)
{
    for (const auto& e : kStates)
        if (s == e.n) return e.s;
    return std::nullopt;
}

const char* retry_class_name(RetryClass c)
{
    for (const auto& e : kRetries)
        if (e.c == c) return e.n;
    return "?";
}

std::optional<RetryClass> retry_class_from_name(const std::string& s)
{
    for (const auto& e : kRetries)
        if (s == e.n) return e.c;
    return std::nullopt;
}

std::string short_txid(const std::string& txid)
{
    return txid.size() > 8 ? txid.substr(0, 8) + "..." : txid;
}

// ── encode ───────────────────────────────────────────────────────────────────

namespace {

J encode_item(const Item& it)
{
    J j = J::object();
    j["id"] = it.id;
    j["label"] = it.label;
    j["added_at"] = it.added_at;
    j["rev"] = it.rev;

    J src = J::object();
    src["hex_path"] = it.tx.source.hex_path;
    src["hex_sha256"] = it.tx.source.hex_sha256;
    src["line"] = it.tx.source.line;
    src["manifest_path"] = it.tx.source.manifest_path;
    src["manifest_sha256"] = it.tx.source.manifest_sha256;
    src["mode"] = it.tx.source.mode;
    src["fee_mode"] = it.tx.source.fee_mode;
    src["fee"] = it.tx.source.fee;
    src["value_out"] = it.tx.source.value_out;
    src["vin"] = it.tx.source.vin;
    src["vout"] = it.tx.source.vout;
    J tx = J::object();
    tx["txid"] = it.tx.txid;
    tx["raw_tx"] = it.tx.raw_tx;
    tx["size"] = it.tx.size;
    tx["source"] = std::move(src);
    j["tx"] = std::move(tx);

    const MaturityTrigger& m = it.triggers.maturity;
    J mat = J::object();
    mat["enabled"] = m.enabled;
    mat["safe_from_height"] = m.safe_from_height > 0 ? J(m.safe_from_height) : J(nullptr);
    mat["youngest_input_height"] = m.youngest_input_height > 0 ? J(m.youngest_input_height) : J(nullptr);
    mat["source"] = m.source;
    mat["inputs_with_unknown_height"] = m.inputs_with_unknown_height;
    mat["slack_blocks"] = m.slack_blocks;
    mat["override_consent"] = json::opt(m.override_consent);
    J parents = J::array();
    for (const ParentReq& p : it.triggers.after_parent) {
        J pj = J::object();
        pj["txid"] = p.txid;
        pj["min_confirmations"] = p.min_confirmations;
        parents.push_back(std::move(pj));
    }
    J trig = J::object();
    trig["maturity"] = std::move(mat);
    trig["not_before_height"] = json::opt(it.triggers.not_before_height);
    trig["not_before_time"] = json::opt(it.triggers.not_before_time);
    trig["after_parent"] = std::move(parents);
    j["triggers"] = std::move(trig);

    J sub = J::object();
    sub["expiry_blocks"] = it.submit.expiry_blocks;
    sub["max_fee"] = it.submit.max_fee;
    sub["flags"] = it.submit.flags;
    sub["auto_resubmit_max"] = it.submit.auto_resubmit_max;
    sub["allow_auto_arm"] = json::opt(it.submit.allow_auto_arm);
    sub["auto_renew"] = it.submit.auto_renew;
    j["submit"] = std::move(sub);

    j["paused"] = it.paused;
    j["state"] = state_name(it.state);
    j["state_since"] = it.state_since;
    j["why"] = it.why;

    const NodeRecord& n = it.node;
    J node = J::object();
    node["admitted_at"] = json::opt(n.admitted_at);
    node["time_added"] = json::opt(n.time_added);
    node["expiry_height"] = json::opt(n.expiry_height);
    node["mined_height"] = json::opt(n.mined_height);
    node["mined_hash"] = json::opt(n.mined_hash);
    node["confirmations"] = n.confirmations;
    node["last_seen_in_mempool"] = json::opt(n.last_seen_in_mempool);
    node["last_build"] = nullptr; // per-build verdict: needs the optional node ledger endpoint (S4)
    node["scan_from_height"] = n.scan_from_height;
    node["mined_height_unknown"] = n.mined_height_unknown;
    j["node"] = std::move(node);

    const RetryState& r = it.retry;
    J retry = J::object();
    retry["class"] = retry_class_name(r.cls);
    retry["not_before"] = json::opt(r.not_before);
    retry["backoff_count"] = r.backoff_count;
    retry["unknown_polls"] = r.unknown_polls;
    retry["resubmits"] = r.resubmits;
    retry["unpriceable"] = r.unpriceable;
    retry["token_fingerprint"] = json::opt(r.token_fingerprint);
    j["retry"] = std::move(retry);

    J attempts = J::array();
    for (const Attempt& a : it.attempts) {
        J aj = J::object();
        aj["at"] = a.at;
        aj["http"] = a.http;
        aj["cause"] = a.cause;
        aj["txid_echo"] = a.txid_echo;
        aj["expiry_height"] = json::opt(a.expiry_height);
        aj["armed"] = json::opt(a.armed);
        aj["duration_ms"] = a.duration_ms;
        attempts.push_back(std::move(aj));
    }
    j["attempts"] = std::move(attempts);

    J jr = J::array();
    for (const JournalEntry& e : it.journal) {
        J ej = J::object();
        ej["at"] = e.at;
        ej["event"] = e.event;
        ej["detail"] = e.detail;
        jr.push_back(std::move(ej));
    }
    j["journal"] = std::move(jr);
    return j;
}

} // namespace

std::string queue_to_json(const Queue& q)
{
    J root = J::object();
    root["schema"] = q.schema;
    root["coin"] = q.coin;
    root["network"] = q.network;
    J node = J::object();
    node["url"] = q.node.url;
    node["token_file"] = q.node.token_file;
    root["node"] = std::move(node);

    J d = J::object();
    d["expiry_blocks"] = q.defaults.expiry_blocks;
    d["max_fee"] = q.defaults.max_fee;
    d["flags"] = q.defaults.flags;
    d["auto_resubmit_max"] = q.defaults.auto_resubmit_max;
    d["after_parent_min_confirmations"] = q.defaults.after_parent_min_confirmations;
    d["poll_sec"] = q.defaults.poll_sec;
    d["display_confirmations"] = q.defaults.display_confirmations;
    root["defaults"] = std::move(d);

    const ArmPolicyRecord& p = q.arm_policy;
    J ap = J::object();
    ap["auto_arm"] = p.auto_arm;
    ap["auto_disarm_when_idle"] = p.auto_disarm_when_idle;
    ap["consented_at"] = json::opt(p.consented_at);
    ap["consent_text"] = json::opt(p.consent_text);
    ap["suspended_reason"] = json::opt(p.suspended_reason);
    ap["last_arm_attempt_at"] = json::opt(p.last_arm_attempt_at);
    ap["armed_by_scheduler_at"] = json::opt(p.armed_by_scheduler_at);
    root["arm_policy"] = std::move(ap);

    J items = J::array();
    for (const Item& it : q.items) items.push_back(encode_item(it));
    root["items"] = std::move(items);

    J tracked = J::array();
    for (const Tracked& t : q.tracked) {
        J tj = J::object();
        tj["txid"] = t.txid;
        tj["first_requested_height"] = t.first_requested_height;
        tj["mined_height"] = json::opt(t.mined_height);
        tj["mined_hash"] = json::opt(t.mined_hash);
        tj["scan_from_height"] = t.scan_from_height;
        tj["window_scanned"] = t.window_scanned;
        tracked.push_back(std::move(tj));
    }
    root["tracked"] = std::move(tracked);

    J alerts = J::array();
    for (const Alert& a : q.alerts) {
        J aj = J::object();
        aj["at"] = a.at;
        aj["kind"] = a.kind;
        aj["detail"] = a.detail;
        alerts.push_back(std::move(aj));
    }
    root["alerts"] = std::move(alerts);

    J runner = J::object();
    runner["last_enabled"] = json::opt(q.runner.last_enabled);
    runner["tick_count"] = q.runner.tick_count;
    runner["last_tick_at"] = json::opt(q.runner.last_tick_at);
    root["runner"] = std::move(runner);

    return json::dump(root);
}

// ── decode ───────────────────────────────────────────────────────────────────

namespace {

bool decode_item(json::Reader& rd, const J& j, const std::string& p, Item& it)
{
    if (!j.is_object()) {
        rd.fail(p, "expected an object");
        return false;
    }
    it.id = rd.req_str(j, "id", p);
    it.label = rd.str(j, "label", p);
    it.added_at = rd.str(j, "added_at", p);
    it.rev = rd.i64(j, "rev", p);

    if (const J* tx = rd.obj(j, "tx", p)) {
        const std::string tp = p + ".tx";
        it.tx.txid = rd.req_str(*tx, "txid", tp);
        it.tx.raw_tx = rd.req_str(*tx, "raw_tx", tp);
        it.tx.size = rd.i64(*tx, "size", tp);
        if (const J* s = rd.obj(*tx, "source", tp)) {
            const std::string sp = tp + ".source";
            TxSource& src = it.tx.source;
            src.hex_path = rd.str(*s, "hex_path", sp);
            src.hex_sha256 = rd.str(*s, "hex_sha256", sp);
            src.line = rd.i64(*s, "line", sp);
            src.manifest_path = rd.str(*s, "manifest_path", sp);
            src.manifest_sha256 = rd.str(*s, "manifest_sha256", sp);
            src.mode = rd.str(*s, "mode", sp);
            src.fee_mode = rd.str(*s, "fee_mode", sp);
            src.fee = rd.i64(*s, "fee", sp);
            src.value_out = rd.i64(*s, "value_out", sp);
            src.vin = rd.i64(*s, "vin", sp);
            src.vout = rd.i64(*s, "vout", sp);
        }
    } else {
        rd.fail(p + ".tx", "required object missing");
    }

    if (const J* t = rd.obj(j, "triggers", p)) {
        const std::string tp = p + ".triggers";
        if (const J* m = rd.obj(*t, "maturity", tp)) {
            const std::string mp = tp + ".maturity";
            MaturityTrigger& mt = it.triggers.maturity;
            mt.enabled = rd.boolean(*m, "enabled", mp);
            mt.safe_from_height = rd.i64(*m, "safe_from_height", mp);
            mt.youngest_input_height = rd.i64(*m, "youngest_input_height", mp);
            mt.source = rd.str(*m, "source", mp);
            mt.inputs_with_unknown_height = rd.i64(*m, "inputs_with_unknown_height", mp);
            mt.slack_blocks = rd.i64(*m, "slack_blocks", mp);
            mt.override_consent = rd.ostr(*m, "override_consent", mp);
            if (mt.enabled && mt.safe_from_height <= 0) rd.fail(mp, "enabled without a safe_from_height");
        }
        it.triggers.not_before_height = rd.oi64(*t, "not_before_height", tp);
        it.triggers.not_before_time = rd.ostr(*t, "not_before_time", tp);
        if (it.triggers.not_before_time) {
            int64_t v = 0;
            std::string perr;
            if (!parse_utc(*it.triggers.not_before_time, v, perr)) rd.fail(tp + ".not_before_time", perr);
        }
        if (const J* ps = rd.arr(*t, "after_parent", tp)) {
            for (size_t i = 0; i < ps->size(); ++i) {
                const std::string pp = tp + ".after_parent[" + std::to_string(i) + "]";
                ParentReq pr;
                pr.txid = rd.req_str((*ps)[i], "txid", pp);
                pr.min_confirmations = rd.i64((*ps)[i], "min_confirmations", pp, 1);
                if (rd.ok() && !is_hex64(pr.txid)) rd.fail(pp, "txid must be 64 lowercase hex");
                it.triggers.after_parent.push_back(pr);
            }
        }
    }

    if (const J* s = rd.obj(j, "submit", p)) {
        const std::string sp = p + ".submit";
        it.submit.expiry_blocks = rd.i64(*s, "expiry_blocks", sp, 576);
        it.submit.max_fee = rd.i64(*s, "max_fee", sp);
        it.submit.flags = rd.i64(*s, "flags", sp);
        it.submit.auto_resubmit_max = rd.i64(*s, "auto_resubmit_max", sp, 3);
        it.submit.allow_auto_arm = rd.obool(*s, "allow_auto_arm", sp);
        it.submit.auto_renew = rd.boolean(*s, "auto_renew", sp);
    }

    it.paused = rd.boolean(j, "paused", p);
    const std::string st = rd.req_str(j, "state", p);
    if (rd.ok()) {
        const auto s = state_from_name(st);
        if (!s) rd.fail(p + ".state", "unknown state '" + st + "'");
        else it.state = *s;
    }
    it.state_since = rd.str(j, "state_since", p);
    it.why = rd.str(j, "why", p);

    if (const J* n = rd.obj(j, "node", p)) {
        const std::string np = p + ".node";
        NodeRecord& nr = it.node;
        nr.admitted_at = rd.ostr(*n, "admitted_at", np);
        nr.time_added = rd.oi64(*n, "time_added", np);
        nr.expiry_height = rd.oi64(*n, "expiry_height", np);
        nr.mined_height = rd.oi64(*n, "mined_height", np);
        nr.mined_hash = rd.ostr(*n, "mined_hash", np);
        nr.confirmations = rd.i64(*n, "confirmations", np);
        nr.last_seen_in_mempool = rd.ostr(*n, "last_seen_in_mempool", np);
        nr.scan_from_height = rd.i64(*n, "scan_from_height", np);
        nr.mined_height_unknown = rd.boolean(*n, "mined_height_unknown", np);
    }

    if (const J* r = rd.obj(j, "retry", p)) {
        const std::string rp = p + ".retry";
        RetryState& rs = it.retry;
        const std::string cls = rd.str(*r, "class", rp, "none");
        const auto c = retry_class_from_name(cls);
        if (!c) rd.fail(rp + ".class", "unknown retry class '" + cls + "'");
        else rs.cls = *c;
        rs.not_before = rd.oi64(*r, "not_before", rp);
        rs.backoff_count = rd.i64(*r, "backoff_count", rp);
        rs.unknown_polls = rd.i64(*r, "unknown_polls", rp);
        rs.resubmits = rd.i64(*r, "resubmits", rp);
        rs.unpriceable = rd.i64(*r, "unpriceable", rp);
        rs.token_fingerprint = rd.ostr(*r, "token_fingerprint", rp);
    }

    if (const J* as = rd.arr(j, "attempts", p)) {
        for (size_t i = 0; i < as->size(); ++i) {
            const std::string ap = p + ".attempts[" + std::to_string(i) + "]";
            const J& a = (*as)[i];
            Attempt at;
            at.at = rd.str(a, "at", ap);
            at.http = rd.i64(a, "http", ap);
            at.cause = rd.str(a, "cause", ap);
            at.txid_echo = rd.str(a, "txid_echo", ap);
            at.expiry_height = rd.oi64(a, "expiry_height", ap);
            at.armed = rd.obool(a, "armed", ap);
            at.duration_ms = rd.i64(a, "duration_ms", ap);
            it.attempts.push_back(std::move(at));
        }
    }
    if (const J* js = rd.arr(j, "journal", p)) {
        for (size_t i = 0; i < js->size(); ++i) {
            const std::string jp = p + ".journal[" + std::to_string(i) + "]";
            const J& e = (*js)[i];
            it.journal.push_back({rd.str(e, "at", jp), rd.str(e, "event", jp), rd.str(e, "detail", jp)});
        }
    }
    if (rd.ok() && !is_hex64(it.tx.txid)) rd.fail(p + ".tx.txid", "must be 64 lowercase hex");
    return rd.ok();
}

} // namespace

bool queue_from_json(const std::string& text, Queue& out, std::string& why)
{
    J root;
    if (!json::parse_bounded(text, root, why)) {
        why = "queue: " + why;
        return false;
    }
    if (!root.is_object()) {
        why = "queue: top level is not an object";
        return false;
    }
    json::Reader rd;
    Queue q;
    q.schema = rd.req_str(root, "schema", "queue");
    if (rd.ok() && q.schema != kQueueSchema) {
        why = "queue: unknown schema '" + q.schema + "' (expected " + kQueueSchema + ")";
        return false;
    }
    q.coin = rd.str(root, "coin", "queue", "dash");
    q.network = rd.str(root, "network", "queue", "mainnet");
    if (rd.ok() && q.coin != "dash") rd.fail("queue.coin", "only dash is supported");
    if (rd.ok() && q.network != "mainnet" && q.network != "testnet")
        rd.fail("queue.network", "must be mainnet or testnet");
    if (const J* n = rd.obj(root, "node", "queue")) {
        q.node.url = rd.str(*n, "url", "queue.node", q.node.url);
        q.node.token_file = rd.str(*n, "token_file", "queue.node");
    }
    if (const J* d = rd.obj(root, "defaults", "queue")) {
        Defaults& df = q.defaults;
        df.expiry_blocks = rd.i64(*d, "expiry_blocks", "queue.defaults", df.expiry_blocks);
        df.max_fee = rd.i64(*d, "max_fee", "queue.defaults", df.max_fee);
        df.flags = rd.i64(*d, "flags", "queue.defaults", df.flags);
        df.auto_resubmit_max = rd.i64(*d, "auto_resubmit_max", "queue.defaults", df.auto_resubmit_max);
        df.after_parent_min_confirmations =
            rd.i64(*d, "after_parent_min_confirmations", "queue.defaults", df.after_parent_min_confirmations);
        df.poll_sec = rd.i64(*d, "poll_sec", "queue.defaults", df.poll_sec);
        df.display_confirmations = rd.i64(*d, "display_confirmations", "queue.defaults", df.display_confirmations);
    }
    if (const J* a = rd.obj(root, "arm_policy", "queue")) {
        ArmPolicyRecord& p = q.arm_policy;
        p.auto_arm = rd.boolean(*a, "auto_arm", "queue.arm_policy");
        p.auto_disarm_when_idle = rd.boolean(*a, "auto_disarm_when_idle", "queue.arm_policy");
        p.consented_at = rd.ostr(*a, "consented_at", "queue.arm_policy");
        p.consent_text = rd.ostr(*a, "consent_text", "queue.arm_policy");
        p.suspended_reason = rd.ostr(*a, "suspended_reason", "queue.arm_policy");
        p.last_arm_attempt_at = rd.oi64(*a, "last_arm_attempt_at", "queue.arm_policy");
        p.armed_by_scheduler_at = rd.ostr(*a, "armed_by_scheduler_at", "queue.arm_policy");
    }
    if (const J* items = rd.arr(root, "items", "queue")) {
        std::set<std::string> ids;
        for (size_t i = 0; i < items->size() && rd.ok(); ++i) {
            Item it;
            if (!decode_item(rd, (*items)[i], "queue.items[" + std::to_string(i) + "]", it)) break;
            if (!ids.insert(it.id).second) {
                rd.fail("queue.items[" + std::to_string(i) + "].id", "duplicate id '" + it.id + "'");
                break;
            }
            q.items.push_back(std::move(it));
        }
    } else if (rd.ok()) {
        rd.fail("queue.items", "required array missing");
    }
    if (const J* tr = rd.arr(root, "tracked", "queue")) {
        for (size_t i = 0; i < tr->size(); ++i) {
            const std::string tp = "queue.tracked[" + std::to_string(i) + "]";
            Tracked t;
            t.txid = rd.req_str((*tr)[i], "txid", tp);
            t.first_requested_height = rd.i64((*tr)[i], "first_requested_height", tp);
            t.mined_height = rd.oi64((*tr)[i], "mined_height", tp);
            t.mined_hash = rd.ostr((*tr)[i], "mined_hash", tp);
            t.scan_from_height = rd.i64((*tr)[i], "scan_from_height", tp);
            t.window_scanned = rd.boolean((*tr)[i], "window_scanned", tp);
            q.tracked.push_back(std::move(t));
        }
    }
    if (const J* al = rd.arr(root, "alerts", "queue")) {
        for (size_t i = 0; i < al->size(); ++i) {
            const std::string ap = "queue.alerts[" + std::to_string(i) + "]";
            q.alerts.push_back(
                {rd.str((*al)[i], "at", ap), rd.str((*al)[i], "kind", ap), rd.str((*al)[i], "detail", ap)});
        }
    }
    if (const J* r = rd.obj(root, "runner", "queue")) {
        q.runner.last_enabled = rd.obool(*r, "last_enabled", "queue.runner");
        q.runner.tick_count = rd.i64(*r, "tick_count", "queue.runner");
        q.runner.last_tick_at = rd.ostr(*r, "last_tick_at", "queue.runner");
    }
    if (!rd.ok()) {
        why = rd.err;
        return false;
    }
    if (!q.node.url.empty() && !validate_node_url(q.node.url, why)) {
        why = "queue: " + why;
        return false;
    }
    if (!arm::validate(q, why)) {
        why = "queue: " + why;
        return false;
    }
    out = std::move(q);
    return true;
}

// ── file I/O ─────────────────────────────────────────────────────────────────

bool save_queue_file(const std::string& path, const Queue& q, std::string& why)
{
#if defined(_WIN32)
    (void)path;
    (void)q;
    why = "queue file I/O unsupported on this platform";
    return false;
#else
    const std::string text = queue_to_json(q);
    const std::string tmp = path + ".tmp." + std::to_string(static_cast<long>(::getpid()));
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        why = "cannot create " + tmp + " (" + std::strerror(errno) + ")";
        return false;
    }
    size_t off = 0;
    while (off < text.size()) {
        const ssize_t n = ::write(fd, text.data() + off, text.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            why = "write " + tmp + " failed (" + std::strerror(errno) + ")";
            ::close(fd);
            ::unlink(tmp.c_str());
            return false;
        }
        off += static_cast<size_t>(n);
    }
    if (::fsync(fd) != 0 || ::close(fd) != 0) {
        why = "fsync/close " + tmp + " failed (" + std::strerror(errno) + ")";
        ::unlink(tmp.c_str());
        return false;
    }
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        why = "rename to " + path + " failed (" + std::strerror(errno) + ")";
        ::unlink(tmp.c_str());
        return false;
    }
    // Best effort: persist the directory entry too.
    const size_t slash = path.rfind('/');
    const std::string dir = slash == std::string::npos ? "." : (slash == 0 ? "/" : path.substr(0, slash));
    const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) {
        (void)::fsync(dfd);
        ::close(dfd);
    }
    return true;
#endif
}

bool load_queue_file(const std::string& path, Queue& out, std::string& why)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        why = "cannot open " + path;
        return false;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    const std::string text = ss.str();
    if (text.size() > 256u * 1024u * 1024u) {
        why = path + " is implausibly large";
        return false;
    }
    return queue_from_json(text, out, why);
}

QueueLock::~QueueLock() { release(); }

bool QueueLock::acquire(const std::string& queue_path, bool blocking, std::string& why)
{
#if defined(_WIN32)
    (void)queue_path;
    (void)blocking;
    why = "queue locking unsupported on this platform";
    return false;
#else
    release();
    const std::string lp = queue_path + ".lock";
    const int fd = ::open(lp.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        why = "cannot open " + lp + " (" + std::strerror(errno) + ")";
        return false;
    }
    if (::flock(fd, LOCK_EX | (blocking ? 0 : LOCK_NB)) != 0) {
        why = errno == EWOULDBLOCK ? "lock held by another runner (" + lp + ")"
                                   : "flock " + lp + " failed (" + std::strerror(errno) + ")";
        ::close(fd);
        return false;
    }
    fd_ = fd;
    return true;
#endif
}

void QueueLock::release()
{
#if !defined(_WIN32)
    if (fd_ >= 0) {
        ::flock(fd_, LOCK_UN);
        ::close(fd_);
    }
#endif
    fd_ = -1;
}

// ── item helpers ─────────────────────────────────────────────────────────────

Item* find_item(Queue& q, const std::string& id)
{
    for (Item& it : q.items)
        if (it.id == id) return &it;
    return nullptr;
}

const Item* find_item(const Queue& q, const std::string& id)
{
    for (const Item& it : q.items)
        if (it.id == id) return &it;
    return nullptr;
}

Item* find_item_by_txid(Queue& q, const std::string& txid)
{
    for (Item& it : q.items)
        if (it.tx.txid == txid) return &it;
    return nullptr;
}

const Item* find_item_by_txid(const Queue& q, const std::string& txid)
{
    for (const Item& it : q.items)
        if (it.tx.txid == txid) return &it;
    return nullptr;
}

Tracked* find_tracked(Queue& q, const std::string& txid)
{
    for (Tracked& t : q.tracked)
        if (t.txid == txid) return &t;
    return nullptr;
}

bool is_terminal(const Item& it)
{
    switch (it.state) {
    case State::Confirmed:
    case State::Refused: return true;
    case State::Dropped: return it.retry.resubmits >= it.submit.auto_resubmit_max;
    case State::Expired: return !it.submit.auto_renew;
    default: return false;
    }
}

bool is_dead_end(const Item& it)
{
    return is_terminal(it) && it.state != State::Confirmed;
}

void journal(Item& it, const std::string& at, const std::string& event, const std::string& detail)
{
    it.journal.push_back({at, event, detail});
    if (it.journal.size() > kMaxJournal)
        it.journal.erase(it.journal.begin(), it.journal.begin() + static_cast<long>(it.journal.size() - kMaxJournal));
}

void add_attempt(Item& it, Attempt a)
{
    it.attempts.push_back(std::move(a));
    if (it.attempts.size() > kMaxAttempts)
        it.attempts.erase(it.attempts.begin(),
                          it.attempts.begin() + static_cast<long>(it.attempts.size() - kMaxAttempts));
}

void add_alert(Queue& q, const std::string& at, const std::string& kind, const std::string& detail)
{
    q.alerts.push_back({at, kind, detail});
    if (q.alerts.size() > kMaxAlerts)
        q.alerts.erase(q.alerts.begin(), q.alerts.begin() + static_cast<long>(q.alerts.size() - kMaxAlerts));
}

// ── operator edits ───────────────────────────────────────────────────────────

namespace {

void edit_state(Item& it, State s, const std::string& at, const std::string& why_text, const std::string& event)
{
    const std::string from = state_name(it.state);
    if (it.state != s) it.state_since = at;
    it.state = s;
    it.why = why_text;
    ++it.rev;
    journal(it, at, event, from + " -> " + state_name(s));
}

} // namespace

bool pause_item(Queue& q, const std::string& id, int64_t now, std::string& why)
{
    Item* it = find_item(q, id);
    if (!it) { why = "no item " + id; return false; }
    if (it->paused) { why = id + " is already paused"; return false; }
    if (is_terminal(*it)) { why = id + " is terminal (" + state_name(it->state) + "); nothing to pause"; return false; }
    it->paused = true;
    edit_state(*it, State::Paused, format_utc(now), "paused by the operator", "paused");
    return true;
}

bool resume_item(Queue& q, const std::string& id, int64_t now, std::string& why)
{
    Item* it = find_item(q, id);
    if (!it) { why = "no item " + id; return false; }
    if (!it->paused) { why = id + " is not paused"; return false; }
    it->paused = false;
    it->retry.cls = RetryClass::None;
    it->retry.not_before.reset();
    edit_state(*it, State::Waiting, format_utc(now), "resumed; triggers evaluated at the next tick", "resumed");
    return true;
}

bool requeue_item(Queue& q, const std::string& id, int64_t now, std::string& why)
{
    Item* it = find_item(q, id);
    if (!it) { why = "no item " + id; return false; }
    if (!is_terminal(*it)) { why = id + " is not terminal (" + state_name(it->state) + ")"; return false; }
    it->retry = RetryState{};
    it->node = NodeRecord{};
    it->paused = false;
    edit_state(*it, State::Waiting, format_utc(now), "re-queued by the operator; attempt counters reset", "requeued");
    return true;
}

bool retry_item(Queue& q, const std::string& id, int64_t now, std::string& why)
{
    Item* it = find_item(q, id);
    if (!it) { why = "no item " + id; return false; }
    if (it->state != State::BlockedNotArmed && it->state != State::BlockedToken && it->state != State::BlockedNode &&
        it->state != State::Ready) {
        why = id + " is " + state_name(it->state) + "; Retry applies to blocked or backing-off items";
        return false;
    }
    it->retry.cls = RetryClass::None;
    it->retry.not_before.reset();
    it->retry.token_fingerprint.reset();
    edit_state(*it, State::Ready, format_utc(now), "operator Retry", "retry");
    return true;
}

bool remove_item(Queue& q, const std::string& id, std::string& why)
{
    for (auto i = q.items.begin(); i != q.items.end(); ++i) {
        if (i->id != id) continue;
        if (!is_terminal(*i) && !i->paused) {
            why = id + " is " + state_name(i->state) + "; pause it first";
            return false;
        }
        q.items.erase(i);
        return true;
    }
    why = "no item " + id;
    return false;
}

// ── pre-flight ───────────────────────────────────────────────────────────────

bool preflight_raw_tx(const std::string& raw_tx_hex, const std::string& expected_txid, std::string& why)
{
    namespace caps = c2w::dash::caps;
    const auto bytes = c2w::artifact::from_hex(raw_tx_hex);
    if (!bytes || bytes->empty()) {
        why = "raw tx is not hex";
        return false;
    }
    if (bytes->size() > caps::kMaxInjectTxBytes) {
        why = "size " + std::to_string(bytes->size()) + " B > " + std::to_string(caps::kMaxInjectTxBytes) +
              " B (node inject cap)";
        return false;
    }
    std::string sw;
    if (!c2w::artifact::accept_as_signed(*bytes, sw)) {
        why = "not a signed tx: " + sw;
        return false;
    }
    const c2w::artifact::RawTxShape shape = c2w::artifact::inspect_raw_tx(*bytes);
    if (shape.vin > caps::kMaxInjectInputs) {
        why = "vin " + std::to_string(shape.vin) + " > " + std::to_string(caps::kMaxInjectInputs) + " (node sandbox cap)";
        return false;
    }
    if (shape.vout > caps::kMaxInjectOutputs) {
        why = "vout " + std::to_string(shape.vout) + " > " + std::to_string(caps::kMaxInjectOutputs) +
              " (node sandbox cap)";
        return false;
    }
    if (!expected_txid.empty()) {
        const std::string txid = c2w::artifact::sha256d_display(*bytes);
        if (txid != expected_txid) {
            why = "txid mismatch: raw tx hashes to " + txid + ", item says " + expected_txid;
            return false;
        }
    }
    return true;
}

// ── enqueue ──────────────────────────────────────────────────────────────────

namespace {

struct ManifestInput {
    std::string txid;
    std::optional<int64_t> height;
    bool coinbase = true;
};

struct ManifestTx {
    std::string txid;
    int64_t fee = 0;
    int64_t value_out = 0;
    int64_t vin = 0;
    int64_t vout = 0;
    std::vector<ManifestInput> inputs;
};

struct ManifestView {
    std::string mode;
    std::string fee_mode;
    std::string hex_file_sha256;
    std::vector<ManifestTx> txs;
    std::optional<int64_t> safe_from_height;
    std::optional<int64_t> youngest_input_height;
    bool maturity_known = false;  // every input height present and safe_from_height set
    int64_t inputs_with_unknown_height = 0;
};

bool parse_manifest(const std::string& text, const std::string& network, ManifestView& mv, std::string& why)
{
    J root;
    if (!json::parse_bounded(text, root, why) || !root.is_object()) {
        why = "manifest: " + (why.empty() ? std::string("top level is not an object") : why);
        return false;
    }
    json::Reader rd;
    const std::string schema = rd.req_str(root, "schema", "manifest");
    if (rd.ok() && schema != kManifestSchema) {
        why = "manifest: unknown schema '" + schema + "'";
        return false;
    }
    if (rd.str(root, "coin", "manifest") != "dash") rd.fail("manifest.coin", "must be dash");
    const std::string net = rd.str(root, "network", "manifest");
    if (rd.ok() && net != network)
        rd.fail("manifest.network", "manifest is for " + net + ", the queue is " + network);
    mv.mode = rd.str(root, "mode", "manifest");
    mv.fee_mode = rd.str(root, "fee_mode", "manifest");
    mv.hex_file_sha256 = rd.req_str(root, "hex_file_sha256", "manifest");
    if (const J* txs = rd.arr(root, "txs", "manifest")) {
        for (size_t i = 0; i < txs->size(); ++i) {
            const std::string tp = "manifest.txs[" + std::to_string(i) + "]";
            const J& t = (*txs)[i];
            ManifestTx mt;
            mt.txid = rd.req_str(t, "txid", tp);
            mt.fee = rd.i64(t, "fee", tp);
            mt.value_out = rd.i64(t, "value_out", tp);
            mt.vin = rd.i64(t, "vin", tp);
            mt.vout = rd.i64(t, "vout", tp);
            if (const J* ins = rd.arr(t, "inputs", tp)) {
                for (size_t k = 0; k < ins->size(); ++k) {
                    const std::string ip = tp + ".inputs[" + std::to_string(k) + "]";
                    ManifestInput mi;
                    mi.txid = rd.req_str((*ins)[k], "txid", ip);
                    mi.height = rd.oi64((*ins)[k], "height", ip);
                    mi.coinbase = rd.boolean((*ins)[k], "coinbase", ip, true);
                    mt.inputs.push_back(std::move(mi));
                }
            }
            mv.txs.push_back(std::move(mt));
        }
    } else if (rd.ok()) {
        rd.fail("manifest.txs", "required array missing");
    }
    if (root.contains("tx_count") && root["tx_count"].is_number_integer() &&
        root["tx_count"].get<int64_t>() != static_cast<int64_t>(mv.txs.size()))
        rd.fail("manifest.tx_count", "does not match the txs array");
    if (const J* m = rd.obj(root, "maturity", "manifest")) {
        mv.safe_from_height = rd.oi64(*m, "safe_from_height", "manifest.maturity");
        mv.youngest_input_height = rd.oi64(*m, "youngest_input_height", "manifest.maturity");
    }
    if (!rd.ok()) {
        why = rd.err;
        return false;
    }

    // Cross-check the manifest's maturity claim against its own inputs, over
    // every tx (the manifest computes it over all inputs of the plan).
    std::vector<c2w::dash::maturity::InputHeight> all;
    int64_t youngest = 0;
    for (const ManifestTx& t : mv.txs) {
        for (const ManifestInput& in : t.inputs) {
            if (!in.height || *in.height <= 0) {
                ++mv.inputs_with_unknown_height;
                continue;
            }
            all.push_back({*in.height, in.coinbase});
            youngest = std::max(youngest, *in.height);
        }
    }
    if (mv.inputs_with_unknown_height > 0 || !mv.safe_from_height || all.empty()) {
        mv.maturity_known = false;
        return true;
    }
    const int64_t s =
        c2w::dash::maturity::safe_from_height(all, [](const c2w::dash::maturity::InputHeight& h) { return h; });
    if (s != *mv.safe_from_height) {
        why = "manifest maturity mismatch: maturity.safe_from_height " + std::to_string(*mv.safe_from_height) +
              " but its inputs give " + std::to_string(s) + " (tampered or mixed-up manifest)";
        return false;
    }
    if (mv.youngest_input_height && *mv.youngest_input_height != youngest) {
        why = "manifest maturity mismatch: maturity.youngest_input_height " +
              std::to_string(*mv.youngest_input_height) + " but its inputs give " + std::to_string(youngest);
        return false;
    }
    mv.youngest_input_height = youngest;
    mv.maturity_known = true;
    return true;
}

std::string next_item_id(const Queue& q, int64_t now)
{
    const std::string date = format_utc(now).substr(0, 10); // YYYY-MM-DD
    std::string prefix = "q-" + date.substr(0, 4) + date.substr(5, 2) + date.substr(8, 2) + "-";
    int64_t best = 0;
    for (const Item& it : q.items) {
        if (it.id.rfind(prefix, 0) != 0) continue;
        const std::string tail = it.id.substr(prefix.size());
        int64_t v = 0;
        bool digits = !tail.empty();
        for (char c : tail) {
            if (c < '0' || c > '9') { digits = false; break; }
            v = v * 10 + (c - '0');
        }
        if (digits) best = std::max(best, v);
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%03lld", static_cast<long long>(best + 1));
    return prefix + buf;
}

} // namespace

EnqueueResult enqueue(Queue& q, const EnqueueRequest& req, int64_t now)
{
    EnqueueResult r;
    auto refuse = [&](const std::string& w) {
        r.ok = false;
        r.why = w;
        r.ids.clear();
        r.notes.clear();
        return r;
    };
    const std::string at = format_utc(now);

    std::string err;
    const auto sc = parse_signed_artifact(req.hex_text, err);
    if (!sc) return refuse("hex file: " + err);
    if (sc->tx_hexes.empty()) return refuse("hex file carries no transaction");
    const size_t nlines = sc->tx_hexes.size();
    std::vector<size_t> lines;
    if (req.line) {
        if (*req.line < 1 || static_cast<size_t>(*req.line) > nlines)
            return refuse("line " + std::to_string(*req.line) + " is outside 1.." + std::to_string(nlines));
        lines.push_back(static_cast<size_t>(*req.line - 1));
    } else {
        for (size_t i = 0; i < nlines; ++i) lines.push_back(i);
    }

    const std::string hex_sha =
        c2w::artifact::to_hex(c2w::artifact::sha256(reinterpret_cast<const uint8_t*>(req.hex_text.data()),
                                                    req.hex_text.size()));
    ManifestView mv;
    const bool have_manifest = req.manifest_text.has_value();
    std::string manifest_sha;
    if (have_manifest) {
        if (!parse_manifest(*req.manifest_text, q.network, mv, err)) return refuse(err);
        manifest_sha = c2w::artifact::to_hex(c2w::artifact::sha256(
            reinterpret_cast<const uint8_t*>(req.manifest_text->data()), req.manifest_text->size()));
        if (mv.hex_file_sha256 != hex_sha)
            return refuse("hex file sha256 " + hex_sha + " does not match the manifest's hex_file_sha256 " +
                          mv.hex_file_sha256);
        if (mv.txs.size() != nlines)
            return refuse("manifest lists " + std::to_string(mv.txs.size()) + " txs, the hex file carries " +
                          std::to_string(nlines) + " lines");
    }

    if (req.not_before_height && *req.not_before_height <= 0) return refuse("not_before_height must be > 0");
    if (req.not_before_time) {
        int64_t t = 0;
        if (!parse_utc(*req.not_before_time, t, err)) return refuse("not_before_time: " + err);
    }
    if (req.maturity_slack_blocks < 0) return refuse("maturity slack must be >= 0");
    if (req.expiry_blocks && *req.expiry_blocks < 1) return refuse("expiry_blocks must be >= 1");
    if (req.max_fee && *req.max_fee < 0) return refuse("max_fee must be >= 0");
    if (req.flags && *req.flags < 0) return refuse("flags must be >= 0");
    if (req.auto_resubmit_max && *req.auto_resubmit_max < 0) return refuse("auto_resubmit_max must be >= 0");
    if (req.allow_auto_arm.value_or(false) &&
        (!q.arm_policy.consented_at || q.arm_policy.consented_at->empty()))
        return refuse("allow_auto_arm:true needs a recorded auto-arm consent on the queue (arm policy)");
    for (const ParentReq& p : req.after_parent) {
        if (!is_hex64(p.txid)) return refuse("after_parent txid '" + p.txid + "' must be 64 lowercase hex");
        if (p.min_confirmations < 1) return refuse("after_parent min_confirmations must be >= 1");
    }
    if (req.inputs_known_mature_consent && req.inputs_known_mature_consent->empty())
        return refuse("the inputs-are-mature override needs a consent text");

    Queue staged = q;
    for (size_t idx : lines) {
        const std::string& hex = sc->tx_hexes[idx];
        const std::string ln = "line " + std::to_string(idx + 1);
        if (!preflight_raw_tx(hex, "", err)) return refuse(ln + ": " + err);
        const std::string txid = c2w::artifact::crossgap_txid(hex);
        if (have_manifest && mv.txs[idx].txid != txid)
            return refuse(ln + ": txid " + txid + " does not match the manifest's txs[" + std::to_string(idx) +
                          "].txid " + mv.txs[idx].txid);
        if (const Item* dup = find_item_by_txid(staged, txid))
            return refuse(ln + ": txid " + short_txid(txid) + " is already queued as " + dup->id + " (" +
                          state_name(dup->state) + "); use requeue");

        Item it;
        it.id = next_item_id(staged, now);
        it.label = req.label.empty() ? (have_manifest ? mv.mode : std::string("inject")) : req.label;
        if (lines.size() > 1) it.label += " #" + std::to_string(idx + 1);
        it.added_at = at;
        it.tx.txid = txid;
        it.tx.raw_tx = hex;
        it.tx.size = static_cast<int64_t>(hex.size() / 2);
        TxSource& src = it.tx.source;
        src.hex_path = req.hex_path;
        src.hex_sha256 = hex_sha;
        src.line = static_cast<int64_t>(idx + 1);
        const auto shape = c2w::artifact::inspect_raw_tx(*c2w::artifact::from_hex(hex));
        src.vin = static_cast<int64_t>(shape.vin);
        src.vout = static_cast<int64_t>(shape.vout);
        if (have_manifest) {
            src.manifest_path = req.manifest_path;
            src.manifest_sha256 = manifest_sha;
            src.mode = mv.mode;
            src.fee_mode = mv.fee_mode;
            src.fee = mv.txs[idx].fee;
            src.value_out = mv.txs[idx].value_out;
        }

        MaturityTrigger& mt = it.triggers.maturity;
        if (have_manifest && mv.maturity_known) {
            mt.enabled = true;
            mt.safe_from_height = *mv.safe_from_height;
            mt.youngest_input_height = mv.youngest_input_height.value_or(0);
            mt.source = "manifest.maturity.safe_from_height";
        } else {
            mt.enabled = false;
            mt.source = have_manifest ? "manifest: maturity unknown" : "no manifest (bare hex)";
            mt.inputs_with_unknown_height =
                have_manifest ? (mv.inputs_with_unknown_height > 0 ? mv.inputs_with_unknown_height
                                                                   : static_cast<int64_t>(mv.txs[idx].inputs.size()))
                              : src.vin;
            if (!req.not_before_height && !req.inputs_known_mature_consent)
                return refuse(ln + ": input maturity is unknown (" + mt.source + ", " +
                              std::to_string(mt.inputs_with_unknown_height) +
                              " inputs without a height); set not_before_height or confirm the inputs are mature");
            mt.override_consent = req.inputs_known_mature_consent;
        }
        mt.slack_blocks = req.maturity_slack_blocks;
        it.triggers.not_before_height = req.not_before_height;
        it.triggers.not_before_time = req.not_before_time;

        // Parents: explicit ones, then inputs whose txid is already queued.
        for (const ParentReq& p : req.after_parent) it.triggers.after_parent.push_back(p);
        if (have_manifest && req.discover_parents) {
            for (const ManifestInput& in : mv.txs[idx].inputs) {
                if (!find_item_by_txid(staged, in.txid)) continue;
                const bool present =
                    std::any_of(it.triggers.after_parent.begin(), it.triggers.after_parent.end(),
                                [&](const ParentReq& p) { return p.txid == in.txid; });
                if (present) continue;
                it.triggers.after_parent.push_back({in.txid, staged.defaults.after_parent_min_confirmations});
                r.notes.push_back(it.id + ": after_parent pre-filled from input " + short_txid(in.txid) +
                                  " (queued as " + find_item_by_txid(staged, in.txid)->id + ")");
            }
        }
        for (const ParentReq& p : it.triggers.after_parent) {
            if (p.txid == txid) return refuse(ln + ": a tx cannot be its own parent");
            if (const Item* parent = find_item_by_txid(staged, p.txid)) {
                if (is_dead_end(*parent))
                    return refuse(ln + ": parent " + short_txid(p.txid) + " (" + parent->id + ") is " +
                                  state_name(parent->state) +
                                  ": it is not going to be mined; re-queue the parent first");
            } else if (!find_tracked(staged, p.txid)) {
                Tracked t;
                t.txid = p.txid;
                staged.tracked.push_back(t);
            }
        }

        SubmitOptions& so = it.submit;
        so.expiry_blocks = req.expiry_blocks.value_or(staged.defaults.expiry_blocks);
        so.max_fee = req.max_fee.value_or(src.fee_mode == "relay" ? src.fee : staged.defaults.max_fee);
        so.flags = req.flags.value_or(staged.defaults.flags);
        so.auto_resubmit_max = req.auto_resubmit_max.value_or(staged.defaults.auto_resubmit_max);
        so.allow_auto_arm = req.allow_auto_arm;
        so.auto_renew = req.auto_renew;

        it.paused = req.pause;
        it.state = req.pause ? State::Paused : State::Waiting;
        it.state_since = at;
        it.why = req.pause ? "paused on add" : "enqueued; triggers are evaluated at the next tick";
        journal(it, at, "enqueued",
                have_manifest ? "hex sha256 matches manifest; txid matches txs[" + std::to_string(idx) + "]"
                              : "bare hex (no manifest)");
        r.ids.push_back(it.id);
        staged.items.push_back(std::move(it));
    }
    q = std::move(staged);
    r.ok = true;
    return r;
}

} // namespace c2w::companion::sched
