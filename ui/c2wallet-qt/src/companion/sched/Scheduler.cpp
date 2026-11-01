// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Scheduler.hpp"

#include "ArmPolicy.hpp"
#include "TokenFile.hpp"

#include <algorithm>

namespace c2w::companion::sched {

namespace {

const char* kNotArmedWhy =
    "blocked: node not armed (enabled=false). Standing arm: add --embedded-tx-inject to the unit; or enable "
    "auto-arm (consent) in the arm policy";

bool is_idle_state(State s)
{
    return s == State::Mined || s == State::Confirmed || s == State::Refused || s == State::Dropped ||
           s == State::Expired || s == State::Paused;
}

std::string confirmations_text(int64_t n)
{
    return std::to_string(n) + (n == 1 ? " confirmation" : " confirmations");
}

void clear_retry_gate(Item& it)
{
    it.retry.cls = RetryClass::None;
    it.retry.not_before.reset();
    it.retry.token_fingerprint.reset();
}

} // namespace

Scheduler::Scheduler(Queue& q, NodeApi& api, const Clock& clock, JournalSink& sink, SchedulerOptions opt)
    : q_(q), api_(api), clock_(clock), sink_(sink), opt_(std::move(opt)), view_(api)
{
}

Scheduler::~Scheduler() { drop_token(); }

std::string Scheduler::token_path() const
{
    return opt_.token_file.empty() ? q_.node.token_file : opt_.token_file;
}

// ── helpers ──────────────────────────────────────────────────────────────────

std::string Scheduler::belt(const std::string& s) const
{
    if (token_loaded_ && contains_secret(s, token_)) return "[line withheld: it contained the control token]";
    return s;
}

void Scheduler::persist()
{
    if (!persist_) return;
    std::string why;
    if (!persist_(q_, why)) {
        report_.persist_failed = true;
        report_.persist_error = why;
    }
}

void Scheduler::note(Item& it, const std::string& event, const std::string& detail)
{
    const std::string d = belt(detail);
    journal(it, at_, event, d);
    sink_.line(at_ + " " + it.id + " " + event + ": " + d);
}

void Scheduler::queue_note(const std::string& event, const std::string& detail)
{
    sink_.line(at_ + " queue " + event + ": " + belt(detail));
}

void Scheduler::raise_alert(const std::string& kind, const std::string& detail)
{
    const std::string d = belt(detail);
    add_alert(q_, at_, kind, d);
    ++report_.alerts;
    sink_.line(at_ + " ALERT " + kind + ": " + d);
}

void Scheduler::transition(Item& it, State s, const std::string& why)
{
    const std::string w = belt(why);
    if (it.state == s) {
        it.why = w;
        return;
    }
    const std::string from = state_name(it.state);
    it.state = s;
    it.state_since = at_;
    it.why = w;
    ++report_.transitions;
    observed_changed_.insert(it.id);
    note(it, "state", from + " -> " + state_name(s) + ": " + w);
    persist();
}

void Scheduler::set_why(Item& it, const std::string& why)
{
    it.why = belt(why);
}

bool Scheduler::load_token(std::string& why)
{
    if (token_loaded_) return true;
    if (!TokenFile::read(token_path(), token_, why)) return false;
    token_loaded_ = true;
    return true;
}

void Scheduler::drop_token()
{
    token_.clear();
    token_loaded_ = false;
}

ChainSnapshot Scheduler::snapshot()
{
    const TipInfo& t = view_.tip();
    ChainSnapshot c;
    c.tip_known = t.known;
    c.tip = t.height;
    c.tip_unknown_why = t.why;
    return c;
}

ParentStatus Scheduler::parent_status(const std::string& txid) const
{
    ParentStatus ps;
    if (const Item* p = find_item_by_txid(q_, txid)) {
        ps.known = true;
        ps.state_text = state_name(p->state);
        const bool in_block = p->state == State::Mined || p->state == State::Confirmed;
        if (in_block && (p->node.mined_height || p->node.mined_height_unknown)) {
            ps.mined = true;
            ps.mined_height = p->node.mined_height;
            ps.height_unknown = !p->node.mined_height.has_value();
        } else if (in_block) {
            ps.state_text = "mined (locating its block)";
        }
        return ps;
    }
    for (const Tracked& t : q_.tracked) {
        if (t.txid != txid) continue;
        ps.known = true;
        ps.mined = t.mined_height.has_value();
        ps.mined_height = t.mined_height;
        ps.state_text = "not seen in a block yet (foreign parent)";
        return ps;
    }
    return ps;
}

Verdict Scheduler::evaluate_item(const Item& it)
{
    return evaluate(it, snapshot(), now_, [this](const std::string& txid) { return parent_status(txid); });
}

// ── tick ─────────────────────────────────────────────────────────────────────

TickReport Scheduler::tick()
{
    report_ = TickReport{};
    observed_changed_.clear();
    now_ = clock_.now_unix();
    at_ = format_utc(now_);
    view_.begin_tick();
    ++q_.runner.tick_count;
    q_.runner.last_tick_at = at_;

    detect_disarm(view_.inject_status());

    // Phase 1: observe what the node holds.
    observe_tracked();
    for (Item& it : q_.items) {
        if (it.paused) {
            if (it.state != State::Paused) transition(it, State::Paused, "paused by the operator");
            continue;
        }
        switch (it.state) {
        case State::Submitting:
            it.retry.cls = RetryClass::MempoolPoll;
            it.retry.unknown_polls = 0;
            transition(it, State::SubmittedUnknown,
                       "submitted_unknown — found mid-submit after a restart; the POST may have reached the node");
            observe_unknown(it);
            break;
        case State::SubmittedUnknown: observe_unknown(it); break;
        case State::Admitted:
        case State::IsHold:
        case State::Riding: observe_admitted(it); break;
        case State::Mined: observe_mined(it); break;
        default: break;
        }
    }

    // Phase 2: act.
    for (Item& it : q_.items) {
        if (it.paused) continue;
        const bool fresh = observed_changed_.count(it.id) != 0;
        switch (it.state) {
        case State::Waiting:
        case State::Ready: act_waiting_or_ready(it); break;
        case State::BlockedNotArmed: act_blocked_not_armed(it); break;
        case State::BlockedToken: act_blocked_token(it); break;
        case State::BlockedNode: act_blocked_node(it); break;
        case State::Dropped:
            if (!fresh) act_dropped(it);
            break;
        case State::Expired:
            if (!fresh) act_expired(it);
            break;
        default: break;
        }
    }

    // Phase 3.
    maybe_auto_disarm();

    drop_token();
    persist();
    return report_;
}

// ── phase 0: disarm detection ────────────────────────────────────────────────

void Scheduler::detect_disarm(const InjectStatus& st)
{
    if (!st.ok) return;
    if (q_.runner.last_enabled.value_or(false) && !st.enabled) {
        const bool any_live = std::any_of(q_.items.begin(), q_.items.end(),
                                          [](const Item& it) { return !it.paused && !is_terminal(it); });
        if (any_live) {
            raise_alert("disarmed", std::string("node disarmed (restart or operator): tx-inject-status enabled "
                                                "true -> false") +
                                        (st.wired ? "" : "; wired=false (the node restarted)"));
            for (Item& it : q_.items) {
                if (!it.paused && it.state == State::Ready)
                    block_not_armed(it, "blocked: node disarmed (restart or operator) — enabled=false", false);
            }
        }
        q_.arm_policy.armed_by_scheduler_at.reset();
    }
    q_.runner.last_enabled = st.enabled;
}

// ── phase 1: observe ─────────────────────────────────────────────────────────

void Scheduler::observe_tracked()
{
    if (q_.tracked.empty()) return;
    const TipInfo& tip = view_.tip();
    if (!tip.known) return;
    for (Tracked& t : q_.tracked) {
        const bool needed = std::any_of(q_.items.begin(), q_.items.end(), [&](const Item& it) {
            if (is_terminal(it)) return false;
            return std::any_of(it.triggers.after_parent.begin(), it.triggers.after_parent.end(),
                               [&](const ParentReq& p) { return p.txid == t.txid; });
        });
        if (!needed) continue;
        if (t.first_requested_height == 0) t.first_requested_height = tip.height;
        if (!t.mined_height) {
            const MempoolView& mp = view_.mempool();
            if (mp.ok && mp.txids.count(t.txid)) {
                t.scan_from_height = tip.height + 1;
                t.window_scanned = true;
                continue;
            }
            const int64_t window_lo = std::max<int64_t>(1, tip.height - opt_.body_window + 1);
            const int64_t lo = t.window_scanned ? std::max(t.scan_from_height, window_lo) : window_lo;
            const FindResult f = view_.find_tx(t.txid, lo, tip.height);
            t.window_scanned = true;
            if (f.found) {
                t.mined_height = f.height;
                t.mined_hash = f.hash;
                queue_note("parent", "foreign parent " + short_txid(t.txid) + " mined at " + std::to_string(f.height));
                persist();
            } else {
                t.scan_from_height = tip.height + 1;
            }
            continue;
        }
        const int64_t h = *t.mined_height;
        const bool check = tip.height < h ||
                           (opt_.reorg_check_every > 0 && q_.runner.tick_count % opt_.reorg_check_every == 0);
        if (!check) continue;
        std::string err;
        const auto hash = view_.block_hash(h, err);
        if (tip.height < h || (hash && t.mined_hash && *hash != *t.mined_hash)) {
            queue_note("reorg", "foreign parent " + short_txid(t.txid) + ": block at " + std::to_string(h) +
                                    " changed; scanning again");
            t.mined_height.reset();
            t.mined_hash.reset();
            t.scan_from_height = h;
            persist();
        }
    }
}

void Scheduler::observe_unknown(Item& it)
{
    const MempoolView& mp = view_.mempool();
    if (!mp.ok) {
        set_why(it, "submitted_unknown — " + mp.error + "; this poll is not counted");
        return;
    }
    if (mp.txids.count(it.tx.txid)) {
        const TipInfo& tip = view_.tip();
        it.node.admitted_at = at_;
        if (tip.known) it.node.scan_from_height = std::max(it.node.scan_from_height, tip.height + 1);
        clear_retry_gate(it);
        it.retry.unknown_polls = 0;
        transition(it, State::Admitted, "admitted — the timed-out submit landed (seen in the mempool)");
        return;
    }
    ++it.retry.unknown_polls;
    if (it.retry.unknown_polls >= opt_.unknown_polls_max) {
        it.retry.unknown_polls = 0;
        clear_retry_gate(it);
        transition(it, State::Ready,
                   "ready — 504 unresolved: absent from the mempool after " + std::to_string(opt_.unknown_polls_max) +
                       " polls; resubmitting (a late accept answers inject-already-known)");
        return;
    }
    set_why(it, "submitted_unknown — 504; polling the mempool (" + std::to_string(it.retry.unknown_polls) + "/" +
                    std::to_string(opt_.unknown_polls_max) + ")");
}

void Scheduler::mark_mined(Item& it, int64_t height, const std::string& hash, int64_t tip)
{
    it.node.mined_height = height;
    it.node.mined_hash = hash;
    it.node.mined_height_unknown = false;
    it.node.confirmations = tip - height + 1;
    transition(it, State::Mined,
               "mined at " + std::to_string(height) + " (" + hash.substr(0, 16) + "), " +
                   confirmations_text(it.node.confirmations));
}

void Scheduler::observe_admitted(Item& it)
{
    const MempoolView& mp = view_.mempool();
    if (!mp.ok) {
        set_why(it, std::string(state_name(it.state)) + " — mempool unavailable: " + mp.error);
        return;
    }
    const TipInfo& tip = view_.tip();
    if (mp.txids.count(it.tx.txid)) {
        it.node.last_seen_in_mempool = at_;
        if (tip.known) it.node.scan_from_height = std::max(it.node.scan_from_height, tip.height + 1);
        if (!it.node.time_added) {
            const MempoolEntryInfo e = view_.mempool_entry(it.tx.txid);
            if (e.ok && e.present && e.time_added) {
                it.node.time_added = *e.time_added;
            } else {
                int64_t t = now_;
                std::string perr;
                if (it.node.admitted_at) (void)parse_utc(*it.node.admitted_at, t, perr);
                it.node.time_added = t;
                note(it, "is_hold",
                     "time_added unavailable (" + (e.error.empty() ? std::string("no entry") : e.error) +
                         "); the IS-hold is estimated from the submit time");
            }
        }
        const int64_t until = *it.node.time_added + opt_.is_hold_secs;
        if (now_ < until) {
            transition(it, State::IsHold,
                       "is_hold — admitted " + it.node.admitted_at.value_or("?") +
                           "; IS-hold: no islock can form for a zero-fee inject, so the node holds it <= " +
                           std::to_string(opt_.is_hold_secs) +
                           " s after time_added (mempool.hpp:223); rides after ~" + format_utc(until) +
                           " (upper bound; the node may select it earlier if the InstantSend feed is dark). "
                           "Per-build RIDES/HELD is in the node log only (no ledger endpoint on this node)");
        } else {
            transition(it, State::Riding,
                       "riding (inferred) — in the mempool " + format_eta_seconds(now_ - *it.node.time_added) +
                           ", IS-hold elapsed; waiting for an embedded block");
        }
        return;
    }

    // Left the mempool: mined, expired or dropped.
    if (!tip.known) {
        set_why(it, std::string(state_name(it.state)) + " — not in the mempool; " + tip.why + "; block scan deferred");
        return;
    }
    const int64_t lo = std::max({it.node.scan_from_height, tip.height - opt_.body_window + 1, int64_t{1}});
    const FindResult f = view_.find_tx(it.tx.txid, lo, tip.height);
    if (f.found) {
        mark_mined(it, f.height, f.hash, tip.height);
        return;
    }
    const std::string range = lo <= tip.height ? std::to_string(lo) + ".." + std::to_string(tip.height)
                                               : std::string("(no new block)");
    const std::string gap =
        f.missing > 0 ? " (" + std::to_string(f.missing) + " heights without a retained body)" : std::string();
    if (it.node.expiry_height && tip.height > *it.node.expiry_height) {
        transition(it, State::Expired,
                   "expired — tip " + std::to_string(tip.height) + " > expiry_height " +
                       std::to_string(*it.node.expiry_height) + ", not found in blocks " + range + gap +
                       (it.submit.auto_renew ? "; auto-renew resubmits with a fresh expiry" : "; terminal"));
        return;
    }
    const bool budget = it.retry.resubmits < it.submit.auto_resubmit_max;
    transition(it, State::Dropped,
               "dropped — left the mempool at " + at_ + " without a block in " + range + gap +
                   " (node restart or eviction); " +
                   (budget ? "resubmit " + std::to_string(it.retry.resubmits + 1) + "/" +
                                 std::to_string(it.submit.auto_resubmit_max) + " when triggers hold"
                           : std::string("auto-resubmit exhausted; terminal")));
}

void Scheduler::observe_mined(Item& it)
{
    const TipInfo& tip = view_.tip();
    if (!tip.known) {
        set_why(it, "mined — " + tip.why);
        return;
    }
    if (!it.node.mined_height) {
        if (it.node.mined_height_unknown) return;
        const int64_t lo = std::max<int64_t>(1, tip.height - opt_.body_window + 1);
        const FindResult f = view_.find_tx(it.tx.txid, lo, tip.height);
        if (!f.found) {
            it.node.mined_height_unknown = true;
            set_why(it, "mined (height unknown) — the node answered inject-already-confirmed and no retained block "
                        "body in " +
                            std::to_string(lo) + ".." + std::to_string(tip.height) +
                            " carries it (mined before the body window?)");
            note(it, "mined", it.why);
            persist();
            return;
        }
        it.node.mined_height = f.height;
        it.node.mined_hash = f.hash;
        note(it, "mined", "found in block " + std::to_string(f.height) + " (" + f.hash.substr(0, 16) + ")");
        persist();
    }
    const int64_t h = *it.node.mined_height;
    const bool check =
        tip.height < h || (opt_.reorg_check_every > 0 && q_.runner.tick_count % opt_.reorg_check_every == 0);
    if (check) {
        std::string err;
        const auto hash = view_.block_hash(h, err);
        if (tip.height < h || (hash && it.node.mined_hash && *hash != *it.node.mined_hash)) {
            note(it, "reorg",
                 "block at " + std::to_string(h) + " changed (" + it.node.mined_hash.value_or("?").substr(0, 16) +
                     " -> " + (hash ? hash->substr(0, 16) : std::string("none")) + ")");
            it.node.mined_height.reset();
            it.node.mined_hash.reset();
            it.node.confirmations = 0;
            it.node.scan_from_height = h;
            const MempoolView& mp = view_.mempool();
            if (mp.ok && mp.txids.count(it.tx.txid)) {
                transition(it, State::Admitted,
                           "admitted — a reorg dropped block " + std::to_string(h) + "; the node re-admitted the inject");
            } else {
                clear_retry_gate(it);
                transition(it, State::Waiting,
                           "waiting — a reorg dropped block " + std::to_string(h) +
                               "; resubmit when the triggers hold (the node re-admits after a rewind)");
            }
            return;
        }
    }
    it.node.confirmations = tip.height - h + 1;
    const std::string where = "mined at " + std::to_string(h) + " (" + it.node.mined_hash.value_or("").substr(0, 16) +
                              "), " + confirmations_text(it.node.confirmations);
    if (it.node.confirmations >= q_.defaults.display_confirmations)
        transition(it, State::Confirmed, "confirmed — " + where);
    else
        set_why(it, where);
}

// ── phase 2: act ─────────────────────────────────────────────────────────────

void Scheduler::act_waiting_or_ready(Item& it)
{
    const Verdict v = evaluate_item(it);
    if (!v.ready) {
        if (it.state != State::Waiting) clear_retry_gate(it);
        transition(it, State::Waiting, "waiting — " + v.why());
        return;
    }
    if (it.state == State::Waiting) transition(it, State::Ready, "ready — all triggers met");
    attempt_submit(it);
}

void Scheduler::attempt_submit(Item& it)
{
    if (it.retry.not_before && now_ < *it.retry.not_before) {
        const std::string last = it.attempts.empty() ? std::string() : " after " + it.attempts.back().cause;
        set_why(it, "ready — retry at " + format_utc(*it.retry.not_before) + " (" + retry_class_name(it.retry.cls) +
                        last + ")");
        return;
    }
    submit(it);
}

void Scheduler::submit(Item& it)
{
    std::string why;
    // Local pre-flight: nothing malformed ever reaches the node.
    if (!preflight_raw_tx(it.tx.raw_tx, it.tx.txid, why)) {
        transition(it, State::Refused, "refused locally (no POST): " + why);
        return;
    }

    const InjectStatus& st = view_.inject_status();
    if (!st.ok) {
        if (st.transport_error) apply_retry(it, RetryClass::Backoff, "node unreachable (" + st.error + ")");
        else block_node(it, RetryClass::Slow, "blocked: tx-inject-status: " + st.error);
        return;
    }
    if (!st.enabled) {
        std::string w;
        const ArmTry t = try_auto_arm(it, w);
        if (t == ArmTry::Diverted) return;
        if (t == ArmTry::NotArmed) {
            block_not_armed(it, w, true);
            return;
        }
    }
    const InjectStatus& s2 = view_.inject_status();
    if ((s2.pool_max_entries > 0 && s2.pool_entries >= s2.pool_max_entries) ||
        (s2.pool_max_total_bytes > 0 && s2.pool_bytes + it.tx.size > s2.pool_max_total_bytes)) {
        set_why(it, "ready — node inject pool full (" + std::to_string(s2.pool_entries) + "/" +
                        std::to_string(s2.pool_max_entries) + " entries, " + std::to_string(s2.pool_bytes) + "/" +
                        std::to_string(s2.pool_max_total_bytes) + " B); waiting one tick");
        return;
    }
    if (s2.have_rate && s2.max_per_window > 0 && s2.local_in_window >= s2.max_per_window) {
        it.retry.cls = RetryClass::RateWindow;
        it.retry.not_before = now_ + (s2.window_sec > 0 ? s2.window_sec : 60);
        set_why(it, "ready — local rate budget in use (" + std::to_string(s2.local_in_window) + "/" +
                        std::to_string(s2.max_per_window) + " per " + std::to_string(s2.window_sec) +
                        " s); retry at " + format_utc(*it.retry.not_before));
        return;
    }
    const TipInfo& tip = view_.tip();
    if (!tip.known) {
        set_why(it, "ready — " + tip.why + "; cannot compute expiry_height");
        return;
    }
    const int64_t expiry = tip.height + it.submit.expiry_blocks;
    if (!load_token(why)) {
        block_token(it, "blocked: token file: " + why);
        return;
    }

    const std::string rest = "\"raw_tx\":\"" + it.tx.raw_tx + "\",\"flags\":" + std::to_string(it.submit.flags) +
                             ",\"expiry_height\":" + std::to_string(expiry) +
                             ",\"max_fee\":" + std::to_string(it.submit.max_fee);
    std::string body = build_token_body(token_, rest);
    transition(it, State::Submitting, "submitting (expiry_height " + std::to_string(expiry) + ")");
    const int64_t t0 = clock_.monotonic_ms();
    const HttpReply reply = api_.post_json(route::kSubmit, body);
    const int64_t dur = clock_.monotonic_ms() - t0;
    wipe_string(body);
    ++report_.submits;
    view_.invalidate_mempool();

    const Outcome o = classify_submit(reply, it.tx.txid);
    Attempt a;
    a.at = at_;
    a.http = o.http;
    a.cause = belt(o.cause);
    a.txid_echo = o.txid_echo.value_or("");
    a.expiry_height = expiry;
    a.armed = o.armed;
    a.duration_ms = dur;
    add_attempt(it, a);
    apply_outcome(it, o, expiry, tip.height);
}

void Scheduler::apply_outcome(Item& it, const Outcome& o, int64_t expiry, int64_t tip)
{
    if (o.alert) raise_alert(o.scheduler_bug ? "scheduler_bug" : "submit", it.id + ": " + o.why);
    switch (o.next) {
    case State::Admitted:
        it.node = NodeRecord{};
        it.node.admitted_at = at_;
        it.node.expiry_height = expiry;
        it.node.scan_from_height = tip + 1;
        clear_retry_gate(it);
        it.retry.backoff_count = 0;
        it.retry.unknown_polls = 0;
        transition(it, State::Admitted,
                   "admitted " + at_ + " (" + o.cause + "), expiry_height " + std::to_string(expiry) +
                       "; next: see it in the mempool");
        return;
    case State::Mined:
        it.node.mined_height.reset();
        it.node.mined_hash.reset();
        it.node.mined_height_unknown = false;
        it.node.confirmations = 0;
        clear_retry_gate(it);
        it.retry.backoff_count = 0;
        transition(it, State::Mined, "mined — " + o.why + "; looking for its block in the body window");
        return;
    case State::SubmittedUnknown:
        it.retry.cls = RetryClass::MempoolPoll;
        it.retry.not_before.reset();
        it.retry.unknown_polls = 0;
        it.node.expiry_height = expiry;
        it.node.scan_from_height = tip + 1;
        transition(it, State::SubmittedUnknown, "submitted_unknown — " + o.why);
        return;
    case State::Ready: apply_retry(it, o.retry, o.why); return;
    case State::BlockedNotArmed: block_not_armed(it, o.why, true); return;
    case State::BlockedToken: block_token(it, o.why); return;
    case State::BlockedNode: block_node(it, o.retry, o.why); return;
    case State::Refused:
        clear_retry_gate(it);
        transition(it, State::Refused, "refused — " + o.why);
        return;
    case State::Waiting:
        clear_retry_gate(it);
        transition(it, State::Waiting, "waiting — " + o.why);
        return;
    default: block_node(it, RetryClass::Operator, "unexpected outcome state " + std::string(state_name(o.next))); return;
    }
}

void Scheduler::apply_retry(Item& it, RetryClass cls, const std::string& why)
{
    it.retry.cls = cls;
    int64_t delay = 0;
    std::string suffix;
    if (cls == RetryClass::Backoff) {
        ++it.retry.backoff_count;
        delay = backoff_seconds(cls, it.retry.backoff_count);
    } else if (cls == RetryClass::Unpriceable) {
        ++it.retry.unpriceable;
        if (it.retry.unpriceable > kUnpriceableRetries) {
            clear_retry_gate(it);
            transition(it, State::Refused,
                       "refused — inject-unpriceable " + std::to_string(it.retry.unpriceable) +
                           " times: an input is not resolvable on the node (UTXO lane withheld or behind, or the "
                           "input is spent)");
            return;
        }
        delay = backoff_seconds(cls, it.retry.unpriceable);
        suffix = " (" + std::to_string(it.retry.unpriceable) + "/" + std::to_string(kUnpriceableRetries) + ")";
    } else if (cls == RetryClass::RateWindow) {
        delay = backoff_seconds(cls, 1, view_.inject_status().window_sec);
    } else {
        delay = backoff_seconds(cls, 1);
    }
    it.retry.not_before = now_ + delay;
    transition(it, State::Ready, "ready — " + why + "; retry at " + format_utc(now_ + delay) + suffix);
}

void Scheduler::block_not_armed(Item& it, const std::string& why, bool alert)
{
    const bool entering = it.state != State::BlockedNotArmed;
    it.retry.cls = RetryClass::Arm;
    it.retry.not_before.reset();
    transition(it, State::BlockedNotArmed, why.empty() ? std::string(kNotArmedWhy) : why);
    if (entering && alert && !arm::consent_applies(q_.arm_policy, it))
        raise_alert("not_armed", it.id + ": node not armed and auto-arm has no consent for this item");
}

void Scheduler::block_token(Item& it, const std::string& why)
{
    it.retry.cls = RetryClass::TokenChange;
    it.retry.not_before.reset();
    it.retry.token_fingerprint = TokenFile::fingerprint(token_path());
    transition(it, State::BlockedToken, why + "; retries when the token file changes (or operator Retry)");
}

void Scheduler::block_node(Item& it, RetryClass cls, const std::string& why)
{
    it.retry.cls = cls;
    if (cls == RetryClass::Slow) {
        it.retry.not_before = now_ + backoff_seconds(cls, 1);
        transition(it, State::BlockedNode, why + "; retry at " + format_utc(*it.retry.not_before));
    } else {
        it.retry.cls = RetryClass::Operator;
        it.retry.not_before.reset();
        transition(it, State::BlockedNode, why + (why.find("operator Retry") == std::string::npos
                                                      ? "; operator Retry only"
                                                      : ""));
    }
}

Scheduler::ArmTry Scheduler::try_auto_arm(Item& it, std::string& why)
{
    ArmPolicyRecord& p = q_.arm_policy;
    if (!arm::consent_applies(p, it)) {
        why.clear(); // the default not-armed text
        return ArmTry::NotArmed;
    }
    if (p.suspended_reason) {
        why = "blocked: node not armed; auto-arm suspended (" + *p.suspended_reason + ")";
        return ArmTry::NotArmed;
    }
    if (p.last_arm_attempt_at && now_ - *p.last_arm_attempt_at < arm::kArmRetrySeconds) {
        why = "blocked: node not armed; next auto-arm attempt after " +
              format_utc(*p.last_arm_attempt_at + arm::kArmRetrySeconds);
        return ArmTry::NotArmed;
    }
    std::string terr;
    if (!load_token(terr)) {
        block_token(it, "blocked: token file: " + terr);
        return ArmTry::Diverted;
    }
    p.last_arm_attempt_at = now_;
    const arm::ArmResult r = arm::two_phase_apply(api_, token_, true);
    report_.arm_posts += r.posts;
    switch (r.kind) {
    case arm::ArmResultKind::Applied: {
        p.armed_by_scheduler_at = at_;
        note(it, "armed", "ARMED by scheduler (consent " + p.consented_at.value_or("?") + ") for " + it.id);
        persist();
        const InjectStatus& st = view_.inject_status(true);
        if (st.ok && st.enabled) {
            q_.runner.last_enabled = true;
            return ArmTry::Armed;
        }
        why = "blocked: armed by the scheduler but tx-inject-status still reports enabled=false";
        return ArmTry::NotArmed;
    }
    case arm::ArmResultKind::NotArmed: block_node(it, RetryClass::Operator, "blocked: " + r.why); return ArmTry::Diverted;
    case arm::ArmResultKind::NoToken: block_token(it, "blocked: auto-arm: " + r.why); return ArmTry::Diverted;
    case arm::ArmResultKind::MoneyGate:
        p.suspended_reason = at_ + " " + r.why;
        raise_alert("money_gate", "auto-arm suspended for this queue: " + r.why +
                                      "; a human must look before consent is recorded again");
        why = "blocked: node not armed; auto-arm suspended (" + r.why + ")";
        return ArmTry::NotArmed;
    case arm::ArmResultKind::Rejected:
        block_node(it, RetryClass::Operator, "blocked: auto-arm: " + r.why);
        return ArmTry::Diverted;
    case arm::ArmResultKind::Protocol:
        raise_alert("arm_protocol", it.id + ": " + r.why);
        block_node(it, RetryClass::Operator, "blocked: " + r.why);
        return ArmTry::Diverted;
    case arm::ArmResultKind::Transport:
        why = "blocked: node not armed; auto-arm failed: " + r.why;
        return ArmTry::NotArmed;
    }
    return ArmTry::NotArmed;
}

void Scheduler::act_blocked_not_armed(Item& it)
{
    const Verdict v = evaluate_item(it);
    if (!v.ready) {
        clear_retry_gate(it);
        transition(it, State::Waiting, "waiting — " + v.why());
        return;
    }
    const InjectStatus& st = view_.inject_status();
    if (!(st.ok && st.enabled)) {
        std::string w;
        const ArmTry t = try_auto_arm(it, w);
        if (t == ArmTry::Diverted) return;
        if (t == ArmTry::NotArmed) {
            set_why(it, w.empty() ? std::string(kNotArmedWhy) : w);
            return;
        }
    }
    clear_retry_gate(it);
    transition(it, State::Ready, "ready — the node is armed (enabled=true)");
    attempt_submit(it);
}

void Scheduler::act_blocked_token(Item& it)
{
    const std::string fp = TokenFile::fingerprint(token_path());
    if (it.retry.token_fingerprint && fp == *it.retry.token_fingerprint) return;
    clear_retry_gate(it);
    transition(it, State::Ready, "ready — the token file changed; retrying");
    act_waiting_or_ready(it);
}

void Scheduler::act_blocked_node(Item& it)
{
    if (it.retry.cls != RetryClass::Slow || !it.retry.not_before || now_ < *it.retry.not_before) return;
    clear_retry_gate(it);
    transition(it, State::Ready, "ready — retrying after the slow back-off");
    act_waiting_or_ready(it);
}

void Scheduler::act_dropped(Item& it)
{
    if (it.retry.resubmits >= it.submit.auto_resubmit_max) {
        set_why(it, "dropped — auto-resubmit exhausted (" + std::to_string(it.retry.resubmits) + "/" +
                        std::to_string(it.submit.auto_resubmit_max) + "); terminal, Re-queue to try again");
        return;
    }
    ++it.retry.resubmits;
    note(it, "resubmit",
         "resubmit " + std::to_string(it.retry.resubmits) + "/" + std::to_string(it.submit.auto_resubmit_max) +
             ": left the mempool without a block (node restart, conflict eviction or expiry)");
    it.node = NodeRecord{};
    clear_retry_gate(it);
    const Verdict v = evaluate_item(it);
    if (!v.ready) {
        transition(it, State::Waiting, "waiting — " + v.why());
        return;
    }
    transition(it, State::Ready, "ready — resubmit " + std::to_string(it.retry.resubmits) + "/" +
                                     std::to_string(it.submit.auto_resubmit_max));
    attempt_submit(it);
}

void Scheduler::act_expired(Item& it)
{
    if (!it.submit.auto_renew) return;
    note(it, "renew", "auto-renew: resubmitting with a fresh expiry_height");
    it.node = NodeRecord{};
    clear_retry_gate(it);
    const Verdict v = evaluate_item(it);
    if (!v.ready) {
        transition(it, State::Waiting, "waiting — " + v.why());
        return;
    }
    transition(it, State::Ready, "ready — auto-renew after expiry");
    attempt_submit(it);
}

// ── phase 3: auto-disarm ─────────────────────────────────────────────────────

void Scheduler::maybe_auto_disarm()
{
    ArmPolicyRecord& p = q_.arm_policy;
    if (!p.auto_disarm_when_idle || !p.consented_at || !p.armed_by_scheduler_at || p.suspended_reason) return;
    const InjectStatus& st = view_.inject_status();
    if (!st.ok || !st.enabled) return;
    for (const Item& it : q_.items)
        if (!is_idle_state(it.state)) return;
    // One apply attempt (arm or disarm) per 10 minutes.
    if (p.last_arm_attempt_at && now_ - *p.last_arm_attempt_at < arm::kArmRetrySeconds) return;
    p.last_arm_attempt_at = now_;
    std::string why;
    if (!load_token(why)) {
        raise_alert("disarm_failed", "auto-disarm: token file: " + why);
        return;
    }
    const arm::ArmResult r = arm::two_phase_apply(api_, token_, false);
    report_.arm_posts += r.posts;
    if (r.kind == arm::ArmResultKind::Applied) {
        p.armed_by_scheduler_at.reset();
        q_.runner.last_enabled = false; // our own disarm is not an alert
        queue_note("disarmed", "DISARMED by scheduler: every item is mined, terminal or paused (auto-disarm when idle)");
        persist();
        return;
    }
    if (r.kind == arm::ArmResultKind::MoneyGate) p.suspended_reason = at_ + " " + r.why;
    raise_alert("disarm_failed", "auto-disarm: " + r.why);
}

} // namespace c2w::companion::sched
