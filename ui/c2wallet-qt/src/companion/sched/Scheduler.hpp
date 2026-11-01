// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Inject scheduler — the per-item state machine (design §5), one tick at a time.
//
// tick() is a plain synchronous function over the injected NodeApi and Clock:
//   0. read /api/tx-inject-status once; detect a disarm (enabled true -> false);
//   1. OBSERVE: tracked foreign parents, then every item the node holds or may
//      hold (submitted_unknown, admitted, is_hold, riding, mined): mempool
//      presence, the IS-hold clock, block-body scans, confirmations, reorgs;
//   2. ACT: waiting/ready items re-evaluate their triggers (never a stale
//      verdict) and submit; blocked items check their unblock condition;
//      dropped/expired items resubmit within their budget;
//   3. auto-disarm when idle (only with consent, only if the scheduler armed).
// Every transition is journaled and persisted through the PersistFn, so a
// fresh Scheduler loaded from the saved queue takes the same next transition.
//
// The control token is read from the token file at first use in a tick, held
// in a zeroizing buffer until the tick ends, placed only into POST bodies
// (wiped after each request), and refused by the journal belt.

#include "ChainView.hpp"
#include "Clock.hpp"
#include "InjectQueue.hpp"
#include "NodeApi.hpp"
#include "SubmitOutcome.hpp"
#include "Triggers.hpp"

#include "../../secure/SecureString.hpp"

#include <cstdint>
#include <functional>
#include <set>
#include <string>

namespace c2w::companion::sched {

// Where the runner's human-readable lines go (stdout/journald for the daemon,
// the GUI log pane). The scheduler never hands it a line containing the token.
struct JournalSink {
    virtual ~JournalSink() = default;
    virtual void line(const std::string& text) = 0;
};

struct NullJournal : JournalSink {
    void line(const std::string&) override {}
};

struct SchedulerOptions {
    std::string token_file;         // overrides queue.node.token_file when non-empty
    int64_t is_hold_secs = 600;     // WAIT_FOR_ISLOCK_TIMEOUT_SECS (mempool.hpp:223)
    int64_t reorg_check_every = 10; // ticks between getblockhash re-checks of a mined item
    int64_t body_window = kBodyWindow;
    int64_t unknown_polls_max = 3;  // submitted_unknown mempool polls before a resubmit
};

using PersistFn = std::function<bool(const Queue&, std::string& why)>;

struct TickReport {
    int64_t transitions = 0;
    int64_t submits = 0;     // POSTs to /api/tx-inject/submit
    int64_t arm_posts = 0;   // POSTs to /api/config/apply
    int64_t alerts = 0;
    bool persist_failed = false;
    std::string persist_error;
};

class Scheduler {
public:
    Scheduler(Queue& q, NodeApi& api, const Clock& clock, JournalSink& sink, SchedulerOptions opt = {});
    ~Scheduler();

    void set_persist(PersistFn fn) { persist_ = std::move(fn); }

    TickReport tick();

    Queue& queue() { return q_; }
    std::string token_path() const;

private:
    enum class ArmTry { Armed, NotArmed, Diverted };

    // phase 0
    void detect_disarm(const InjectStatus& st);
    // phase 1
    void observe_tracked();
    void observe_unknown(Item& it);
    void observe_admitted(Item& it);
    void observe_mined(Item& it);
    void mark_mined(Item& it, int64_t height, const std::string& hash, int64_t tip);
    // phase 2
    void act_waiting_or_ready(Item& it);
    void act_blocked_not_armed(Item& it);
    void act_blocked_token(Item& it);
    void act_blocked_node(Item& it);
    void act_dropped(Item& it);
    void act_expired(Item& it);
    void attempt_submit(Item& it);
    void submit(Item& it);
    void apply_outcome(Item& it, const Outcome& o, int64_t expiry, int64_t tip);
    void apply_retry(Item& it, RetryClass cls, const std::string& why);
    void block_not_armed(Item& it, const std::string& why, bool alert);
    void block_token(Item& it, const std::string& why);
    void block_node(Item& it, RetryClass cls, const std::string& why);
    ArmTry try_auto_arm(Item& it, std::string& why);
    // phase 3
    void maybe_auto_disarm();

    // helpers
    ChainSnapshot snapshot();
    ParentStatus parent_status(const std::string& txid) const;
    Verdict evaluate_item(const Item& it);
    void transition(Item& it, State s, const std::string& why);
    void set_why(Item& it, const std::string& why);
    void note(Item& it, const std::string& event, const std::string& detail);
    void queue_note(const std::string& event, const std::string& detail);
    void raise_alert(const std::string& kind, const std::string& detail);
    std::string belt(const std::string& s) const;
    bool load_token(std::string& why);
    void drop_token();
    void persist();

    Queue& q_;
    NodeApi& api_;
    const Clock& clock_;
    JournalSink& sink_;
    SchedulerOptions opt_;
    PersistFn persist_;
    ChainView view_;

    // per tick
    int64_t now_ = 0;
    std::string at_;
    TickReport report_;
    std::set<std::string> observed_changed_;
    c2w::secure::SecureString token_;
    bool token_loaded_ = false;
};

} // namespace c2w::companion::sched
