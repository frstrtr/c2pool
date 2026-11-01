// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Inject scheduler — the queue: items, their persisted state, the JSON codec of
// queue.json (schema c2wallet-inject-queue/1) and the enqueue step that turns a
// signed <name>.hex (+ <name>.manifest.json) into queue items.
//
// The queue file holds PUBLIC data only: raw signed txs, txids, provenance
// digests, trigger settings, node observations, attempts and a journal. It
// never holds the control token, a money nonce or any key material.
//
// Determinism: the codec writes a fixed key order with a 2-space indent and a
// trailing newline, so load -> save of a file this code wrote is byte-identical.
// Every field the state machine needs to resume after a restart is persisted
// (retry timers, counters, the last seen arm state), so a fresh Scheduler loaded
// from the file takes the same next transition as the one that wrote it.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace c2w::companion::sched {

inline constexpr const char* kQueueSchema = "c2wallet-inject-queue/1";
inline constexpr const char* kManifestSchema = "c2wallet-inject-manifest/1";

inline constexpr size_t kMaxAttempts = 50;
inline constexpr size_t kMaxJournal = 200;
inline constexpr size_t kMaxAlerts = 50;

enum class State : uint8_t {
    Waiting,          // triggers not met
    Ready,            // triggers met; submits when the retry gate allows
    Submitting,       // a POST is in flight (only ever seen on disk after a crash)
    BlockedNotArmed,  // node answered inject-disabled / enabled=false
    BlockedToken,     // 403 or unreadable token file
    BlockedNode,      // node posture problem (not wired, no UTXO view, unknown cause)
    SubmittedUnknown, // 504: the node may still accept it
    Admitted,         // node accepted it; not yet observed in the mempool
    IsHold,           // in the mempool, inside the InstantSend hold window
    Riding,           // in the mempool, hold elapsed (inferred)
    Mined,            // found in a block (or the node answered already-confirmed)
    Confirmed,        // confirmations >= the display threshold (terminal)
    Dropped,          // left the mempool without a block
    Expired,          // tip passed expiry_height, not mined
    Refused,          // terminal refusal (the tx itself is wrong)
    Paused,           // frozen by the operator
};

const char* state_name(State s);
std::optional<State> state_from_name(const std::string& s);

// How an item waits before the next submit attempt (§6 retry column).
enum class RetryClass : uint8_t {
    None,
    Backoff,      // transport error: 30, 60, 120, 300, 300... s
    Slow,         // blocked_node posture: every 300 s
    RateWindow,   // local rate budget: window_sec + 15 s
    PoolFull,     // inject pool full: 300 s
    Unpriceable,  // 600 s, at most 3 retries
    Retry5m,      // reserved oracle-* causes: 300 s
    TokenChange,  // until the token file changes (or operator Retry)
    Arm,          // until the node is armed (or consented auto-arm)
    Operator,     // operator Retry only
    MempoolPoll,  // 504: poll the mempool 3 times
};

const char* retry_class_name(RetryClass c);
std::optional<RetryClass> retry_class_from_name(const std::string& s);

struct TxSource {
    std::string hex_path;
    std::string hex_sha256;
    int64_t line = 0; // 1-based line in the hex file
    std::string manifest_path;
    std::string manifest_sha256;
    std::string mode;     // manifest "mode" ("consolidate" | "collateral"), empty without one
    std::string fee_mode; // manifest "fee_mode" ("inject-zero-fee" | "relay")
    int64_t fee = 0;
    int64_t value_out = 0;
    int64_t vin = 0;
    int64_t vout = 0;
};

struct TxRecord {
    std::string txid; // display order
    std::string raw_tx;
    int64_t size = 0;
    TxSource source;
};

struct MaturityTrigger {
    bool enabled = false;
    int64_t safe_from_height = 0; // first block height in which every input is spendable
    int64_t youngest_input_height = 0;
    std::string source;           // where safe_from_height came from
    int64_t inputs_with_unknown_height = 0;
    int64_t slack_blocks = 0;     // operator slack on top of the consensus rule (only delays)
    std::optional<std::string> override_consent; // "inputs are known mature" text when disabled
};

struct ParentReq {
    std::string txid;
    int64_t min_confirmations = 1;
};

struct Triggers {
    MaturityTrigger maturity;
    std::optional<int64_t> not_before_height;
    std::optional<std::string> not_before_time; // UTC ISO-8601 'Z'
    std::vector<ParentReq> after_parent;
};

struct SubmitOptions {
    int64_t expiry_blocks = 576;
    int64_t max_fee = 0;
    int64_t flags = 0;
    int64_t auto_resubmit_max = 3;
    std::optional<bool> allow_auto_arm; // nullopt = inherit the queue policy
    bool auto_renew = false;            // expired -> ready with a fresh expiry
};

// What the node told us about this item's tx.
struct NodeRecord {
    std::optional<std::string> admitted_at;
    std::optional<int64_t> time_added;     // node's MempoolEntry::time_added (IS-hold clock)
    std::optional<int64_t> expiry_height;
    std::optional<int64_t> mined_height;
    std::optional<std::string> mined_hash;
    int64_t confirmations = 0;
    std::optional<std::string> last_seen_in_mempool;
    int64_t scan_from_height = 0;          // lowest height the tx can be found in
    bool mined_height_unknown = false;     // already-confirmed, block outside the body window
};

struct RetryState {
    RetryClass cls = RetryClass::None;
    std::optional<int64_t> not_before;     // unix seconds
    int64_t backoff_count = 0;             // consecutive transport failures
    int64_t unknown_polls = 0;             // submitted_unknown mempool polls
    int64_t resubmits = 0;                 // drop/restart resubmits used
    int64_t unpriceable = 0;               // inject-unpriceable refusals seen
    std::optional<std::string> token_fingerprint; // token file identity when blocked_token
};

struct Attempt {
    std::string at;
    int64_t http = 0; // 0 = transport error
    std::string cause;
    std::string txid_echo;
    std::optional<int64_t> expiry_height;
    std::optional<bool> armed;
    int64_t duration_ms = 0;
};

struct JournalEntry {
    std::string at;
    std::string event;
    std::string detail;
};

struct Item {
    std::string id;
    std::string label;
    std::string added_at;
    int64_t rev = 0; // bumped by operator edits
    TxRecord tx;
    Triggers triggers;
    SubmitOptions submit;
    bool paused = false;
    State state = State::Waiting;
    std::string state_since;
    std::string why;
    NodeRecord node;
    RetryState retry;
    std::vector<Attempt> attempts;
    std::vector<JournalEntry> journal;
};

// A parent txid that is not itself a queue item (§5.4).
struct Tracked {
    std::string txid;
    int64_t first_requested_height = 0;
    std::optional<int64_t> mined_height;
    std::optional<std::string> mined_hash;
    int64_t scan_from_height = 0;
    bool window_scanned = false; // the body window was searched once
};

struct NodeConfig {
    std::string url = "http://127.0.0.1:8080";
    std::string token_file;
};

struct Defaults {
    int64_t expiry_blocks = 576;
    int64_t max_fee = 0;
    int64_t flags = 0;
    int64_t auto_resubmit_max = 3;
    int64_t after_parent_min_confirmations = 1;
    int64_t poll_sec = 15;
    int64_t display_confirmations = 6; // mined -> confirmed
};

// The recorded auto-arm consent (§7.2). Logic lives in ArmPolicy.hpp.
struct ArmPolicyRecord {
    bool auto_arm = false;
    bool auto_disarm_when_idle = false;
    std::optional<std::string> consented_at;
    std::optional<std::string> consent_text;
    std::optional<std::string> suspended_reason;  // set after a money_gate refusal
    std::optional<int64_t> last_arm_attempt_at;   // unix seconds
    std::optional<std::string> armed_by_scheduler_at;
};

struct Alert {
    std::string at;
    std::string kind;
    std::string detail;
};

struct RunnerState {
    std::optional<bool> last_enabled; // last /api/tx-inject-status "enabled" seen
    int64_t tick_count = 0;
    std::optional<std::string> last_tick_at;
};

struct Queue {
    std::string schema = kQueueSchema;
    std::string coin = "dash";
    std::string network = "mainnet";
    NodeConfig node;
    Defaults defaults;
    ArmPolicyRecord arm_policy;
    std::vector<Item> items;
    std::vector<Tracked> tracked;
    std::vector<Alert> alerts;
    RunnerState runner;
};

// ── codec ────────────────────────────────────────────────────────────────────

// Deterministic JSON: fixed key order, 2-space indent, trailing newline.
std::string queue_to_json(const Queue& q);

// Parse + validate. Refuses another schema, a malformed field, an unknown state
// name, a duplicate item id, and an arm policy that claims auto-arm (queue-wide
// or per item) without a recorded consented_at.
bool queue_from_json(const std::string& text, Queue& out, std::string& why);

// Atomic write (temp file in the same directory + fsync + rename).
bool save_queue_file(const std::string& path, const Queue& q, std::string& why);
bool load_queue_file(const std::string& path, Queue& out, std::string& why);

// flock(path + ".lock"). The runner takes it non-blocking (a second runner
// exits "lock held"); edits take it blocking for a short read-modify-write.
class QueueLock {
public:
    QueueLock() = default;
    ~QueueLock();
    QueueLock(const QueueLock&) = delete;
    QueueLock& operator=(const QueueLock&) = delete;
    bool acquire(const std::string& queue_path, bool blocking, std::string& why);
    void release();
    bool held() const { return fd_ >= 0; }

private:
    int fd_ = -1;
};

// ── item helpers ─────────────────────────────────────────────────────────────

Item* find_item(Queue& q, const std::string& id);
const Item* find_item(const Queue& q, const std::string& id);
Item* find_item_by_txid(Queue& q, const std::string& txid);
const Item* find_item_by_txid(const Queue& q, const std::string& txid);
Tracked* find_tracked(Queue& q, const std::string& txid);

// Terminal: confirmed, refused, dropped with the resubmit budget spent, expired
// without auto-renew.
bool is_terminal(const Item& it);
// Will this item's tx never be mined without an operator action?
bool is_dead_end(const Item& it);

void journal(Item& it, const std::string& at, const std::string& event, const std::string& detail);
void add_attempt(Item& it, Attempt a);
void add_alert(Queue& q, const std::string& at, const std::string& kind, const std::string& detail);

// ── operator edits (each bumps rev and journals) ─────────────────────────────

bool pause_item(Queue& q, const std::string& id, int64_t now, std::string& why);
bool resume_item(Queue& q, const std::string& id, int64_t now, std::string& why);
// Terminal -> waiting with the attempt counters reset.
bool requeue_item(Queue& q, const std::string& id, int64_t now, std::string& why);
// blocked_* -> ready now (operator "Retry").
bool retry_item(Queue& q, const std::string& id, int64_t now, std::string& why);
// Only terminal or paused items may be removed.
bool remove_item(Queue& q, const std::string& id, std::string& why);

// ── enqueue ──────────────────────────────────────────────────────────────────

struct EnqueueRequest {
    std::string hex_text;                      // content of <name>.hex
    std::string hex_path;                      // provenance only
    std::optional<std::string> manifest_text;  // content of <name>.manifest.json
    std::string manifest_path;
    std::optional<int64_t> line;               // 1-based; nullopt = every line
    std::string label;
    std::optional<int64_t> not_before_height;
    std::optional<std::string> not_before_time;
    std::vector<ParentReq> after_parent;       // explicit parents (merged with discovered ones)
    bool discover_parents = true;
    // Required when maturity is unknown and no not_before_height is given.
    std::optional<std::string> inputs_known_mature_consent;
    int64_t maturity_slack_blocks = 0;
    std::optional<int64_t> expiry_blocks;
    std::optional<int64_t> max_fee;
    std::optional<int64_t> flags;
    std::optional<int64_t> auto_resubmit_max;
    std::optional<bool> allow_auto_arm;
    bool auto_renew = false;
    bool pause = false;
};

struct EnqueueResult {
    bool ok = false;
    std::string why;                 // refusal reason when !ok
    std::vector<std::string> ids;    // items added, in hex-line order
    std::vector<std::string> notes;  // e.g. "after_parent pre-filled from input 539aa4b7...:0"
};

// Verifies the hex <-> manifest binding (sha256 of the hex file, each line's
// txid), cross-checks the manifest's maturity against its inputs, refuses an
// unsigned blob or one over the node caps, discovers parents among queued
// items, and appends one item per selected line. All-or-nothing: on refusal
// the queue is unchanged.
EnqueueResult enqueue(Queue& q, const EnqueueRequest& req, int64_t now);

// The local pre-flight shared by enqueue and the submit step: the hex decodes,
// accept_as_signed() holds, size <= 100000, vin <= 1000, vout <= 1000, and the
// recomputed txid equals `expected_txid` (when non-empty).
bool preflight_raw_tx(const std::string& raw_tx_hex, const std::string& expected_txid,
                      std::string& why);

// Short txid for display: first 8 hex chars + "...".
std::string short_txid(const std::string& txid);

} // namespace c2w::companion::sched
