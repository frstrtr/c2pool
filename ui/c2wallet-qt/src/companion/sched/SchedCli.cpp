// SPDX-License-Identifier: AGPL-3.0-or-later
#include "SchedCli.hpp"

#include "ArmPolicy.hpp"
#include "ChainView.hpp"
#include "Config.hpp"
#include "InjectQueue.hpp"
#include "Runner.hpp"
#include "Scheduler.hpp"
#include "TokenFile.hpp"
#include "Triggers.hpp"

#include "../scan/ScanCli.hpp"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <map>
#include <optional>
#include <ostream>
#include <set>
#include <sstream>

#if !defined(_WIN32)
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace c2w::companion::sched::cli {

namespace {

constexpr size_t kMaxHexFileBytes = 16u * 1024u * 1024u;
constexpr size_t kMaxManifestBytes = 16u * 1024u * 1024u;
constexpr int64_t kIsHoldSecs = 600; // WAIT_FOR_ISLOCK_TIMEOUT_SECS (mempool.hpp:223)

// ── small parsing helpers ────────────────────────────────────────────────────

bool parse_i64(const std::string& s, int64_t lo, int64_t hi, int64_t& out)
{
    if (s.empty() || s.size() > 18) return false;
    int64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
    }
    if (v < lo || v > hi) return false;
    out = v;
    return true;
}

bool parse_yes_no(const std::string& s, bool& out)
{
    if (s == "yes" || s == "true" || s == "on") { out = true; return true; }
    if (s == "no" || s == "false" || s == "off") { out = false; return true; }
    return false;
}

bool is_hex64(const std::string& s)
{
    if (s.size() != 64) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

std::string lower(std::string s)
{
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

bool file_exists(const std::string& path)
{
#if defined(_WIN32)
    std::ifstream f(path);
    return static_cast<bool>(f);
#else
    struct stat st {};
    return ::stat(path.c_str(), &st) == 0;
#endif
}

bool read_file(const std::string& path, size_t max_bytes, std::string& out, std::string& why)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        why = "cannot open " + path;
        return false;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    if (out.size() > max_bytes) {
        why = path + " is larger than " + std::to_string(max_bytes) + " bytes";
        return false;
    }
    return true;
}

// Subcommand options: --name VALUE / --name=VALUE for valued ones, bare
// --name for flags, everything else positional.
struct Args {
    std::map<std::string, std::vector<std::string>> values;
    std::set<std::string> flags;
    std::vector<std::string> pos;

    bool has(const std::string& k) const { return values.count(k) != 0 || flags.count(k) != 0; }
    const std::string* one(const std::string& k) const
    {
        auto it = values.find(k);
        return it == values.end() || it->second.empty() ? nullptr : &it->second.back();
    }
};

bool parse_args(const std::vector<std::string>& v, size_t from, const std::set<std::string>& flag_names,
                const std::set<std::string>& valued, const std::set<std::string>& multi, Args& a, std::string& why)
{
    for (size_t i = from; i < v.size(); ++i) {
        const std::string& t = v[i];
        if (t.size() > 2 && t.rfind("--", 0) == 0) {
            const size_t eq = t.find('=');
            const std::string name = eq == std::string::npos ? t : t.substr(0, eq);
            if (flag_names.count(name)) {
                if (eq != std::string::npos) {
                    why = "usage: " + name + " takes no value";
                    return false;
                }
                a.flags.insert(name);
                continue;
            }
            if (valued.count(name)) {
                std::string value;
                if (eq != std::string::npos) value = t.substr(eq + 1);
                else if (i + 1 < v.size()) value = v[++i];
                else {
                    why = "usage: " + name + " needs a value";
                    return false;
                }
                if (a.values.count(name) && !multi.count(name)) {
                    why = "usage: " + name + " given twice";
                    return false;
                }
                a.values[name].push_back(value);
                continue;
            }
            why = "usage: unknown option " + name;
            return false;
        }
        a.pos.push_back(t);
    }
    return true;
}

// ── shared context ───────────────────────────────────────────────────────────

struct Ctx {
    Env& env;
    CliOverrides g;
    std::string path;

    std::ostream& out() { return *env.out; }
    std::ostream& err() { return *env.err; }
    int64_t now() const { return env.clock->now_unix(); }
};

int usage_error(Ctx& c, const std::string& why)
{
    c.err() << why << "\n(see c2wallet-qt-schedd help)\n";
    return kExitUsage;
}

int refuse(Ctx& c, const std::string& why)
{
    c.err() << "refused: " << why << "\n";
    return kExitAttention;
}

bool load_existing(Ctx& c, Queue& q, int& rc)
{
    std::string why;
    if (!file_exists(c.path)) {
        c.err() << "no queue at " << c.path << " (create it with `init`, or pass --queue PATH)\n";
        rc = kExitQueue;
        return false;
    }
    if (!load_queue_file(c.path, q, why)) {
        c.err() << "queue " << c.path << " is unreadable or invalid: " << why << "\n";
        rc = kExitQueue;
        return false;
    }
    return true;
}

bool check_owner(Ctx& c, int& rc)
{
    std::string why;
    if (owned_by_other_user(c.path, why)) {
        c.err() << "refused: " << why << "\n";
        rc = kExitUsage;
        return false;
    }
    return true;
}

// Item by id, full txid, or a unique txid prefix of at least 8 hex chars.
const Item* resolve(const Queue& q, const std::string& key, std::string& why)
{
    if (const Item* it = find_item(q, key)) return it;
    const std::string k = lower(key);
    if (const Item* it = find_item_by_txid(q, k)) return it;
    if (k.size() >= 8) {
        const Item* hit = nullptr;
        for (const Item& it : q.items) {
            if (it.tx.txid.rfind(k, 0) != 0) continue;
            if (hit) {
                why = "txid prefix " + key + " is ambiguous";
                return nullptr;
            }
            hit = &it;
        }
        if (hit) return hit;
    }
    why = "no item " + key + " in the queue";
    return nullptr;
}

// ── rendering ────────────────────────────────────────────────────────────────

std::string yes_no(bool b) { return b ? "yes" : "no"; }

std::string policy_text(const ArmPolicyRecord& p)
{
    std::string s = "auto_arm=" + yes_no(p.auto_arm) + ", auto_disarm_when_idle=" + yes_no(p.auto_disarm_when_idle);
    if (p.consented_at)
        s += ", consented_at " + *p.consented_at + " (\"" + p.consent_text.value_or("") + "\")";
    else
        s += ", no consent recorded";
    if (p.suspended_reason) s += ", AUTO-ARM SUSPENDED: " + *p.suspended_reason;
    if (p.armed_by_scheduler_at) s += ", armed by the scheduler at " + *p.armed_by_scheduler_at;
    return s;
}

std::string parent_rule(const Queue& q, const Item& it, const ParentReq& p)
{
    const Item* qi = find_item_by_txid(q, p.txid);
    std::string s = "after parent " + p.txid.substr(0, 16) + " (" + (qi ? "queue item " + qi->id : "foreign txid") + "): ";
    if (it.triggers.allow_unconfirmed_parent)
        return s + "in the node mempool or mined (allow_unconfirmed_parent)";
    return s + "mined with >= " + std::to_string(p.min_confirmations) +
           (p.min_confirmations == 1 ? " confirmation" : " confirmations") +
           " and final (ChainLocked; >= " + std::to_string(std::max<int64_t>(p.min_confirmations, kFallbackParentConfirmations)) +
           " confirmations when the node exposes no ChainLock)";
}

std::vector<std::string> trigger_lines(const Queue& q, const Item& it)
{
    std::vector<std::string> out;
    const MaturityTrigger& m = it.triggers.maturity;
    if (m.enabled)
        out.push_back("maturity: submit at tip >= " + std::to_string(maturity_fire_tip(m)) +
                      " (inputs spendable in block >= " + std::to_string(m.safe_from_height) +
                      (m.youngest_input_height > 0 ? ", youngest input h0=" + std::to_string(m.youngest_input_height)
                                                   : std::string()) +
                      (m.slack_blocks > 0 ? ", slack " + std::to_string(m.slack_blocks) : std::string()) + "; " +
                      m.source + ")");
    else
        out.push_back("maturity: off (" + m.source +
                      (m.override_consent ? "; operator override: \"" + *m.override_consent + "\"" : std::string()) + ")");
    if (it.triggers.not_before_height)
        out.push_back("not_before_height: tip >= " + std::to_string(*it.triggers.not_before_height));
    if (it.triggers.not_before_time) out.push_back("not_before_time: " + *it.triggers.not_before_time);
    for (const ParentReq& p : it.triggers.after_parent) out.push_back(parent_rule(q, it, p));
    if (it.triggers.allow_unconfirmed_parent && it.triggers.after_parent.empty())
        out.push_back("allow_unconfirmed_parent: set (no parents)");
    return out;
}

// What changed since the runner wrote `why`: the IS-hold clock and retry gates
// are re-read against the current time.
std::string live_note(const Item& it, int64_t now)
{
    if ((it.state == State::IsHold || it.state == State::Admitted) && it.node.time_added) {
        const int64_t until = *it.node.time_added + kIsHoldSecs;
        if (now < until)
            return "IS-hold ends ~" + format_utc(until) + " (in " + format_eta_seconds(until - now) +
                   "; upper bound: the node may select it earlier when its InstantSend feed is dark)";
        return "IS-hold elapsed at " + format_utc(until) + " (the runner marks it riding at its next tick)";
    }
    if (it.retry.not_before && (it.state == State::Ready || it.state == State::BlockedNode)) {
        const int64_t nb = *it.retry.not_before;
        if (now < nb) return "next attempt at " + format_utc(nb) + " (in " + format_eta_seconds(nb - now) + ")";
        return "next attempt at the runner's next tick";
    }
    return "";
}

std::vector<const Alert*> pending_alerts(const Queue& q)
{
    std::vector<const Alert*> out;
    for (const Alert& a : q.alerts)
        if (!q.alerts_acked_at || a.at > *q.alerts_acked_at) out.push_back(&a);
    return out;
}

bool is_blocked(State s)
{
    return s == State::BlockedNotArmed || s == State::BlockedToken || s == State::BlockedNode;
}

bool is_live(const Item& it) { return !it.paused && !is_terminal(it); }

std::string runner_text(const Queue& q, const std::string& path, int64_t now)
{
    std::string s = runner_lock_held(path) ? "running (lock held)" : "NOT RUNNING";
    if (q.runner.last_tick_at) {
        int64_t t = 0;
        std::string perr;
        s += ", last tick " + *q.runner.last_tick_at;
        if (parse_utc(*q.runner.last_tick_at, t, perr)) {
            const int64_t age = now - t;
            s += " (" + (age >= 0 && age < 120 ? std::to_string(age) + " s" : format_eta_seconds(age)) + " ago)";
        }
        s += ", tick " + std::to_string(q.runner.tick_count);
    } else {
        s += ", never ticked";
    }
    return s;
}

void print_item_line(Ctx& c, const Item& it)
{
    std::string st = state_name(it.state);
    c.out() << it.id << "  " << st << std::string(st.size() < 18 ? 18 - st.size() : 1, ' ') << it.tx.txid.substr(0, 16)
            << "  " << it.label << "\n";
    c.out() << "    why:  " << it.why << "\n";
    const std::string live = live_note(it, c.now());
    if (!live.empty()) c.out() << "    now:  " << live << "\n";
}

// ── commands ─────────────────────────────────────────────────────────────────

int cmd_init(Ctx& c, const std::vector<std::string>& v)
{
    Args a;
    std::string why;
    if (!parse_args(v, 1, {}, {"--network"}, {}, a, why)) return usage_error(c, why);
    if (!a.pos.empty()) return usage_error(c, "usage: init takes no positional argument");
    const std::string* net = a.one("--network");
    if (net && *net != "mainnet" && *net != "testnet") return usage_error(c, "usage: --network must be mainnet or testnet");
    int rc = 0;
    if (!check_owner(c, rc)) return rc;
    const bool existed = file_exists(c.path);
    Queue result;
    const bool ok = edit_queue_file(
        c.path,
        [&](Queue& q, std::string& w) {
            if (net && *net != q.network) {
                if (existed && !q.items.empty()) {
                    w = "the queue holds items for " + q.network + "; its network cannot change";
                    return false;
                }
                q.network = *net;
            }
            if (c.g.node_url) q.node.url = *c.g.node_url;
            if (c.g.token_file) q.node.token_file = *c.g.token_file;
            if (c.g.poll_sec) q.defaults.poll_sec = *c.g.poll_sec;
            result = q;
            return true;
        },
        why);
    if (!ok) return refuse(c, why);
    c.out() << "queue " << c.path << (existed ? " (updated)" : " (created)") << "\n"
            << "  network     " << result.network << "\n"
            << "  node.url    " << result.node.url << "\n"
            << "  token_file  " << (result.node.token_file.empty() ? "(not set: pass --token-file)" : result.node.token_file)
            << "\n"
            << "  poll_sec    " << result.defaults.poll_sec << "\n"
            << "  arm policy  " << policy_text(result.arm_policy) << "\n";
    if (!result.node.token_file.empty()) {
        c2w::secure::SecureString tok;
        std::string terr;
        if (TokenFile::read(result.node.token_file, tok, terr))
            c.out() << "  token file  readable by this user under the node's rules (content not shown)\n";
        else
            c.out() << "  token file  NOT usable by this user: " << terr << "\n";
        tok.clear();
    }
    return kExitOk;
}

int cmd_add(Ctx& c, const std::vector<std::string>& v_in)
{
    Args a;
    std::string why;
    // Scan & Plan: add ... --preflight [preflight options] checks the pair
    // right before it is queued (scan/ScanCli).
    std::vector<std::string> v;
    scan::cli::AddPreflight pf;
    if (!scan::cli::split_add_preflight(v_in, v, pf, why)) return usage_error(c, why);
    if (!parse_args(v, 1, {"--no-manifest", "--no-discover-parents", "--allow-unconfirmed-parent", "--auto-renew", "--pause"},
                    {"--hex", "--manifest", "--line", "--label", "--after-parent", "--not-before-height",
                     "--not-before-time", "--h0", "--maturity-slack", "--inputs-known-mature", "--expiry-blocks",
                     "--max-fee", "--auto-resubmit-max", "--allow-auto-arm"},
                    {"--after-parent"}, a, why))
        return usage_error(c, why);
    if (!a.pos.empty()) return usage_error(c, "usage: add takes no positional argument (got '" + a.pos[0] + "')");
    const std::string* hex_path = a.one("--hex");
    if (!hex_path) return usage_error(c, "usage: add needs --hex FILE");
    if (a.has("--manifest") && a.has("--no-manifest")) return usage_error(c, "usage: --manifest and --no-manifest conflict");

    EnqueueRequest req;
    req.hex_path = *hex_path;
    if (!read_file(*hex_path, kMaxHexFileBytes, req.hex_text, why)) return refuse(c, why);
    std::string manifest_note;
    if (const std::string* mp = a.one("--manifest")) {
        std::string text;
        if (!read_file(*mp, kMaxManifestBytes, text, why)) return refuse(c, why);
        req.manifest_text = text;
        req.manifest_path = *mp;
    } else if (!a.has("--no-manifest")) {
        std::string base = *hex_path;
        if (base.size() > 4 && base.compare(base.size() - 4, 4, ".hex") == 0) base.resize(base.size() - 4);
        const std::string mp = base + ".manifest.json";
        if (file_exists(mp)) {
            std::string text;
            if (!read_file(mp, kMaxManifestBytes, text, why)) return refuse(c, why);
            req.manifest_text = text;
            req.manifest_path = mp;
            manifest_note = "manifest: auto-located " + mp;
        } else {
            manifest_note = "manifest: none beside the hex (" + mp + "); bare hex";
        }
    } else {
        // --no-manifest: the manifest beside the hex is not used, but a
        // stage-2 (projected heights) marker in it still applies.
        std::string base = *hex_path;
        if (base.size() > 4 && base.compare(base.size() - 4, 4, ".hex") == 0) base.resize(base.size() - 4);
        const std::string mp = base + ".manifest.json";
        if (file_exists(mp)) {
            std::string text;
            if (!read_file(mp, kMaxManifestBytes, text, why)) return refuse(c, why);
            req.fence_manifest_text = text;
            manifest_note = "manifest: " + mp + " not used (--no-manifest); a projected-heights marker in it still applies";
        }
    }

    std::string forced_reason, preflight_summary;
    if (pf.requested) {
        const int prc = scan::cli::preflight_for_add(pf, req.hex_text, req.manifest_text, c.env, c.g, c.path,
                                                     forced_reason, preflight_summary);
        if (prc != kExitOk) {
            c.err() << "refused: the preflight did not pass; nothing was queued\n";
            return prc;
        }
    }

    int64_t n = 0;
    if (const std::string* s = a.one("--line")) {
        if (!parse_i64(*s, 1, 1000000, n)) return usage_error(c, "usage: --line must be a positive integer");
        req.line = n;
    }
    if (const std::string* s = a.one("--label")) req.label = *s;
    struct PendingParent {
        std::string txid;
        std::optional<int64_t> n;
    };
    std::vector<PendingParent> parents;
    if (auto it = a.values.find("--after-parent"); it != a.values.end()) {
        for (const std::string& spec : it->second) {
            PendingParent p;
            const size_t colon = spec.find(':');
            p.txid = lower(spec.substr(0, colon));
            if (!is_hex64(p.txid)) return usage_error(c, "usage: --after-parent TXID[:N] needs a 64-hex txid (got '" + spec + "')");
            if (colon != std::string::npos) {
                if (!parse_i64(spec.substr(colon + 1), 1, 1000000, n))
                    return usage_error(c, "usage: --after-parent TXID:N needs N >= 1 (got '" + spec + "')");
                p.n = n;
            }
            parents.push_back(p);
        }
    }
    if (const std::string* s = a.one("--not-before-height")) {
        if (!parse_i64(*s, 1, 100000000, n)) return usage_error(c, "usage: --not-before-height must be a positive height");
        req.not_before_height = n;
    }
    if (const std::string* s = a.one("--not-before-time")) {
        int64_t t = 0;
        if (!parse_utc(*s, t, why)) return usage_error(c, "usage: --not-before-time: " + why);
        req.not_before_time = *s;
    }
    if (const std::string* s = a.one("--h0")) {
        if (!parse_i64(*s, 1, 100000000, n)) return usage_error(c, "usage: --h0 must be a positive block height");
        req.explicit_h0 = n;
    }
    if (const std::string* s = a.one("--maturity-slack")) {
        if (!parse_i64(*s, 0, 100000, n)) return usage_error(c, "usage: --maturity-slack must be 0..100000 blocks");
        req.maturity_slack_blocks = n;
    }
    if (const std::string* s = a.one("--inputs-known-mature")) {
        if (s->empty()) return usage_error(c, "usage: --inputs-known-mature needs a consent text");
        req.inputs_known_mature_consent = *s;
    }
    if (const std::string* s = a.one("--expiry-blocks")) {
        if (!parse_i64(*s, 1, 100000, n)) return usage_error(c, "usage: --expiry-blocks must be 1..100000");
        req.expiry_blocks = n;
    }
    if (const std::string* s = a.one("--max-fee")) {
        if (!parse_i64(*s, 0, 2100000000000000LL, n)) return usage_error(c, "usage: --max-fee must be >= 0 duffs");
        req.max_fee = n;
    }
    if (const std::string* s = a.one("--auto-resubmit-max")) {
        if (!parse_i64(*s, 0, 1000, n)) return usage_error(c, "usage: --auto-resubmit-max must be 0..1000");
        req.auto_resubmit_max = n;
    }
    if (const std::string* s = a.one("--allow-auto-arm")) {
        bool b = false;
        if (!parse_yes_no(*s, b)) return usage_error(c, "usage: --allow-auto-arm yes|no");
        req.allow_auto_arm = b;
    }
    req.discover_parents = !a.has("--no-discover-parents");
    req.allow_unconfirmed_parent = a.has("--allow-unconfirmed-parent");
    req.auto_renew = a.has("--auto-renew");
    req.pause = a.has("--pause");

    int rc = 0;
    if (!check_owner(c, rc)) return rc;
    const bool existed = file_exists(c.path);
    EnqueueResult er;
    Queue after;
    const bool ok = edit_queue_file(
        c.path,
        [&](Queue& q, std::string& w) {
            if (!existed) {
                if (c.g.node_url) q.node.url = *c.g.node_url;
                if (c.g.token_file) q.node.token_file = *c.g.token_file;
            }
            req.after_parent.clear();
            for (const PendingParent& p : parents)
                req.after_parent.push_back({p.txid, p.n.value_or(q.defaults.after_parent_min_confirmations)});
            er = enqueue(q, req, c.now());
            if (!er.ok) {
                w = er.why;
                return false;
            }
            if (pf.requested)
                for (const std::string& id : er.ids)
                    if (Item* it = find_item(q, id)) {
                        journal(*it, format_utc(c.now()), "preflight", preflight_summary);
                        if (!forced_reason.empty())
                            journal(*it, format_utc(c.now()), "preflight_forced", "operator reason: " + forced_reason);
                    }
            after = q;
            return true;
        },
        why);
    if (!ok) return refuse(c, why);
    if (!existed) c.out() << "created a new queue at " << c.path << "\n";
    if (!manifest_note.empty()) c.out() << manifest_note << "\n";
    for (const std::string& id : er.ids) {
        const Item* it = find_item(after, id);
        if (!it) continue;
        c.out() << "added " << id << ": txid " << it->tx.txid << ", " << it->tx.size << " B, vin " << it->tx.source.vin
                << " / vout " << it->tx.source.vout << (it->paused ? " (paused)" : "") << "\n";
        for (const std::string& l : trigger_lines(after, *it)) c.out() << "    " << l << "\n";
        c.out() << "    submit: expiry +" << it->submit.expiry_blocks << " blocks, max_fee " << it->submit.max_fee
                << " duffs, auto_resubmit_max " << it->submit.auto_resubmit_max << ", allow_auto_arm "
                << (it->submit.allow_auto_arm ? yes_no(*it->submit.allow_auto_arm)
                                              : "inherit (queue: " + yes_no(after.arm_policy.auto_arm) + ")")
                << "\n";
    }
    for (const std::string& note : er.notes) c.out() << "note: " << note << "\n";
    c.out() << "the runner picks it up at its next tick\n";
    return kExitOk;
}

int cmd_list(Ctx& c, const std::vector<std::string>& v)
{
    Args a;
    std::string why;
    if (!parse_args(v, 1, {}, {}, {}, a, why)) return usage_error(c, why);
    Queue q;
    int rc = 0;
    if (!load_existing(c, q, rc)) return rc;
    c.out() << "queue  " << c.path << " (" << q.items.size() << " items, node " << q.node.url << ")\n"
            << "runner " << runner_text(q, c.path, c.now()) << "\n"
            << "arm    " << policy_text(q.arm_policy) << "\n";
    const auto pend = pending_alerts(q);
    if (!pend.empty())
        c.out() << "alerts " << pend.size() << " pending (latest " << pend.back()->at << " " << pend.back()->kind << ": "
                << pend.back()->detail << "); acknowledge with ack-alerts\n";
    c.out() << "\n";
    for (const Item& it : q.items) print_item_line(c, it);
    if (q.items.empty()) c.out() << "(empty)\n";
    return kExitOk;
}

int cmd_show(Ctx& c, const std::vector<std::string>& v)
{
    Args a;
    std::string why;
    if (!parse_args(v, 1, {}, {"--journal", "--attempts"}, {}, a, why)) return usage_error(c, why);
    if (a.pos.size() != 1) return usage_error(c, "usage: show ID");
    int64_t nj = 20, na = 10;
    if (const std::string* s = a.one("--journal"); s && !parse_i64(*s, 0, 1000, nj))
        return usage_error(c, "usage: --journal N");
    if (const std::string* s = a.one("--attempts"); s && !parse_i64(*s, 0, 1000, na))
        return usage_error(c, "usage: --attempts N");
    Queue q;
    int rc = 0;
    if (!load_existing(c, q, rc)) return rc;
    const Item* itp = resolve(q, a.pos[0], why);
    if (!itp) return refuse(c, why);
    const Item& it = *itp;
    auto& o = c.out();
    o << "item      " << it.id << "  \"" << it.label << "\" (added " << it.added_at << ", rev " << it.rev << ")\n"
      << "state     " << state_name(it.state) << " since " << it.state_since << (it.paused ? " (paused)" : "") << "\n"
      << "why       " << it.why << "\n";
    const std::string live = live_note(it, c.now());
    if (!live.empty()) o << "now       " << live << "\n";
    const TxSource& s = it.tx.source;
    o << "tx        " << it.tx.txid << ", " << it.tx.size << " B, vin " << s.vin << " / vout " << s.vout << "\n"
      << "source    hex " << s.hex_path << " (sha256 " << s.hex_sha256 << ", line " << s.line << ")\n";
    if (!s.manifest_path.empty())
        o << "          manifest " << s.manifest_path << " (sha256 " << s.manifest_sha256 << "), mode " << s.mode
          << ", fee_mode " << s.fee_mode << ", fee " << s.fee << ", value_out " << s.value_out << "\n";
    o << "triggers\n";
    for (const std::string& l : trigger_lines(q, it)) o << "          " << l << "\n";
    o << "submit    expiry +" << it.submit.expiry_blocks << " blocks, max_fee " << it.submit.max_fee << ", flags "
      << it.submit.flags << ", auto_resubmit_max " << it.submit.auto_resubmit_max << ", auto_renew "
      << yes_no(it.submit.auto_renew) << ", allow_auto_arm "
      << (it.submit.allow_auto_arm ? yes_no(*it.submit.allow_auto_arm) : std::string("inherit")) << "\n";
    const NodeRecord& n = it.node;
    o << "node      admitted_at " << n.admitted_at.value_or("-") << ", time_added "
      << (n.time_added ? format_utc(*n.time_added) + " (IS-hold until " + format_utc(*n.time_added + kIsHoldSecs) + ")"
                       : std::string("-"))
      << ", expiry_height " << (n.expiry_height ? std::to_string(*n.expiry_height) : std::string("-")) << "\n"
      << "          mined_height " << (n.mined_height ? std::to_string(*n.mined_height) : std::string(n.mined_height_unknown ? "unknown" : "-"))
      << ", mined_hash " << n.mined_hash.value_or("-") << ", confirmations " << n.confirmations
      << ", last seen in mempool " << n.last_seen_in_mempool.value_or("-") << "\n";
    o << "retry     class " << retry_class_name(it.retry.cls) << ", not_before "
      << (it.retry.not_before ? format_utc(*it.retry.not_before) : std::string("-")) << ", resubmits "
      << it.retry.resubmits << "/" << it.submit.auto_resubmit_max << ", backoff " << it.retry.backoff_count << "\n";
    o << "attempts  (" << it.attempts.size() << ", newest last)\n";
    const size_t a0 = it.attempts.size() > static_cast<size_t>(na) ? it.attempts.size() - static_cast<size_t>(na) : 0;
    for (size_t i = a0; i < it.attempts.size(); ++i) {
        const Attempt& at = it.attempts[i];
        o << "          " << at.at << " http " << at.http << " " << at.cause << " expiry "
          << (at.expiry_height ? std::to_string(*at.expiry_height) : std::string("-")) << " "
          << at.duration_ms << " ms\n";
    }
    o << "journal   (" << it.journal.size() << ", newest last)\n";
    const size_t j0 = it.journal.size() > static_cast<size_t>(nj) ? it.journal.size() - static_cast<size_t>(nj) : 0;
    for (size_t i = j0; i < it.journal.size(); ++i)
        o << "          " << it.journal[i].at << " " << it.journal[i].event << ": " << it.journal[i].detail << "\n";
    return kExitOk;
}

int cmd_item_edit(Ctx& c, const std::vector<std::string>& v, const std::string& cmd)
{
    Args a;
    std::string why;
    if (!parse_args(v, 1, {}, {}, {}, a, why)) return usage_error(c, why);
    const bool fee = cmd == "set-max-fee";
    if (a.pos.size() != (fee ? 2u : 1u)) return usage_error(c, fee ? "usage: set-max-fee ID DUFFS" : "usage: " + cmd + " ID");
    int64_t duffs = 0;
    if (fee && !parse_i64(a.pos[1], 0, 2100000000000000LL, duffs)) return usage_error(c, "usage: DUFFS must be >= 0");
    int rc = 0;
    if (!check_owner(c, rc)) return rc;
    std::string id;
    const bool ok = edit_queue_file(
        c.path,
        [&](Queue& q, std::string& w) {
            const Item* it = resolve(q, a.pos[0], w);
            if (!it) return false;
            id = it->id;
            const int64_t now = c.now();
            if (cmd == "pause") return pause_item(q, id, now, w);
            if (cmd == "resume") return resume_item(q, id, now, w);
            if (cmd == "requeue") return requeue_item(q, id, now, w);
            if (cmd == "retry") return retry_item(q, id, now, w);
            if (cmd == "rm") return remove_item(q, id, w);
            return set_submit_max_fee(q, id, duffs, now, w);
        },
        why, /*create_if_missing=*/false);
    if (!ok) return refuse(c, why);
    if (cmd == "rm") c.out() << id << " removed\n";
    else if (fee) c.out() << id << " submit.max_fee = " << duffs << " duffs\n";
    else c.out() << id << " " << (cmd == "retry" ? "retry requested" : cmd + "d") << "; the runner applies it at its next tick\n";
    return kExitOk;
}

int cmd_arm_policy(Ctx& c, const std::vector<std::string>& v)
{
    Args a;
    std::string why;
    if (!parse_args(v, 1, {}, {"--auto-arm", "--auto-disarm-when-idle", "--consent"}, {}, a, why)) return usage_error(c, why);
    if (!a.pos.empty()) return usage_error(c, "usage: arm-policy [--auto-arm yes|no] [--auto-disarm-when-idle yes|no] --consent \"<text>\"");
    if (!a.has("--auto-arm") && !a.has("--auto-disarm-when-idle") && !a.has("--consent")) {
        Queue q;
        int rc = 0;
        if (!load_existing(c, q, rc)) return rc;
        c.out() << "arm policy  " << policy_text(q.arm_policy) << "\n\n" << arm::exposure_text() << "\n";
        return kExitOk;
    }
    std::optional<bool> want_arm, want_disarm;
    bool b = false;
    if (const std::string* s = a.one("--auto-arm")) {
        if (!parse_yes_no(*s, b)) return usage_error(c, "usage: --auto-arm yes|no");
        want_arm = b;
    }
    if (const std::string* s = a.one("--auto-disarm-when-idle")) {
        if (!parse_yes_no(*s, b)) return usage_error(c, "usage: --auto-disarm-when-idle yes|no");
        want_disarm = b;
    }
    const std::string consent = a.one("--consent") ? *a.one("--consent") : std::string();
    int rc = 0;
    if (!check_owner(c, rc)) return rc;
    ArmPolicyRecord recorded;
    bool needs_text = false;
    const bool ok = edit_queue_file(
        c.path,
        [&](Queue& q, std::string& w) {
            const bool arm_on = want_arm.value_or(q.arm_policy.auto_arm);
            const bool disarm_on = want_disarm.value_or(q.arm_policy.auto_disarm_when_idle);
            if ((arm_on || disarm_on) && consent.empty()) {
                needs_text = true;
                w = "--consent \"<text>\" is required to record auto-arm / auto-disarm consent";
                return false;
            }
            Queue staged = q;
            if (!arm::record_consent(staged.arm_policy, arm_on, disarm_on, consent, c.now(), w)) return false;
            if (!arm::validate(staged, w)) return false; // e.g. an item still sets allow_auto_arm:true
            q = std::move(staged);
            recorded = q.arm_policy;
            return true;
        },
        why);
    if (!ok) return needs_text ? usage_error(c, "usage: " + why) : refuse(c, why);
    c.out() << "arm policy recorded: " << policy_text(recorded) << "\n";
    if (recorded.auto_arm)
        c.out() << "\nThe runner may now arm the node (two-phase /api/config/apply, at most once per 10 minutes, never "
                   "after a money_gate refusal) when an item is ready and the node reports enabled=false.\n"
                << arm::exposure_text() << "\n";
    return kExitOk;
}

int cmd_ack_alerts(Ctx& c, const std::vector<std::string>& v)
{
    Args a;
    std::string why;
    if (!parse_args(v, 1, {}, {}, {}, a, why)) return usage_error(c, why);
    int rc = 0;
    if (!check_owner(c, rc)) return rc;
    size_t n = 0;
    const bool ok = edit_queue_file(
        c.path,
        [&](Queue& q, std::string&) {
            n = pending_alerts(q).size();
            q.alerts_acked_at = format_utc(c.now());
            return true;
        },
        why, /*create_if_missing=*/false);
    if (!ok) return refuse(c, why);
    c.out() << n << " pending alert(s) acknowledged\n";
    return kExitOk;
}

int cmd_status(Ctx& c, const std::vector<std::string>& v)
{
    Args a;
    std::string why;
    if (!parse_args(v, 1, {}, {}, {}, a, why)) return usage_error(c, why);
    Queue q;
    int rc = 0;
    if (!load_existing(c, q, rc)) return rc;
    std::vector<std::string> attention;
    const std::string url = c.g.node_url.value_or(q.node.url);
    const bool live = std::any_of(q.items.begin(), q.items.end(), is_live);
    auto& o = c.out();
    o << "queue   " << c.path << " (" << q.items.size() << " items)\n";

    bool enabled = false, reachable = false;
    std::unique_ptr<NodeApi> api;
    if (!validate_node_url(url, why) || !(api = c.env.make_api(url, why))) {
        o << "node    " << url << ": " << why << "\n";
        attention.push_back("node transport: " + why);
    } else {
        ChainView view(*api);
        const InjectStatus& st = view.inject_status();
        const TipInfo& tip = view.tip();
        if (!st.ok) {
            o << "node    " << url << ": tx-inject-status " << st.error << "\n";
            attention.push_back("node: " + st.error);
        } else {
            reachable = true;
            enabled = st.enabled;
            o << "node    " << url << ": tx-inject wired=" << (st.wired ? "true" : "false")
              << " enabled=" << (st.enabled ? "true" : "false") << "; ";
            if (tip.known) o << "tip " << tip.height << " (synced)";
            else o << tip.why;
            if (tip.chainlock.known) {
                o << "; ChainLock " << tip.chainlock.height;
                if (tip.chainlock.known_block && !*tip.chainlock.known_block) o << " (NOT on the node's header chain)";
                else if (tip.chainlock.blockhash.empty()) o << " (adopted without a block hash)";
            } else if (tip.chainlock.exposed) {
                o << "; ChainLock: " << tip.chainlock.why;
            } else {
                o << "; ChainLock not exposed (parents need >= 2 confirmations)";
            }
            const UptimeInfo& up = view.uptime();
            if (up.ok) o << "; up " << up.seconds << " s";
            else o << "; " << up.why << " (any disarm counts as deliberate)";
            o << "\n";
            o << "pool    " << st.pool_entries << "/" << st.pool_max_entries << " entries, " << st.pool_bytes << "/"
              << st.pool_max_total_bytes << " B";
            if (st.have_rate)
                o << "; local rate " << st.local_in_window << "/" << st.max_per_window << " per " << st.window_sec << " s";
            o << "\n";
        }
    }
    std::string arm;
    if (!reachable) arm = "unknown (node unreachable)";
    else if (!enabled) arm = "none (enabled=false)";
    else if (q.arm_policy.armed_by_scheduler_at)
        arm = "scheduler (armed " + *q.arm_policy.armed_by_scheduler_at + ", consent " +
              q.arm_policy.consented_at.value_or("?") + ")";
    else arm = "standing (unit flag --embedded-tx-inject or an operator arm)";
    o << "ARM     " << arm << "\n"
      << "policy  " << policy_text(q.arm_policy) << "\n";
    if (reachable && !enabled && live) {
        attention.push_back(q.arm_policy.auto_arm && q.arm_policy.consented_at && !q.arm_policy.suspended_reason
                                ? "node disarmed (auto-arm consent recorded: the runner re-arms when an item is ready)"
                                : "node disarmed and auto-arm has no usable consent");
    }
    if (q.arm_policy.suspended_reason) attention.push_back("auto-arm suspended: " + *q.arm_policy.suspended_reason);

    const bool running = runner_lock_held(c.path);
    o << "runner  " << runner_text(q, c.path, c.now()) << "\n";
    if (live && !running) attention.push_back("live items but no runner holds the queue");
    if (live && running && q.runner.last_tick_at) {
        int64_t t = 0;
        std::string perr;
        const int64_t stale = std::max<int64_t>(120, 5 * std::max<int64_t>(1, q.defaults.poll_sec));
        if (parse_utc(*q.runner.last_tick_at, t, perr) && c.now() - t > stale)
            attention.push_back("runner's last tick is older than " + std::to_string(stale) + " s");
    }

    std::map<std::string, int> counts;
    int blocked = 0;
    for (const Item& it : q.items) {
        ++counts[it.paused ? std::string("paused") : std::string(state_name(it.state))];
        if (!it.paused && is_blocked(it.state)) {
            ++blocked;
            attention.push_back(it.id + " " + state_name(it.state) + ": " + it.why);
        }
    }
    o << "items   ";
    bool first = true;
    for (const auto& kv : counts) {
        o << (first ? "" : ", ") << kv.first << " " << kv.second;
        first = false;
    }
    if (first) o << "(none)";
    o << "; blocked " << blocked << "\n";
    const auto pend = pending_alerts(q);
    if (!pend.empty()) {
        o << "alerts  " << pend.size() << " pending since the last ack:\n";
        const size_t s0 = pend.size() > 5 ? pend.size() - 5 : 0;
        for (size_t i = s0; i < pend.size(); ++i)
            o << "        " << pend[i]->at << " " << pend[i]->kind << ": " << pend[i]->detail << "\n";
        attention.push_back(std::to_string(pend.size()) + " pending alert(s) (ack-alerts after reading them)");
    }
    if (attention.empty()) {
        o << "RESULT  OK\n";
        return kExitOk;
    }
    o << "RESULT  ATTENTION\n";
    for (const std::string& r : attention) o << "        - " << r << "\n";
    return kExitAttention;
}

struct StreamSink : JournalSink {
    std::ostream& o;
    explicit StreamSink(std::ostream& s) : o(s) {}
    void line(const std::string& text) override { o << text << std::endl; }
};

int cmd_run(Ctx& c, const std::vector<std::string>& v)
{
    Args a;
    std::string why;
    if (!parse_args(v, 1, {"--once"}, {}, {}, a, why)) return usage_error(c, why);
    if (!a.pos.empty()) return usage_error(c, "usage: run [--once]");
    const bool once = a.has("--once");
    int rc = 0;
    if (!check_owner(c, rc)) return rc;

    // Create the queue (and its directory) when missing, then take the runner
    // lock, held for the whole loop: a second runner exits "lock held".
    Queue q;
    bool created = false;
    if (!load_or_create_queue(c.path, q, created, why, [&](Queue& nq) {
            if (c.g.node_url) nq.node.url = *c.g.node_url;
            if (c.g.token_file) nq.node.token_file = *c.g.token_file;
            if (c.g.poll_sec) nq.defaults.poll_sec = *c.g.poll_sec;
        })) {
        c.err() << "queue " << c.path << ": " << why << "\n";
        return kExitQueue;
    }
    QueueLock runner_lock;
    if (!runner_lock.acquire(runner_lock_base(c.path), /*blocking=*/false, why)) {
        c.err() << "runner: " << why << "\n";
        return why.find("lock held") != std::string::npos ? kExitLock : kExitUsage;
    }
    // Re-read under the runner lock: another runner may have written since.
    bool created2 = false;
    if (!load_or_create_queue(c.path, q, created2, why)) {
        c.err() << "queue " << c.path << ": " << why << "\n";
        return kExitQueue;
    }

    const std::string url = c.g.node_url.value_or(q.node.url);
    if (!validate_node_url(url, why)) return usage_error(c, "config: " + why);
    const std::string token_file = c.g.token_file.value_or(q.node.token_file);
    if (token_file.empty())
        return usage_error(c, "config: no token file (pass --token-file PATH, or record it with init --token-file PATH)");
    std::unique_ptr<NodeApi> api = c.env.make_api(url, why);
    if (!api) return usage_error(c, "config: node transport: " + why);
    int64_t poll = c.g.poll_sec.value_or(q.defaults.poll_sec);
    if (poll < 1 || poll > 3600) poll = 15;

    StreamSink sink(c.out());
    const std::string at = format_utc(c.now());
    sink.line(at + " runner: start queue=" + c.path + (created ? " (created)" : "") + " node=" + url +
              " token_file=" + token_file + " poll=" + std::to_string(poll) + "s items=" + std::to_string(q.items.size()) +
              (once ? " once" : ""));
    sink.line(at + " runner: arm policy: " + policy_text(q.arm_policy));
    {
        c2w::secure::SecureString tok;
        std::string terr;
        if (TokenFile::read(token_file, tok, terr)) sink.line(at + " runner: token file usable (content not shown)");
        else sink.line(at + " runner: WARNING token file not usable: " + terr + " (items block until it is fixed)");
        tok.clear();
    }

    SchedulerOptions so;
    so.token_file = token_file;
    Runner r(c.path, std::move(q), *api, *c.env.clock, sink, so);
    int exit_code = kExitOk;
    for (;;) {
        const Runner::Step s = r.step();
        if (!s.ticked) {
            sink.line(format_utc(c.now()) + " runner: tick skipped (nothing sent to the node): " + s.sync_error);
            if (once) exit_code = kExitQueue;
        } else if (s.report.persist_failed) {
            sink.line(format_utc(c.now()) + " runner: WARNING persist failed: " + s.report.persist_error);
        }
        if (once) break;
        if (c.env.stop_requested && c.env.stop_requested()) break;
        if (c.env.sleep_ms) c.env.sleep_ms(poll * 1000);
        if (c.env.stop_requested && c.env.stop_requested()) break;
    }
    sink.line(format_utc(c.now()) + " runner: stop");
    return exit_code;
}

} // namespace

std::string default_queue_path()
{
    std::string base;
    const char* x = std::getenv("XDG_DATA_HOME");
    if (x && x[0] == '/') {
        base = x;
    } else {
#if !defined(_WIN32)
        if (const struct passwd* pw = ::getpwuid(::geteuid()); pw && pw->pw_dir && pw->pw_dir[0] == '/')
            base = std::string(pw->pw_dir) + "/.local/share";
#endif
        if (base.empty()) {
            const char* h = std::getenv("HOME");
            base = std::string(h && h[0] == '/' ? h : ".") + "/.local/share";
        }
    }
    return base + "/c2wallet-qt/companion/queue.json";
}

namespace {
const char* sched_usage_text()
{
    return R"(c2wallet-qt-schedd - headless inject scheduler for a local c2pool DASH node (key-free).

usage: c2wallet-qt-schedd [--queue PATH] [--node-url URL] [--token-file PATH] [--poll-sec N] COMMAND ...

  --queue PATH       queue file (default $XDG_DATA_HOME or ~/.local/share + /c2wallet-qt/companion/queue.json)
  --node-url URL     loopback only: http://127.0.0.1:PORT, http://[::1]:PORT, http://localhost:PORT
  --token-file PATH  the node's 0600 control-token file (there is no --token VALUE)
  --poll-sec N       runner tick interval, 1..3600 (default: the queue's poll_sec, 15)

commands:
  init [--network mainnet|testnet]
        create the queue, or update its node.url / token_file / poll_sec from the global options
  add --hex FILE [--manifest FILE | --no-manifest] [--line N] [--label TEXT]
      [--after-parent TXID[:N]]... [--no-discover-parents] [--allow-unconfirmed-parent]
      [--not-before-height H] [--not-before-time YYYY-MM-DDTHH:MM:SSZ]
      [--h0 H] [--maturity-slack N] [--inputs-known-mature "<consent text>"]
      [--expiry-blocks N] [--max-fee DUFFS] [--auto-resubmit-max N] [--auto-renew]
      [--allow-auto-arm yes|no] [--pause]
      [--preflight [--utxos FILE] [--scanplan FILE] [--source dashd|c2pool|both|none]
       [--dashd-url URL --dashd-auth-file PATH] [--no-validate] [--force "<reason>"]]
        queue each line of a signed .hex (the sibling NAME.manifest.json is used when present).
        Maturity comes from the manifest, or from --h0 (youngest input height, coinbase rule
        h0+100); without either, --not-before-height or --inputs-known-mature is required.
        A parent (--after-parent, or an input already in the queue) must be mined with N
        confirmations (default 1) AND final: ChainLocked, or >= 2 confirmations when the node
        exposes no ChainLock. --allow-unconfirmed-parent lets a parent in the node mempool fire
        the child instead (off unless given).
  list                    every item: state, why it waits, and the live IS-hold / retry ETA
  show ID [--journal N] [--attempts N]
                          one item in full (ID = item id, txid, or a unique txid prefix)
  pause ID | resume ID | rm ID | requeue ID | retry ID
  set-max-fee ID DUFFS
  arm-policy [--auto-arm yes|no] [--auto-disarm-when-idle yes|no] --consent "<text>"
        record (timestamped) or revoke auto-arm consent; with no option, print the policy.
        Nothing ever defaults to auto-arm; auto-disarm stays off unless given. Alias: set-arm-policy
  ack-alerts              mark the current alerts as read (status stops counting them)
  status                  node arm state, tip, ChainLock, pool, runner liveness, item counts;
                          exit 1 when anything needs attention (monitoring hook)
  run [--once]            the loop (single instance per queue; logs to stdout)

exit codes: 0 ok, 1 refused / attention, 2 usage or config error, 3 queue unreadable, 4 lock held
)";
}
} // namespace

const char* usage_text()
{
    static const std::string text = std::string(sched_usage_text()) + "\n" + scan::cli::usage_text();
    return text.c_str();
}

int run(const std::vector<std::string>& args, Env& env)
{
    CliOverrides g;
    std::string why;
    std::ostream& err = *env.err;
    if (!parse_cli_overrides(args, g, why)) {
        err << why << "\n";
        return kExitUsage;
    }
    if (g.rest.empty()) {
        err << usage_text();
        return kExitUsage;
    }
    const std::string cmd = g.rest[0];
    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        *env.out << usage_text();
        return kExitOk;
    }
    Ctx c{env, g, g.queue.value_or(env.default_queue_path.empty() ? default_queue_path() : env.default_queue_path)};
    const std::vector<std::string>& v = g.rest;
    if (cmd == "init") return cmd_init(c, v);
    if (cmd == "add") return cmd_add(c, v);
    if (cmd == "list") return cmd_list(c, v);
    if (cmd == "show") return cmd_show(c, v);
    if (cmd == "pause" || cmd == "resume" || cmd == "rm" || cmd == "requeue" || cmd == "retry" || cmd == "set-max-fee")
        return cmd_item_edit(c, v, cmd);
    if (cmd == "arm-policy" || cmd == "set-arm-policy") return cmd_arm_policy(c, v);
    if (cmd == "ack-alerts") return cmd_ack_alerts(c, v);
    if (cmd == "status") return cmd_status(c, v);
    if (cmd == "run") return cmd_run(c, v);
    if (scan::cli::is_scan_command(cmd)) return scan::cli::run(v, env, g, c.path);
    err << "usage: unknown command '" << cmd << "'\n" << usage_text();
    return kExitUsage;
}

} // namespace c2w::companion::sched::cli
