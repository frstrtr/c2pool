// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/p2pool_state.hpp
//
// THE STATE FILE: what the monitor knows, in a form that survives the monitor.
//
// ---------------------------------------------------------------------------
// WHY THERE IS A FILE AT ALL
// ---------------------------------------------------------------------------
// Everything the observer learns lives in a ReadModel in process memory, which
// means a three-hour watch ends the way it began: with nothing. Worse, the
// headless `--snapshot` run -- the one that is actually left going overnight --
// prints its single frame at the END, so a run that is killed at hour two has
// produced literally no output at all. The most valuable observation this
// component can make is a rare one (a same-height race, a stall, a chain going
// dark at 4am), and rare observations are exactly the ones a session-lifetime
// memory loses.
//
// So the monitor writes what it knows to a file on every refresh, and reads it
// back when it starts. Two properties are worth more than everything else in
// this header put together:
//
//   * THE FILE IS NEVER HALF-WRITTEN. A snapshot is written to a temporary file
//     in the same directory, fsynced, and renamed over the real one, which is
//     atomic on POSIX. A reader -- including the next run of the monitor -- sees
//     either the previous complete state or the new complete state, never a
//     torn one, whatever happens to the writer in between. That machinery is in
//     p2pool_persist.hpp; this file is the FORMAT it writes.
//   * THE FILE CANNOT DISAGREE WITH THE SCREEN. MonitorState is built from
//     tui::MonitorFrame -- the same plain-data snapshot the renderer draws, from
//     the same instant -- and not from a second pass over the read models. A
//     second pass would be a second source of truth, and two sources of truth
//     about a number is one more than is useful.
//
// The inverse direction, frame_of(), rebuilds a frame from a file so `--read`
// renders a saved state through the SAME renderer, with no network at all.
//
// ---------------------------------------------------------------------------
// WHAT THE FORMAT COMMITS TO
// ---------------------------------------------------------------------------
// JSON, one object, schema tag "p2pmon-state/1", about 3 KB for three chains.
// A text format, because the whole point is that something other than this
// program can read it -- jq, a spreadsheet, a person at 4am -- and a binary
// format would make the file useful only to the code that wrote it.
//
// EVERY TIME IN THE FILE IS WALL-CLOCK MILLISECONDS, never an elapsed figure.
// "This chain's tip last moved 40 seconds ago" is a statement that becomes
// false while the file sits on disk; "this chain's tip last moved at
// 1757620000123" stays true forever and is turned back into an age against the
// CURRENT clock when it is read. That single rule is what makes a day-old file
// render as STALE rather than as a healthy chain -- and it is the reason the
// freshness clock lives in absolute instants in p2pool_freshness.hpp.
//
// NUMBERS THAT MUST BE EXACT ARE STORED AS TEXT. Difficulty and cumulative
// difficulty are up to 128 bits; JSON numbers are doubles in most readers, and
// a double loses the low bits of a cumulative difficulty. They are written as
// decimal STRINGS and read back through a 128-bit accumulator, so the value
// that comes out is bit-identical to the one that went in. The derived
// `hashrate_hs` is written as a convenience for external readers and is NOT
// read back: on load it is recomputed from the exact difficulty by the same
// expression the live path uses, so a restored panel and a live panel cannot
// round differently.
//
// ---------------------------------------------------------------------------
// WHY A HAND-ROLLED WRITER AND minijson FOR READING
// ---------------------------------------------------------------------------
// The p2pool targets are a LIGHT link -- xmr_coin and nothing else -- and stay
// that way. The writer below is about forty lines of string building, and the
// reader is the repository's existing header-only
// src/impl/xmr/node/minijson.hpp, included as-is: it keeps number tokens as raw
// TEXT, which is exactly what a u64 that must survive a round trip needs, and
// including it edits nothing outside this tree.
//
// The file we parse is one we wrote, in a directory we own, so minijson's
// "well-formed input" contract is met by construction. It is still treated as
// untrusted in the one way that matters: from_json() validates the schema tag
// and every field is read through a defaulting accessor, so a truncated,
// hand-edited or foreign file yields a state with missing fields rather than a
// crash -- and a state whose chains are absent renders as absent, which is the
// correct answer.
//
// STL only, deliberately POSIX-free: the offline render KAT compiles this
// header, and the syscalls live one file over.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "impl/xmr/node/minijson.hpp"
#include "impl/xmr/p2pool/p2pool_consensus.hpp"
#include "impl/xmr/p2pool/p2pool_freshness.hpp"
#include "impl/xmr/p2pool/p2pool_tui.hpp"

namespace c2pool::xmr::p2pool::state {

// The reader, included as-is from the native lane and not edited: it lives in a
// different namespace branch, so it gets an alias rather than a copy.
namespace minijson = c2pool::xmr::node::minijson;

inline constexpr const char* kSchema      = "p2pmon-state/1";
inline constexpr const char* kStateFile   = "p2pmon-state.json";
inline constexpr const char* kJournalFile = "p2pmon-history.jsonl";
inline constexpr const char* kLockFile    = ".lock";

// ---------------------------------------------------------------------------
// A tiny JSON writer. Emits compact, well-formed JSON and nothing else.
// ---------------------------------------------------------------------------
class JsonWriter {
public:
    JsonWriter& begin_object() { sep(); s_ += '{'; comma_ = false; return *this; }
    JsonWriter& end_object()   { s_ += '}'; comma_ = true;  return *this; }
    JsonWriter& begin_array()  { sep(); s_ += '['; comma_ = false; return *this; }
    JsonWriter& end_array()    { s_ += ']'; comma_ = true;  return *this; }

    JsonWriter& key(const char* k) {
        sep();
        s_ += '"'; s_ += k; s_ += "\":";
        comma_ = false;
        return *this;
    }
    JsonWriter& str(const std::string& v) { sep(); escape(v); comma_ = true; return *this; }
    JsonWriter& u64(std::uint64_t v) { sep(); s_ += std::to_string(v); comma_ = true; return *this; }
    JsonWriter& integer(long long v) { sep(); s_ += std::to_string(v); comma_ = true; return *this; }
    JsonWriter& boolean(bool v) { sep(); s_ += v ? "true" : "false"; comma_ = true; return *this; }
    JsonWriter& null() { sep(); s_ += "null"; comma_ = true; return *this; }

    // %.17g is the shortest form that round-trips an IEEE double exactly, which
    // is the only property this needs. Non-finite values cannot occur here and
    // would not be valid JSON, so they are written as 0 rather than as `nan`.
    JsonWriter& number(double v) {
        sep();
        if (!(v == v) || v > 1e308 || v < -1e308) { s_ += '0'; comma_ = true; return *this; }
        char b[40];
        std::snprintf(b, sizeof(b), "%.17g", v);
        s_ += b;
        comma_ = true;
        return *this;
    }

    const std::string& text() const noexcept { return s_; }

private:
    void sep() { if (comma_) s_ += ','; comma_ = true; }

    void escape(const std::string& v) {
        s_ += '"';
        for (const char c : v) {
            switch (c) {
                case '"':  s_ += "\\\""; break;
                case '\\': s_ += "\\\\"; break;
                case '\n': s_ += "\\n";  break;
                case '\r': s_ += "\\r";  break;
                case '\t': s_ += "\\t";  break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char b[8];
                        std::snprintf(b, sizeof(b), "\\u%04x", static_cast<unsigned>(c) & 0xFFu);
                        s_ += b;
                    } else {
                        s_ += c;
                    }
            }
        }
        s_ += '"';
    }

    std::string s_;
    bool        comma_ = false;
};

// ---------------------------------------------------------------------------
// Exact decimal <-> 128-bit. The difficulty round trip.
// ---------------------------------------------------------------------------
inline bool dec_to_u128(const std::string& s, std::uint64_t& hi, std::uint64_t& lo) {
    hi = 0;
    lo = 0;
    if (s.empty() || s.size() > 40) return false;
    unsigned __int128 v = 0;
    for (const char c : s) {
        if (c < '0' || c > '9') return false;
        const unsigned __int128 next = v * 10u + static_cast<unsigned>(c - '0');
        if (next < v) return false;                 // overflowed 128 bits
        v = next;
    }
    hi = static_cast<std::uint64_t>(v >> 64);
    lo = static_cast<std::uint64_t>(v);
    return true;
}

// The SAME expression Difficulty::as_double() uses, so a value that made the
// round trip renders to the same long double it did before it was written.
inline long double u128_as_double(std::uint64_t hi, std::uint64_t lo) noexcept {
    return static_cast<long double>(hi) * 18446744073709551616.0L
         + static_cast<long double>(lo);
}

// ---------------------------------------------------------------------------
// THE RECORD
// ---------------------------------------------------------------------------

// What is true of a chain across every session that has ever run against this
// state directory. Only ever monotone: a high-water mark cannot be un-seen by a
// later run that happened to start cold.
struct ChainLifetime {
    std::uint64_t tip_height_max = 0;
    std::uint64_t monero_tpl_max = 0;
};

struct ChainState {
    std::string   name;                   // "main" / "mini" / "nano"
    std::uint16_t port     = 0;
    std::uint64_t target_s = 0;

    std::string   liveness = "DARK";      // the word that was on screen
    std::string   source   = "live";      // "live" or "restored"
    bool          have_data = false;      // the gate for absence-vs-zero

    // Absolute wall-clock instants; see the header on why none of these is an age.
    bool          ever_connected     = false;
    std::uint64_t started_at_ms      = 0;
    std::uint64_t tip_advanced_at_ms = 0;
    std::uint64_t rx_at_ms           = 0;
    std::uint64_t up_since_ms        = 0;   // 0 = no peers up
    std::uint64_t down_since_ms      = 0;   // 0 = peers up

    std::uint64_t tip_height = 0;
    std::string   tip_id;                   // 64 hex, or empty when there is none
    std::string   difficulty            = "0";   // exact decimal
    std::string   cumulative_difficulty = "0";   // exact decimal
    double        hashrate_hs = 0.0;        // derived; recomputed on load

    bool          cadence_ok = false;
    double        cadence_s  = 0.0;
    std::uint64_t cadence_n  = 0;
    std::uint64_t frontier   = 0;
    std::vector<std::uint64_t> gaps_ms;     // at most 24, oldest first

    std::uint64_t contested       = 0;
    std::uint64_t uncles_named    = 0;
    std::uint64_t uncles_resolved = 0;
    std::uint64_t monero_tpl_high = 0;
    std::uint64_t monero_heights  = 0;

    std::uint64_t peers_up    = 0;
    std::uint64_t sockets     = 0;
    std::uint64_t peers_known = 0;
    std::uint64_t gossiped    = 0;
    std::uint64_t queued      = 0;

    std::uint64_t distinct       = 0;
    std::uint64_t dupes          = 0;
    std::uint64_t parse_failures = 0;
    std::uint64_t broadcasts     = 0;

    std::uint64_t out_messages[kControlMessageCount] = {0, 0, 0, 0};
    std::uint64_t out_bytes[kControlMessageCount]    = {0, 0, 0, 0};

    ChainLifetime lifetime;
};

struct PersistStats {
    std::uint64_t errors            = 0;
    std::string   last_error;
    std::uint64_t loop_stall_max_ms = 0;
};

struct LifetimeState {
    std::uint64_t sessions            = 0;
    std::uint64_t first_started_at_ms = 0;
    std::uint64_t runtime_ms_total    = 0;
};

struct MonitorState {
    std::string   schema = kSchema;
    std::uint64_t written_at_ms = 0;
    std::uint64_t seq  = 0;
    std::uint64_t pid  = 0;
    std::string   host;
    std::string   session_id;              // "<start_wall_ms>-<pid>"
    std::uint64_t session_started_at_ms = 0;
    std::uint64_t elapsed_ms = 0;
    std::string   shutdown;                // "clean" when written on the way out

    std::vector<int>         emitted_ids;      // the read-only claim, on disk
    std::vector<std::string> chains_configured;

    PersistStats  persist;
    LifetimeState lifetime;
    std::vector<ChainState> chains;

    const ChainState* find(const std::string& name) const {
        for (const ChainState& c : chains) if (c.name == name) return &c;
        return nullptr;
    }
    bool loaded() const noexcept { return written_at_ms != 0; }
};

// ---------------------------------------------------------------------------
// WRITE
// ---------------------------------------------------------------------------
inline void write_chain(JsonWriter& w, const ChainState& c) {
    w.begin_object();
    w.key("port").u64(c.port);
    w.key("target_s").u64(c.target_s);
    w.key("liveness").str(c.liveness);
    w.key("source").str(c.source);
    w.key("have_data").boolean(c.have_data);
    w.key("ever_connected").boolean(c.ever_connected);
    w.key("started_at_ms").u64(c.started_at_ms);
    w.key("tip_advanced_at_ms").u64(c.tip_advanced_at_ms);
    w.key("rx_at_ms").u64(c.rx_at_ms);
    w.key("up_since_ms");   if (c.up_since_ms)   w.u64(c.up_since_ms);   else w.null();
    w.key("down_since_ms"); if (c.down_since_ms) w.u64(c.down_since_ms); else w.null();
    w.key("tip_height").u64(c.tip_height);
    w.key("tip_id").str(c.tip_id);
    w.key("difficulty").str(c.difficulty);
    w.key("cumulative_difficulty").str(c.cumulative_difficulty);
    w.key("hashrate_hs").number(c.hashrate_hs);
    w.key("cadence_ok").boolean(c.cadence_ok);
    w.key("cadence_s").number(c.cadence_s);
    w.key("cadence_n").u64(c.cadence_n);
    w.key("frontier").u64(c.frontier);
    w.key("gaps_ms").begin_array();
    for (const std::uint64_t g : c.gaps_ms) w.u64(g);
    w.end_array();
    w.key("contested").u64(c.contested);
    w.key("uncles_named").u64(c.uncles_named);
    w.key("uncles_resolved").u64(c.uncles_resolved);
    w.key("monero_tpl_high").u64(c.monero_tpl_high);
    w.key("monero_heights").u64(c.monero_heights);
    w.key("peers_up").u64(c.peers_up);
    w.key("sockets").u64(c.sockets);
    w.key("peers_known").u64(c.peers_known);
    w.key("gossiped").u64(c.gossiped);
    w.key("queued").u64(c.queued);
    w.key("distinct").u64(c.distinct);
    w.key("dupes").u64(c.dupes);
    w.key("parse_failures").u64(c.parse_failures);
    w.key("broadcasts").u64(c.broadcasts);
    w.key("out").begin_object();
    w.key("messages").begin_array();
    for (std::size_t i = 0; i < kControlMessageCount; ++i) w.u64(c.out_messages[i]);
    w.end_array();
    w.key("bytes").begin_array();
    for (std::size_t i = 0; i < kControlMessageCount; ++i) w.u64(c.out_bytes[i]);
    w.end_array();
    w.end_object();
    w.key("lifetime").begin_object();
    w.key("tip_height_max").u64(c.lifetime.tip_height_max);
    w.key("monero_tpl_max").u64(c.lifetime.monero_tpl_max);
    w.end_object();
    w.end_object();
}

inline std::string to_json(const MonitorState& s) {
    JsonWriter w;
    w.begin_object();
    w.key("schema").str(s.schema.empty() ? std::string(kSchema) : s.schema);
    w.key("written_at_ms").u64(s.written_at_ms);
    w.key("seq").u64(s.seq);
    w.key("pid").u64(s.pid);
    w.key("host").str(s.host);
    w.key("session_id").str(s.session_id);
    w.key("session_started_at_ms").u64(s.session_started_at_ms);
    w.key("elapsed_ms").u64(s.elapsed_ms);
    if (!s.shutdown.empty()) w.key("shutdown").str(s.shutdown);
    w.key("emitted_ids").begin_array();
    for (const int id : s.emitted_ids) w.integer(id);
    w.end_array();
    w.key("chains_configured").begin_array();
    for (const std::string& n : s.chains_configured) w.str(n);
    w.end_array();
    w.key("persist").begin_object();
    w.key("errors").u64(s.persist.errors);
    w.key("last_error").str(s.persist.last_error);
    w.key("loop_stall_max_ms").u64(s.persist.loop_stall_max_ms);
    w.end_object();
    w.key("lifetime").begin_object();
    w.key("sessions").u64(s.lifetime.sessions);
    w.key("first_started_at_ms").u64(s.lifetime.first_started_at_ms);
    w.key("runtime_ms_total").u64(s.lifetime.runtime_ms_total);
    w.end_object();
    w.key("chains").begin_object();
    for (const ChainState& c : s.chains) { w.key(c.name.c_str()); write_chain(w, c); }
    w.end_object();
    w.end_object();
    return w.text() + "\n";
}

// The journal line. A COMPACT DIGEST, not the whole state: the journal exists
// to be tailed and to be grepped months later for "when did nano go dark", and
// a 3 KB line per second is neither. It is append-only and NEVER read back by
// this program -- the state file is the only thing load() looks at -- so its
// shape can change without a migration.
inline std::string journal_line(const MonitorState& s) {
    JsonWriter w;
    w.begin_object();
    w.key("t").u64(s.written_at_ms);
    w.key("seq").u64(s.seq);
    w.key("session").str(s.session_id);
    w.key("elapsed_ms").u64(s.elapsed_ms);
    if (!s.shutdown.empty()) w.key("shutdown").str(s.shutdown);
    w.key("chains").begin_object();
    for (const ChainState& c : s.chains) {
        w.key(c.name.c_str()).begin_object();
        w.key("live").str(c.liveness);
        w.key("tip").u64(c.tip_height);
        w.key("peers").u64(c.peers_up);
        w.key("blocks").u64(c.distinct);
        w.key("contested").u64(c.contested);
        w.key("tip_at").u64(c.tip_advanced_at_ms);
        w.end_object();
    }
    w.end_object();
    w.end_object();
    return w.text();
}

// ---------------------------------------------------------------------------
// READ
// ---------------------------------------------------------------------------
namespace detail {

using minijson::Value;

inline std::uint64_t u64_or(const Value& v, std::uint64_t d = 0) {
    return v.is_number() ? v.as_u64(d) : d;
}
inline double dbl_or(const Value& v, double d = 0.0) {
    return v.is_number() ? v.as_double(d) : d;
}
inline std::string str_or(const Value& v, const char* d = "") {
    return v.is_string() ? v.as_string() : std::string(d);
}

inline ChainState read_chain(const std::string& name, const Value& o) {
    ChainState c;
    c.name     = name;
    c.port     = static_cast<std::uint16_t>(u64_or(o["port"]));
    c.target_s = u64_or(o["target_s"]);
    c.liveness = str_or(o["liveness"], "DARK");
    c.source   = str_or(o["source"], "live");
    c.have_data      = o["have_data"].as_bool(false);
    c.ever_connected = o["ever_connected"].as_bool(false);
    c.started_at_ms      = u64_or(o["started_at_ms"]);
    c.tip_advanced_at_ms = u64_or(o["tip_advanced_at_ms"]);
    c.rx_at_ms           = u64_or(o["rx_at_ms"]);
    c.up_since_ms        = u64_or(o["up_since_ms"]);      // null -> 0, which is its meaning
    c.down_since_ms      = u64_or(o["down_since_ms"]);
    c.tip_height = u64_or(o["tip_height"]);
    c.tip_id     = str_or(o["tip_id"]);
    c.difficulty            = str_or(o["difficulty"], "0");
    c.cumulative_difficulty = str_or(o["cumulative_difficulty"], "0");
    c.hashrate_hs = dbl_or(o["hashrate_hs"]);
    c.cadence_ok = o["cadence_ok"].as_bool(false);
    c.cadence_s  = dbl_or(o["cadence_s"]);
    c.cadence_n  = u64_or(o["cadence_n"]);
    c.frontier   = u64_or(o["frontier"]);
    for (const Value& g : o["gaps_ms"].arr) c.gaps_ms.push_back(u64_or(g));
    c.contested       = u64_or(o["contested"]);
    c.uncles_named    = u64_or(o["uncles_named"]);
    c.uncles_resolved = u64_or(o["uncles_resolved"]);
    c.monero_tpl_high = u64_or(o["monero_tpl_high"]);
    c.monero_heights  = u64_or(o["monero_heights"]);
    c.peers_up    = u64_or(o["peers_up"]);
    c.sockets     = u64_or(o["sockets"]);
    c.peers_known = u64_or(o["peers_known"]);
    c.gossiped    = u64_or(o["gossiped"]);
    c.queued      = u64_or(o["queued"]);
    c.distinct       = u64_or(o["distinct"]);
    c.dupes          = u64_or(o["dupes"]);
    c.parse_failures = u64_or(o["parse_failures"]);
    c.broadcasts     = u64_or(o["broadcasts"]);
    const Value& out = o["out"];
    for (std::size_t i = 0; i < kControlMessageCount && i < out["messages"].arr.size(); ++i)
        c.out_messages[i] = u64_or(out["messages"].arr[i]);
    for (std::size_t i = 0; i < kControlMessageCount && i < out["bytes"].arr.size(); ++i)
        c.out_bytes[i] = u64_or(out["bytes"].arr[i]);
    c.lifetime.tip_height_max = u64_or(o["lifetime"]["tip_height_max"]);
    c.lifetime.monero_tpl_max = u64_or(o["lifetime"]["monero_tpl_max"]);
    return c;
}

}  // namespace detail

// Returns false with a reason on anything that is not a state file of a schema
// we understand. A false here is never fatal to the caller: a monitor that
// cannot read the previous state starts a fresh one and says so.
inline bool from_json(const std::string& text, MonitorState& out, std::string& why) {
    minijson::Value root;
    if (!minijson::parse(text, root) || !root.is_object()) { why = "not JSON"; return false; }
    const std::string schema = detail::str_or(root["schema"]);
    if (schema != kSchema) {
        why = "schema is \"" + schema + "\", expected \"" + kSchema + "\"";
        return false;
    }

    MonitorState s;
    s.schema        = schema;
    s.written_at_ms = detail::u64_or(root["written_at_ms"]);
    s.seq           = detail::u64_or(root["seq"]);
    s.pid           = detail::u64_or(root["pid"]);
    s.host          = detail::str_or(root["host"]);
    s.session_id    = detail::str_or(root["session_id"]);
    s.session_started_at_ms = detail::u64_or(root["session_started_at_ms"]);
    s.elapsed_ms    = detail::u64_or(root["elapsed_ms"]);
    s.shutdown      = detail::str_or(root["shutdown"]);
    for (const minijson::Value& v : root["emitted_ids"].arr)
        s.emitted_ids.push_back(static_cast<int>(detail::u64_or(v)));
    for (const minijson::Value& v : root["chains_configured"].arr)
        s.chains_configured.push_back(detail::str_or(v));
    s.persist.errors            = detail::u64_or(root["persist"]["errors"]);
    s.persist.last_error        = detail::str_or(root["persist"]["last_error"]);
    s.persist.loop_stall_max_ms = detail::u64_or(root["persist"]["loop_stall_max_ms"]);
    s.lifetime.sessions            = detail::u64_or(root["lifetime"]["sessions"]);
    s.lifetime.first_started_at_ms = detail::u64_or(root["lifetime"]["first_started_at_ms"]);
    s.lifetime.runtime_ms_total    = detail::u64_or(root["lifetime"]["runtime_ms_total"]);

    // Chains are written keyed by name and read back in the order the file
    // listed them under chains_configured, so a state written with
    // `--chains nano,main` reloads in that order rather than in map order.
    const minijson::Value& chains = root["chains"];
    for (const std::string& n : s.chains_configured) {
        const minijson::Value& c = chains[n];
        if (c.is_object()) s.chains.push_back(detail::read_chain(n, c));
    }
    for (const auto& kv : chains.obj) {
        if (s.find(kv.first)) continue;                // already taken in order
        if (kv.second.is_object()) s.chains.push_back(detail::read_chain(kv.first, kv.second));
    }

    if (!s.written_at_ms) { why = "no written_at_ms"; return false; }
    out = s;
    return true;
}

// ---------------------------------------------------------------------------
// FRAME -> STATE. One instant, one copy, no second pass over the read models.
// ---------------------------------------------------------------------------
struct SessionMeta {
    std::uint64_t written_at_ms = 0;
    std::uint64_t seq = 0;
    std::uint64_t pid = 0;
    std::string   host;
    std::string   session_id;
    std::uint64_t session_started_at_ms = 0;
    std::string   shutdown;
    PersistStats  persist;
    LifetimeState lifetime;
};

inline ChainState chain_state_of(const tui::ChainView& v) {
    ChainState c;
    c.name     = to_string(v.chain);
    c.port     = v.port;
    c.target_s = v.target_s;
    c.liveness = to_string(v.status);
    c.source   = to_string(v.source);
    c.have_data = v.have_data;
    c.ever_connected     = v.fresh.ever_connected;
    c.started_at_ms      = v.fresh.started_at_ms;
    c.tip_advanced_at_ms = v.fresh.tip_at_ms;
    c.rx_at_ms           = v.fresh.rx_at_ms;
    c.up_since_ms        = v.fresh.up_since_ms;
    c.down_since_ms      = v.fresh.down_since_ms;
    c.tip_height = v.tip_height;
    c.tip_id     = v.tip_id;
    c.difficulty            = v.difficulty;
    c.cumulative_difficulty = v.cumulative;
    c.hashrate_hs = static_cast<double>(v.hashrate);
    c.cadence_ok = v.cadence_ok;
    c.cadence_s  = v.cadence_s;
    c.cadence_n  = v.cadence_n;
    c.frontier   = v.frontier;
    c.gaps_ms    = v.gaps_ms;
    c.contested       = v.contested;
    c.uncles_named    = v.uncles_named;
    c.uncles_resolved = v.uncles_resolved;
    c.monero_tpl_high = v.monero_high;
    c.monero_heights  = v.monero_heights;
    c.peers_up    = v.peers_up;
    c.sockets     = v.sockets;
    c.peers_known = v.peers_known;
    c.gossiped    = v.gossiped;
    c.queued      = v.queued;
    c.distinct       = v.distinct;
    c.dupes          = v.dupes;
    c.parse_failures = v.parse_failures;
    c.broadcasts     = v.broadcasts;
    for (std::size_t i = 0; i < kControlMessageCount; ++i) {
        c.out_messages[i] = v.out.messages[i];
        c.out_bytes[i]    = v.out.bytes[i];
    }
    c.lifetime.tip_height_max = v.lifetime_tip_max > v.tip_height
                              ? v.lifetime_tip_max : v.tip_height;
    c.lifetime.monero_tpl_max = v.lifetime_monero_max > v.monero_high
                              ? v.lifetime_monero_max : v.monero_high;
    return c;
}

inline MonitorState state_of(const tui::MonitorFrame& f, const SessionMeta& meta) {
    MonitorState s;
    s.written_at_ms = meta.written_at_ms;
    s.seq  = meta.seq;
    s.pid  = meta.pid;
    s.host = meta.host;
    s.session_id = meta.session_id;
    s.session_started_at_ms = meta.session_started_at_ms;
    s.elapsed_ms = f.elapsed_ms;
    s.shutdown   = meta.shutdown;
    s.emitted_ids = tui::emitted_id_set();      // computed from the encoder, on disk
    s.persist  = meta.persist;
    s.lifetime = meta.lifetime;
    for (const tui::ChainView& v : f.chains) {
        s.chains_configured.push_back(to_string(v.chain));
        s.chains.push_back(chain_state_of(v));
    }
    return s;
}

// ---------------------------------------------------------------------------
// STATE -> FRAME. `--read`, and the reason the state file is worth writing: a
// saved state goes through the SAME renderer as a live one, which is what makes
// the file reviewable rather than merely archived.
//
// Everything time-dependent is resolved against the CALLER'S `now`, never
// against the file's own timestamps, so a file that has been sitting on disk
// for a day renders as a day-old chain -- STALE, with the age spelled out --
// rather than as whatever it looked like when it was written.
// ---------------------------------------------------------------------------
inline tui::ChainView chain_view_of(const ChainState& c, std::uint64_t now_ms) {
    tui::ChainView v;
    if (c.name == "mini")      v.chain = Sidechain::Mini;
    else if (c.name == "nano") v.chain = Sidechain::Nano;
    else                       v.chain = Sidechain::Main;
    v.port     = c.port ? c.port : default_port(v.chain);
    v.target_s = c.target_s ? c.target_s : params_of(v.chain).target_block_time;

    v.source    = tui::ChainSource::Restored;
    v.have_data = c.have_data;

    v.fresh.known          = true;
    v.fresh.have_data      = c.have_data;
    v.fresh.ever_connected = c.ever_connected;
    v.fresh.started_at_ms  = c.started_at_ms;
    v.fresh.tip_at_ms      = c.tip_advanced_at_ms;
    v.fresh.rx_at_ms       = c.rx_at_ms;
    v.fresh.up_since_ms    = c.up_since_ms;
    v.fresh.down_since_ms  = c.down_since_ms;

    v.tip_height = c.tip_height;
    v.tip_id     = c.tip_id;
    v.tip_id8    = c.tip_id.size() >= 8 ? c.tip_id.substr(0, 8) : std::string("-");
    v.difficulty = c.difficulty;
    v.cumulative = c.cumulative_difficulty;

    // Exact decimal back to the same long double the live path computed.
    std::uint64_t hi = 0, lo = 0;
    if (dec_to_u128(c.difficulty, hi, lo)) v.difficulty_d = u128_as_double(hi, lo);
    if (dec_to_u128(c.cumulative_difficulty, hi, lo)) v.cumulative_d = u128_as_double(hi, lo);
    v.hashrate = v.target_s ? v.difficulty_d / static_cast<long double>(v.target_s) : 0.0L;

    v.cadence_ok = c.cadence_ok;
    v.cadence_s  = c.cadence_s;
    v.cadence_n  = static_cast<std::size_t>(c.cadence_n);
    v.frontier   = c.frontier;
    v.gaps_ms    = c.gaps_ms;

    v.contested       = static_cast<std::size_t>(c.contested);
    v.uncles_named    = static_cast<std::size_t>(c.uncles_named);
    v.uncles_resolved = static_cast<std::size_t>(c.uncles_resolved);
    v.monero_high     = c.monero_tpl_high;
    v.monero_heights  = static_cast<std::size_t>(c.monero_heights);

    v.peers_up    = static_cast<std::size_t>(c.peers_up);
    v.sockets     = static_cast<std::size_t>(c.sockets);
    v.peers_known = static_cast<std::size_t>(c.peers_known);
    v.gossiped    = static_cast<std::size_t>(c.gossiped);
    v.queued      = static_cast<std::size_t>(c.queued);

    v.distinct       = static_cast<std::size_t>(c.distinct);
    v.dupes          = static_cast<std::size_t>(c.dupes);
    v.parse_failures = static_cast<std::size_t>(c.parse_failures);
    v.broadcasts     = static_cast<std::size_t>(c.broadcasts);
    for (std::size_t i = 0; i < kControlMessageCount; ++i) {
        v.out.messages[i] = c.out_messages[i];
        v.out.bytes[i]    = c.out_bytes[i];
    }

    v.lifetime_tip_max    = c.lifetime.tip_height_max;
    v.lifetime_monero_max = c.lifetime.monero_tpl_max;

    // THE SAME CLASSIFIER AS A LIVE PANEL, at the reader's clock. The status
    // word on a restored panel is therefore not the word that was saved: it is
    // what that data means NOW, which is the only reading that is not a lie.
    v.status = classify(v.fresh, v.peers_up, v.sockets, v.queued, v.cadence_ok,
                        v.target_s, now_ms);
    v.tip_age_ms = v.fresh.tip_age_ms(now_ms);
    v.rx_age_ms  = v.fresh.rx_age_ms(now_ms);
    v.status_age_known = true;
    if (v.status == tui::ChainStatus::Down)
        v.status_age_ms = v.fresh.down_ms(now_ms);
    else if (v.status == tui::ChainStatus::Dark || v.status == tui::ChainStatus::Dialling)
        v.status_age_ms = FreshnessView::age(now_ms, v.fresh.started_at_ms);
    else
        v.status_age_ms = v.tip_age_ms;
    return v;
}

inline tui::MonitorFrame frame_of(const MonitorState& s, std::uint64_t now_ms) {
    tui::MonitorFrame f;
    f.elapsed_ms  = s.elapsed_ms;
    f.interactive = false;
    f.from_file   = true;
    f.file_age_ms = FreshnessView::age(now_ms, s.written_at_ms);
    for (const ChainState& c : s.chains) {
        tui::ChainView v = chain_view_of(c, now_ms);
        v.data_age_ms = f.file_age_ms;
        if (v.lifetime_tip_max) {
            v.carried             = true;
            v.carry_written_at_ms = s.written_at_ms;
            v.carry_age_ms        = f.file_age_ms;
            v.carry_tip_height    = c.tip_height;
            v.carry_tip_id8       = c.tip_id.size() >= 8 ? c.tip_id.substr(0, 8) : std::string();
        }
        f.chains.push_back(v);
    }
    f.persist.enabled         = true;
    f.persist.seq             = s.seq;
    f.persist.ever_saved      = true;
    f.persist.saved_age_ms    = f.file_age_ms;
    f.persist.errors          = static_cast<std::size_t>(s.persist.errors);
    f.persist.last_error      = s.persist.last_error;
    f.persist.loop_stall_max_ms = s.persist.loop_stall_max_ms;
    f.persist.sessions        = s.lifetime.sessions;
    f.persist.runtime_ms_total = s.lifetime.runtime_ms_total;
    f.persist.restored        = true;
    f.persist.restored_age_ms = f.file_age_ms;
    return f;
}

} // namespace c2pool::xmr::p2pool::state
