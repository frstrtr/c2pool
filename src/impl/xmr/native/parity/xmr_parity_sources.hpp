// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/parity/xmr_parity_sources.hpp
//
// C6, the intake: turning what each arm can say into ArmObservations.
//
// Three sources, one shape:
//   * the NATIVE tip, read off C2c's ChainStateView (its ChainRow carries the
//     weights, the major version and the recomputed cumulative difficulty --
//     none of which are in a Monero block header, which is exactly why a pool
//     cannot SPV this and why the parity claim is worth making);
//   * the MONEROD tip, read off get_info AND get_last_block_header;
//   * a TEMPLATE, read off a node::MinerData -- the value type both C4 arms
//     already produce, so the template seam compares the two arms' actual
//     output rather than a re-derivation.
//
// WHY BOTH get_info AND get_last_block_header. They are two answers to the same
// question from one daemon, taken microseconds apart, and monerod's tip can move
// between them. If they disagree, the capture is INCOHERENT and yields NO
// observation -- which the comparator scores VOID. Reconciling them silently
// (say, by preferring one) would manufacture a tip that the daemon never
// reported, and every later "agreement" would be against that invention.
//
// ABSENCE IS PARSED, NOT DEFAULTED. Every field goes through obs_u64 / obs_hash,
// which return Obs::absent() when the JSON key is missing or of the wrong type.
// A daemon that stops returning `long_term_weight` must make the sample FAIL,
// not silently compare 0 == 0.
//
// SCOPE FENCE: src/impl/xmr/ only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "impl/xmr/native/chain/xmr_chain_view.hpp"
#include "impl/xmr/native/parity/xmr_parity_types.hpp"
#include "impl/xmr/node/minijson.hpp"
#include "impl/xmr/node/monerod_transport.hpp"

namespace c2pool::xmr::native::parity {

namespace mj = ::c2pool::xmr::node::minijson;

// ---------------------------------------------------------------------------
// presence-preserving readers
// ---------------------------------------------------------------------------
inline Obs obs_u64(const mj::Value& v) {
    return v.is_number() ? Obs::u64(v.as_u64()) : Obs::absent();
}

inline Obs obs_hash(const mj::Value& v) {
    if (!v.is_string() || v.as_string().size() != 64) return Obs::absent();
    Hash h{};
    if (!mj::hex_to_hash(v.as_string(), h)) return Obs::absent();
    return Obs::id(h);
}

inline bool read_hash(const mj::Value& v, Hash& out) {
    if (!v.is_string() || v.as_string().size() != 64) return false;
    return mj::hex_to_hash(v.as_string(), out);
}

// "0xc45ab9090f" -> U128. monerod's wide_* fields are the authoritative width;
// the paired lo/top64 numbers are the compatibility spelling.
inline bool parse_wide_hex(const std::string& s, U128& out) {
    if (s.size() < 3 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) return false;
    U128 v{};
    for (std::size_t i = 2; i < s.size(); ++i) {
        int d;
        const char c = s[i];
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return false;
        if (v.hi >> 60) return false;                       // would overflow 128 bits
        v.hi = (v.hi << 4) | (v.lo >> 60);
        v.lo = (v.lo << 4) | static_cast<std::uint64_t>(d);
    }
    out = v;
    return true;
}

// A 128-bit quantity as monerod spells it: prefer the wide hex, fall back to
// the lo/top64 pair, and report absence when neither is there.
inline Obs obs_u128(const mj::Value& parent, const char* wide_key,
                    const char* lo_key, const char* hi_key) {
    const mj::Value& w = parent[wide_key];
    U128 v{};
    if (w.is_string() && parse_wide_hex(w.as_string(), v)) return Obs::u128(v);
    const mj::Value& lo = parent[lo_key];
    if (!lo.is_number()) return Obs::absent();
    v.lo = lo.as_u64();
    v.hi = parent[hi_key].is_number() ? parent[hi_key].as_u64() : 0;
    return Obs::u128(v);
}

// ---------------------------------------------------------------------------
// The two monerod tip calls.
// ---------------------------------------------------------------------------
struct MonerodTipRpc {
    static std::string body_get_info() {
        return "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_info\"}";
    }
    static std::string body_get_last_block_header() {
        return "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_last_block_header\"}";
    }

    struct InfoView {
        bool          ok = false;
        std::uint64_t height = 0;            // == tip + 1
        Hash          top_block_hash{};
        Obs           cumulative_difficulty = Obs::absent();
        Obs           difficulty            = Obs::absent();
        bool          synchronized = false;
        std::string   version;
        std::string   nettype;
        std::string   why;
    };

    static InfoView parse_info(const char* data, std::size_t n) {
        InfoView v;
        mj::Value root;
        if (!mj::parse(data, n, root) || !root.is_object()) { v.why = "get_info: not JSON"; return v; }
        const mj::Value& r = root["result"];
        if (!r.is_object()) { v.why = "get_info: no result object"; return v; }
        if (r["status"].as_string() != "OK") {
            v.why = "get_info: status '" + r["status"].as_string() + "'";
            return v;
        }
        if (!r["height"].is_number()) { v.why = "get_info: no height"; return v; }
        v.height = r["height"].as_u64();
        if (!read_hash(r["top_block_hash"], v.top_block_hash)) {
            v.why = "get_info: no top_block_hash";
            return v;
        }
        v.cumulative_difficulty =
            obs_u128(r, "wide_cumulative_difficulty", "cumulative_difficulty",
                     "cumulative_difficulty_top64");
        v.difficulty = obs_u128(r, "wide_difficulty", "difficulty", "difficulty_top64");
        v.synchronized = r["synchronized"].as_bool(false);
        v.version      = r["version"].as_string();
        v.nettype      = r["nettype"].as_string();
        v.ok = true;
        return v;
    }
    static InfoView parse_info(const std::vector<char>& b) { return parse_info(b.data(), b.size()); }

    struct HeaderView {
        bool          ok = false;
        std::uint64_t height = 0;
        Hash          id{};
        Hash          prev_id{};
        Obs           timestamp             = Obs::absent();
        Obs           difficulty            = Obs::absent();
        Obs           cumulative_difficulty = Obs::absent();
        Obs           reward                = Obs::absent();
        Obs           block_weight          = Obs::absent();
        Obs           long_term_weight      = Obs::absent();
        Obs           major_version         = Obs::absent();
        Obs           minor_version         = Obs::absent();
        Obs           num_txes              = Obs::absent();
        std::string   why;
    };

    static HeaderView parse_block_header(const char* data, std::size_t n) {
        HeaderView v;
        mj::Value root;
        if (!mj::parse(data, n, root) || !root.is_object()) { v.why = "block header: not JSON"; return v; }
        const mj::Value& r = root["result"];
        if (!r.is_object()) { v.why = "block header: no result object"; return v; }
        if (r["status"].as_string() != "OK") {
            v.why = "block header: status '" + r["status"].as_string() + "'";
            return v;
        }
        const mj::Value& h = r["block_header"];
        if (!h.is_object()) { v.why = "block header: no block_header object"; return v; }
        if (!h["height"].is_number()) { v.why = "block header: no height"; return v; }
        v.height = h["height"].as_u64();
        if (!read_hash(h["hash"], v.id))          { v.why = "block header: no hash"; return v; }
        if (!read_hash(h["prev_hash"], v.prev_id)) { v.why = "block header: no prev_hash"; return v; }
        v.timestamp        = obs_u64(h["timestamp"]);
        v.difficulty       = obs_u128(h, "wide_difficulty", "difficulty", "difficulty_top64");
        v.cumulative_difficulty =
            obs_u128(h, "wide_cumulative_difficulty", "cumulative_difficulty",
                     "cumulative_difficulty_top64");
        v.reward           = obs_u64(h["reward"]);
        v.block_weight     = obs_u64(h["block_weight"]);
        v.long_term_weight = obs_u64(h["long_term_weight"]);
        v.major_version    = obs_u64(h["major_version"]);
        v.minor_version    = obs_u64(h["minor_version"]);
        v.num_txes         = obs_u64(h["num_txes"]);
        v.ok = true;
        return v;
    }
    static HeaderView parse_block_header(const std::vector<char>& b) {
        return parse_block_header(b.data(), b.size());
    }
};

// ---------------------------------------------------------------------------
// Assembling the observations.
// ---------------------------------------------------------------------------

// The monerod tip, from the two answers, ONLY if they describe the same tip.
inline ArmObservation monerod_tip_observation(const MonerodTipRpc::InfoView&  info,
                                              const MonerodTipRpc::HeaderView& hdr) {
    ArmObservation o;
    o.arm = "monerod";
    if (!info.ok)  { o.why = info.why; return o; }
    if (!hdr.ok)   { o.why = hdr.why;  return o; }
    if (info.height != hdr.height + 1) {
        o.why = "incoherent capture: get_info height " + Obs::u64(info.height).value
              + " but get_last_block_header height " + Obs::u64(hdr.height).value;
        return o;
    }
    if (info.top_block_hash != hdr.id) {
        o.why = "incoherent capture: get_info top_block_hash is not the header's hash "
                "(the daemon's tip moved between the two calls)";
        return o;
    }

    o.have    = true;
    o.height  = hdr.height;
    o.prev_id = hdr.prev_id;
    o.fields.set("id",                    Obs::id(hdr.id));
    o.fields.set("prev_id",               Obs::id(hdr.prev_id));
    // The header's own number, cross-checked against get_info: if THOSE two
    // disagree the daemon is inconsistent with itself, and the sample is void.
    o.fields.set("cumulative_difficulty", hdr.cumulative_difficulty);
    o.fields.set("difficulty",            hdr.difficulty);
    o.fields.set("timestamp",             hdr.timestamp);
    o.fields.set("reward",                hdr.reward);
    o.fields.set("block_weight",          hdr.block_weight);
    o.fields.set("long_term_weight",      hdr.long_term_weight);
    o.fields.set("major_version",         hdr.major_version);

    if (info.cumulative_difficulty.present && hdr.cumulative_difficulty.present
        && info.cumulative_difficulty.value != hdr.cumulative_difficulty.value) {
        o.have = false;
        o.why  = "incoherent capture: get_info cumulative_difficulty "
               + info.cumulative_difficulty.value + " but header "
               + hdr.cumulative_difficulty.value;
    }
    return o;
}

// The native tip, straight off a C2c row. Everything the table asks for is a
// column of the row, which is the whole claim: the native index carries the
// chain STATE, not just the headers.
inline ArmObservation native_tip_observation(const ChainRow& row) {
    ArmObservation o;
    o.arm     = "native";
    o.have    = true;
    o.height  = row.height;
    o.prev_id = row.prev_id;
    o.fields.set("id",                    Obs::id(row.id));
    o.fields.set("prev_id",               Obs::id(row.prev_id));
    o.fields.set("cumulative_difficulty", Obs::u128(row.cumulative_difficulty));
    o.fields.set("difficulty",            Obs::u128(row.difficulty));
    o.fields.set("timestamp",             Obs::u64(row.timestamp));
    o.fields.set("reward",                Obs::u64(row.reward));
    o.fields.set("block_weight",          Obs::u64(row.block_weight));
    o.fields.set("long_term_weight",      Obs::u64(row.long_term_weight));
    o.fields.set("major_version",         Obs::u64(row.major_version));
    return o;
}

// A template, from the MinerData an arm produced.
//
// median_timestamp: monerod's get_miner_data does not return it, so a zero here
// means "this arm does not report the field", not "the median is zero". It is a
// CONSTRAINT in the table for exactly that reason, and it is left ABSENT rather
// than rendered as 0 so nothing can ever compare two absences and call it equal.
inline ArmObservation template_observation(const char* arm, const node::MinerData& md) {
    ArmObservation o;
    o.arm     = arm;
    o.have    = true;
    o.height  = md.height;
    o.prev_id = md.prev_id;
    o.fields.set("prev_id",                 Obs::id(md.prev_id));
    o.fields.set("major_version",           Obs::u64(md.major_version));
    o.fields.set("difficulty",              Obs::u128(md.difficulty));
    o.fields.set("seed_hash",               Obs::id(md.seed_hash));
    o.fields.set("median_weight",           Obs::u64(md.median_weight));
    o.fields.set("already_generated_coins", Obs::u64(md.already_generated_coins));
    o.fields.set("median_timestamp",
                 md.median_timestamp != 0 ? Obs::u64(md.median_timestamp) : Obs::absent());
    o.fields.set("tx_backlog_count", Obs::u64(static_cast<std::uint64_t>(md.tx_backlog.size())));
    return o;
}

inline ArmObservation no_observation(const char* arm, std::string why) {
    ArmObservation o;
    o.arm = arm;
    o.why = std::move(why);
    return o;
}

// ---------------------------------------------------------------------------
// ITipObserver -- what the oracle pulls a tip from.
//
// A tip EVENT says something moved; the oracle then asks both sides what they
// see. That indirection is what lets one side be an RPC round trip and the
// other a struct read without either knowing about the other.
// ---------------------------------------------------------------------------
class ITipObserver {
public:
    virtual ~ITipObserver() = default;
    virtual ArmObservation observe() = 0;
};

// The native side. Cheap: it reads the row the verify thread already built.
class ChainViewTipObserver final : public ITipObserver {
public:
    explicit ChainViewTipObserver(const ChainStateView& view) : view_(view) {}

    ArmObservation observe() override {
        const ChainRow* t = view_.state().tip();
        if (t == nullptr) return no_observation("native", "native index has no tip yet");
        if (!view_.sync_state().synced)
            return no_observation("native", "native index is not synced (fail-closed)");
        return native_tip_observation(*t);
    }

    // For the height classifier: the effective median the tip was judged under.
    std::uint64_t effective_median() const { return view_.state().effective_median_weight(); }

private:
    const ChainStateView& view_;
};

// The monerod side. `poll()` issues the two calls and caches the result;
// `observe()` returns the cache. The split exists for the same reason it does
// on MonerodMinerDataSource: a network round trip must never sit behind a call
// the oracle makes on someone else's thread.
class MonerodTipObserver final : public ITipObserver {
public:
    explicit MonerodTipObserver(node::IMonerodTransport& tx) : tx_(tx) {}

    bool poll() {
        MonerodTipRpc::InfoView   info;
        MonerodTipRpc::HeaderView hdr;
        bool got_info = false, got_hdr = false;

        tx_.rpc_post(MonerodTipRpc::body_get_info(), [&](const node::RpcResponse& r) {
            if (!r.ok()) { info.why = "transport: " + r.error; return; }
            info = MonerodTipRpc::parse_info(r.body);
            got_info = info.ok;
        });
        tx_.rpc_post(MonerodTipRpc::body_get_last_block_header(), [&](const node::RpcResponse& r) {
            if (!r.ok()) { hdr.why = "transport: " + r.error; return; }
            hdr = MonerodTipRpc::parse_block_header(r.body);
            got_hdr = hdr.ok;
        });

        ++polls_;
        cached_ = monerod_tip_observation(info, hdr);
        if (got_info) daemon_version_ = info.version;
        if (got_info) nettype_ = info.nettype;
        if (got_info) synchronized_ = info.synchronized;
        if (!cached_.have) ++failures_;
        return cached_.have;
    }

    ArmObservation observe() override { return cached_; }

    const std::string& daemon_version() const noexcept { return daemon_version_; }
    const std::string& nettype()        const noexcept { return nettype_; }
    bool               synchronized()   const noexcept { return synchronized_; }
    std::uint64_t      polls()          const noexcept { return polls_; }
    std::uint64_t      failures()       const noexcept { return failures_; }

private:
    node::IMonerodTransport& tx_;
    ArmObservation cached_ = no_observation("monerod", "not polled yet");
    std::string    daemon_version_;
    std::string    nettype_;
    bool           synchronized_ = false;
    std::uint64_t  polls_ = 0, failures_ = 0;
};

} // namespace c2pool::xmr::native::parity
