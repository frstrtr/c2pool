// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/parity/xmr_txpool_parity.hpp
//
// M1: P-POOL -- the native relayed txpool against monerod's own, transaction by
// transaction.
//
// THE CLAIM. Every transaction both pools hold agrees on {id, weight, fee,
// blob_size}, where our side of it was built from bytes that arrived over levin
// NOTIFY_NEW_TRANSACTIONS and were decoded, weighed and priced by C3 -- and
// monerod's side is the daemon's own answer to get_transaction_pool. No part of
// our number came from the daemon. That is the whole of M1: the pool a template
// is built from is arithmetic we do ourselves and can be held to.
//
// WHY THE ID IS THE ALIGNMENT KEY AND NOT A COMPARED FIELD. A Monero v2
// transaction id is the triple Keccak over the three measured byte spans that
// make up the blob, so two pools reporting the same id are holding the same
// bytes. Using it as the key is therefore stronger than comparing it: it turns
// the other three fields from "three numbers that happen to match" into three
// independent derivations from one agreed input. It also means blob EQUALITY is
// implied rather than asserted, which is why this seam does not ship a blob
// digest field it would have to defend.
//
// THE SET PROBLEM, AND WHY IT IS NOT SWEPT UNDER A MEASUREMENT. Two pools are
// never identical at an instant: a transaction submitted to the daemon is in
// its pool before it has reached us, and one relayed to us in a stem phase may
// not be in the daemon's. Scoring that as parity failure would make the seam
// fail on propagation, so the per-transaction comparison runs over the
// INTERSECTION and the two set differences are carried as measurements.
//
// That is exactly the shape of the DASH shadow-compare blind spot -- a
// comparison that reports agreement because it compared nothing -- so it is
// paid for here, at the level above the sample, by TxpoolParityTally:
//
//   * every id ever seen in the DAEMON's pool is remembered;
//   * every id ever actually compared is remembered;
//   * `never_compared()` is the difference, and it is a MILESTONE GATE.
//
// A set difference that closes is propagation. A set difference that never
// closes is an uncompared transaction, and it is visible as one. An empty
// intersection yields NO samples and is reported as NoSamples, never as a
// clean run -- the tally counts `empty_samples` for exactly that reason.
//
// WHAT IS DELIBERATELY NOT COMPARED. monerod's tx_info also carries
// receive_time, relayed, do_not_relay, last_relayed_time, kept_by_block,
// double_spend_seen and max_used_block_*. Every one of them is either a local
// observation (when did THIS node first see it) or a fact about a history our
// pool does not carry; none of them is an input to a block template. Listing
// them here as absent-by-design is how that stays a decision rather than an
// omission somebody re-files.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/.
//
// Header-only. STL plus the node's minijson and monerod transport.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/parity/xmr_parity_comparator.hpp"
#include "impl/xmr/native/parity/xmr_parity_sources.hpp"   // mj, obs_u64, read_hash
#include "impl/xmr/native/parity/xmr_parity_types.hpp"
#include "impl/xmr/node/minijson.hpp"
#include "impl/xmr/node/monerod_transport.hpp"

namespace c2pool::xmr::native::parity {

// ---------------------------------------------------------------------------
// One transaction as one arm measured it.
//
// Everything but the id is an Obs, so "the daemon stopped returning weight" is
// a hole the comparator can see rather than a zero it would happily match
// against another zero.
// ---------------------------------------------------------------------------
struct PoolTxObs {
    Hash id{};
    Obs  weight    = Obs::absent();
    Obs  fee       = Obs::absent();
    Obs  blob_size = Obs::absent();
    // Measurements: the daemon has no equivalent of either, so they are here to
    // be READ, never to be matched.
    Obs  peers    = Obs::absent();
    Obs  evidence = Obs::absent();
};

// ---------------------------------------------------------------------------
// One arm's whole pool at one instant.
//
// `have` is the difference between "this arm answered" and "this arm holds
// nothing". An arm that could not answer produces no samples and no set
// differences; an arm that answered with an empty pool produces no samples and
// a set difference that is entirely the other arm's. Those are different facts
// and they are kept different.
// ---------------------------------------------------------------------------
struct PoolSnapshot {
    bool                   have = false;
    std::string            arm;
    std::string            why;     // when !have
    std::vector<PoolTxObs> txs;

    const PoolTxObs* find(const Hash& id) const {
        for (const PoolTxObs& t : txs) if (t.id == id) return &t;
        return nullptr;
    }
};

inline PoolSnapshot no_pool_observation(const char* arm, std::string why) {
    PoolSnapshot s;
    s.arm = arm;
    s.why = std::move(why);
    return s;
}

// ---------------------------------------------------------------------------
// monerod: /get_transaction_pool
//
// NOT under /json_rpc -- MonerodHttp::json_rpc_method_ already knows that, and
// the body carries the method name so the transport can route it.
//
// The response also carries tx_blob (hex) and tx_json (an escaped JSON document)
// per transaction, which on a busy pool is megabytes of text this seam has no
// use for. There is no field filter on this endpoint in monerod 0.18, so the
// cost is paid and the parse simply ignores both -- worth knowing before this
// probe is pointed at mainnet with a one-second cadence.
// ---------------------------------------------------------------------------
struct MonerodTxpoolRpc {
    static std::string body() {
        return "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_transaction_pool\"}";
    }

    static PoolSnapshot parse(const char* data, std::size_t n) {
        PoolSnapshot s;
        s.arm = "monerod";
        mj::Value root;
        if (!mj::parse(data, n, root) || !root.is_object()) {
            s.why = "get_transaction_pool: not JSON";
            return s;
        }
        // This endpoint answers at the TOP level, not under "result".
        const mj::Value& r = root.obj.count("result") ? root["result"] : root;
        const std::string status = r["status"].as_string();
        if (status != "OK") {
            s.why = "get_transaction_pool: status '" + status + "'";
            return s;
        }
        const mj::Value& list = r["transactions"];
        // An ABSENT "transactions" key is what monerod emits for an empty pool,
        // so it is an answer of "nothing", not a failure to answer. A present
        // key of the wrong type IS a failure.
        if (!list.is_array()) {
            if (list.type != mj::Type::Null) {
                s.why = "get_transaction_pool: 'transactions' is not an array";
                return s;
            }
            s.have = true;
            return s;
        }
        for (const mj::Value& t : list.arr) {
            PoolTxObs o;
            if (!read_hash(t["id_hash"], o.id)) {
                s.why = "get_transaction_pool: an entry has no usable id_hash";
                s.txs.clear();
                return s;                       // a pool we cannot key is not a pool
            }
            o.weight    = obs_u64(t["weight"]);
            o.fee       = obs_u64(t["fee"]);
            o.blob_size = obs_u64(t["blob_size"]);
            s.txs.push_back(std::move(o));
        }
        s.have = true;
        return s;
    }

    static PoolSnapshot parse(const std::vector<char>& b) { return parse(b.data(), b.size()); }
};

// ---------------------------------------------------------------------------
// One transaction, as the seam table wants it.
//
// height / prev_id are the TIP BOTH ARMS WERE AT when the two pools were read.
// They are not properties of the transaction; they are what makes the sample
// re-readable afterwards, and they are what the comparator's own alignment
// check runs on before it ever looks at a field.
// ---------------------------------------------------------------------------
inline ArmObservation pool_tx_observation(const char* arm, std::uint64_t height,
                                          const Hash& prev_id, const PoolTxObs& t) {
    ArmObservation o;
    o.arm     = arm;
    o.have    = true;
    o.height  = height;
    o.prev_id = prev_id;
    o.fields.set("tx_id",     Obs::id(t.id));
    o.fields.set("weight",    t.weight);
    o.fields.set("fee",       t.fee);
    o.fields.set("blob_size", t.blob_size);
    o.fields.set("peers",     t.peers);
    o.fields.set("evidence",  t.evidence);
    return o;
}

// ---------------------------------------------------------------------------
// One comparison of two whole pools.
// ---------------------------------------------------------------------------
struct TxpoolParityReport {
    bool          judged = false;        // both arms answered
    std::string   why;                   // when !judged
    std::uint64_t height = 0;
    Hash          prev_id{};

    std::vector<SeamResult> samples;     // one per intersection transaction

    std::vector<Hash> ours_only;         // in the native pool, not in monerod's
    std::vector<Hash> theirs_only;       // in monerod's pool, not in ours

    // The ids this report actually judged, and the ones that did not come out
    // CLEAN. They are carried explicitly rather than dug back out of the
    // samples: the id is an ALIGNMENT KEY, so a matching sample records it
    // nowhere, and a coverage claim that could only see the ids that DIFFERED
    // would be the same blindness the seam exists to avoid.
    std::vector<Hash> compared_ids;
    std::vector<Hash> failed_ids;

    // Every id the NATIVE pool held at the capture, judged or not. An eviction
    // is a difference between two of these taken at two tips, so it has to be
    // the whole pool and not the part of it that happened to be comparable.
    std::vector<Hash> native_ids;

    std::size_t native_count  = 0;
    std::size_t monerod_count = 0;

    std::size_t clean = 0, fail = 0, voided = 0, served_mismatch = 0;
    std::size_t fields_compared = 0, fields_equal = 0, fields_differed = 0,
                fields_absent = 0;

    // Both pools held exactly the same set of ids: the moment at which the set
    // difference is not an excuse for anything.
    bool aligned() const noexcept { return ours_only.empty() && theirs_only.empty(); }
    bool all_equal() const noexcept {
        return fail == 0 && served_mismatch == 0 && fields_differed == 0 && fields_absent == 0;
    }
};

// ---------------------------------------------------------------------------
// compare_txpools -- the set comparison, then compare_seam per transaction.
//
// The per-transaction judgement is NOT re-implemented here: it goes through the
// same compare_seam that judges P-TIP and P-TPL, with the same non-vacuity rule
// (a sample reaches CLEAN only if every required EQUALITY field was answered by
// both arms and matched). Writing a second comparator for this seam would mean
// the M1 claim rested on a judge nobody had audited.
// ---------------------------------------------------------------------------
inline TxpoolParityReport compare_txpools(const PoolSnapshot&     native,
                                          const PoolSnapshot&     monerod,
                                          std::uint64_t           height,
                                          const Hash&             prev_id,
                                          const ClassifierInputs& classes = {}) {
    TxpoolParityReport rep;
    rep.height  = height;
    rep.prev_id = prev_id;

    if (!native.have) {
        rep.why = "no observation from the native pool"
                + (native.why.empty() ? std::string() : (": " + native.why));
        return rep;
    }
    if (!monerod.have) {
        rep.why = "no observation from monerod's pool"
                + (monerod.why.empty() ? std::string() : (": " + monerod.why));
        return rep;
    }

    rep.judged        = true;
    rep.native_count  = native.txs.size();
    rep.monerod_count = monerod.txs.size();

    // Index the daemon side once; a pool is an unordered set on both sides and
    // a quadratic walk over a mainnet pool would put this probe on a hot path
    // it is forbidden from being on.
    std::map<Hash, const PoolTxObs*> theirs;
    for (const PoolTxObs& t : monerod.txs) theirs.emplace(t.id, &t);

    std::set<Hash> ours;
    rep.native_ids.reserve(native.txs.size());
    for (const PoolTxObs& t : native.txs) {
        ours.insert(t.id);
        rep.native_ids.push_back(t.id);
        auto it = theirs.find(t.id);
        if (it == theirs.end()) {
            rep.ours_only.push_back(t.id);
            continue;
        }
        CompareOptions opt;
        opt.classes = classes;
        const SeamResult r = compare_seam(POOL_SEAM,
                                          pool_tx_observation("native",  height, prev_id, t),
                                          pool_tx_observation("monerod", height, prev_id, *it->second),
                                          opt);
        rep.fields_compared += r.equality_compared;
        rep.fields_equal    += r.equality_equal;
        rep.fields_differed += r.equality_differed;
        rep.fields_absent   += r.equality_absent;
        switch (r.sample.verdict) {
            case ParityVerdict::Clean:          ++rep.clean;           break;
            case ParityVerdict::Fail:           ++rep.fail;            break;
            case ParityVerdict::ServedMismatch: ++rep.served_mismatch; break;
            case ParityVerdict::Void:           ++rep.voided;          break;
        }
        // A VOID sample compared nothing, so it is not coverage. Only a sample
        // that was actually judged puts its id on the compared list.
        if (r.judged()) rep.compared_ids.push_back(t.id);
        if (r.sample.verdict != ParityVerdict::Clean) rep.failed_ids.push_back(t.id);
        rep.samples.push_back(r);
    }
    for (const auto& kv : theirs)
        if (ours.find(kv.first) == ours.end()) rep.theirs_only.push_back(kv.first);

    return rep;
}

// ---------------------------------------------------------------------------
// TxpoolParityTally -- the claim across a whole run.
//
// A per-sample verdict cannot carry M1's claim, because M1's claim is about
// COVERAGE as much as agreement: "every transaction the daemon's pool ever held
// was compared, and every comparison matched". The tally is where that is
// arithmetic rather than an impression.
//
// `never_compared()` is the load-bearing one. Ids enter `daemon_seen_` the
// moment the daemon reports them and leave nothing behind when the daemon's
// pool loses them, so a transaction that was mined or dropped before we ever
// saw it stays on the list forever. That is deliberate: it is exactly the
// transaction a pool-parity claim must not be allowed to skip past.
// ---------------------------------------------------------------------------
class TxpoolParityTally {
public:
    void add(const TxpoolParityReport& rep) {
        ++polls_;
        if (!rep.judged) { ++unjudged_; return; }
        ++samples_;
        if (rep.aligned()) ++aligned_samples_;
        if (rep.samples.empty()) ++empty_samples_;

        native_max_ = rep.native_count > native_max_ ? rep.native_count : native_max_;
        monerod_max_ = rep.monerod_count > monerod_max_ ? rep.monerod_count : monerod_max_;

        clean_ += rep.clean;
        fail_  += rep.fail;
        void_  += rep.voided;
        mismatch_ += rep.served_mismatch;
        fields_compared_ += rep.fields_compared;
        fields_equal_    += rep.fields_equal;
        fields_differed_ += rep.fields_differed;
        fields_absent_   += rep.fields_absent;

        // Everything the DAEMON held, whether or not we had it yet. This is the
        // set the coverage claim is made against.
        for (const Hash& h : rep.theirs_only)  daemon_seen_.insert(h);
        for (const Hash& h : rep.compared_ids) { daemon_seen_.insert(h); compared_.insert(h); }
        // A VOID intersection id is one the daemon HELD and the comparator
        // could not judge. It is not in compared_ids by construction, and it is
        // not in theirs_only either, so without this line it would be in
        // neither set -- invisible to the coverage claim. failed_ids carries
        // every non-CLEAN verdict, VOID included, which is exactly the set that
        // needs remembering.
        for (const Hash& h : rep.failed_ids) { daemon_seen_.insert(h); failed_ids_.insert(h); }
    }

    std::vector<Hash> never_compared() const {
        std::vector<Hash> out;
        for (const Hash& h : daemon_seen_)
            if (compared_.find(h) == compared_.end()) out.push_back(h);
        return out;
    }

    std::uint64_t polls()           const noexcept { return polls_; }
    std::uint64_t samples()         const noexcept { return samples_; }
    std::uint64_t unjudged()        const noexcept { return unjudged_; }
    std::uint64_t aligned_samples() const noexcept { return aligned_samples_; }
    std::uint64_t empty_samples()   const noexcept { return empty_samples_; }
    std::uint64_t clean()           const noexcept { return clean_; }
    std::uint64_t failed()          const noexcept { return fail_; }
    std::uint64_t voided()          const noexcept { return void_; }
    std::uint64_t served_mismatch() const noexcept { return mismatch_; }
    std::uint64_t fields_compared() const noexcept { return fields_compared_; }
    std::uint64_t fields_equal()    const noexcept { return fields_equal_; }
    std::uint64_t fields_differed() const noexcept { return fields_differed_; }
    std::uint64_t fields_absent()   const noexcept { return fields_absent_; }
    std::size_t   distinct_txs_compared() const noexcept { return compared_.size(); }
    std::size_t   distinct_daemon_ids()   const noexcept { return daemon_seen_.size(); }
    std::size_t   native_pool_max()  const noexcept { return native_max_; }
    std::size_t   monerod_pool_max() const noexcept { return monerod_max_; }

    // Distinct transactions that came out of the comparator as anything other
    // than CLEAN, so a report can name them instead of only counting them.
    std::vector<Hash> failed_ids() const {
        return std::vector<Hash>(failed_ids_.begin(), failed_ids_.end());
    }

    // NO DISAGREEMENT. Weaker than passes() on purpose: it says only that
    // nothing the comparator DID judge came out wrong. It makes no claim about
    // how much was judged, so it can never stand in for the parity gate -- it
    // is what a SCENARIO run (one that exists to prove an eviction, not
    // coverage) is allowed to assert, and the caller has to say which it is.
    bool no_disagreement(std::string& why) const {
        if (fail_ != 0 || mismatch_ != 0) { why = "a transaction failed parity"; return false; }
        if (fields_differed_ != 0)        { why = "a field differed"; return false; }
        if (fields_absent_ != 0)          { why = "a required field was not answered"; return false; }
        why.clear();
        return true;
    }

    // The M1 gate, in one predicate so that nothing can pass it by accident.
    //
    // `min_txs` is the milestone's own floor on distinct transactions: a run
    // that compared three transactions perfectly has proven very little.
    //
    // `allow_uncompared` is the ONE deliberate hole, and it is an argument
    // rather than a tolerance so that every use of it has to be written down at
    // the call site. It exists for a scenario that holds a divergence on
    // purpose -- the key-image conflict proof puts a twin in OUR pool and the
    // original in the DAEMON's, so exactly one daemon id is expected never to
    // become comparable. Every other run passes zero, and a scenario that
    // passes more than it can name is a scenario that has stopped proving
    // anything.
    bool passes(std::size_t min_txs, std::size_t allow_uncompared, std::string& why) const {
        if (samples_ == 0)                { why = "no judged pool sample"; return false; }
        if (compared_.size() < min_txs) {
            why = "only " + std::to_string(compared_.size())
                + " distinct transactions compared, floor is " + std::to_string(min_txs);
            return false;
        }
        if (fields_compared_ == 0)        { why = "no field was ever compared"; return false; }
        if (fail_ != 0 || mismatch_ != 0) { why = "a transaction failed parity"; return false; }
        if (fields_differed_ != 0)        { why = "a field differed"; return false; }
        if (fields_absent_ != 0)          { why = "a required field was not answered"; return false; }
        const std::vector<Hash> missed = never_compared();
        if (missed.size() > allow_uncompared) {
            why = std::to_string(missed.size())
                + " id(s) the daemon's pool held were never compared, allowance is "
                + std::to_string(allow_uncompared);
            return false;
        }
        if (aligned_samples_ == 0) {
            why = "the two pools never held the same set of ids at one instant";
            return false;
        }
        why.clear();
        return true;
    }

private:
    std::uint64_t polls_ = 0, samples_ = 0, unjudged_ = 0;
    std::uint64_t aligned_samples_ = 0, empty_samples_ = 0;
    std::uint64_t clean_ = 0, fail_ = 0, void_ = 0, mismatch_ = 0;
    std::uint64_t fields_compared_ = 0, fields_equal_ = 0, fields_differed_ = 0,
                  fields_absent_ = 0;
    std::size_t   native_max_ = 0, monerod_max_ = 0;
    std::set<Hash> daemon_seen_;
    std::set<Hash> compared_;
    std::set<Hash> failed_ids_;
};

// ---------------------------------------------------------------------------
// The daemon-side pool observer. Same split as MonerodTipObserver: poll() does
// the round trip on the owner's thread, observe() hands back the cache, and a
// probe never sits behind a network call on somebody else's thread.
// ---------------------------------------------------------------------------
class MonerodTxpoolObserver {
public:
    explicit MonerodTxpoolObserver(node::IMonerodTransport& tx) : tx_(tx) {}

    bool poll() {
        PoolSnapshot s = no_pool_observation("monerod", "transport did not answer");
        tx_.rpc_post(MonerodTxpoolRpc::body(), [&](const node::RpcResponse& r) {
            if (!r.ok()) { s.why = "transport: " + r.error; return; }
            s = MonerodTxpoolRpc::parse(r.body);
        });
        ++polls_;
        cached_ = std::move(s);
        if (!cached_.have) ++failures_;
        return cached_.have;
    }

    const PoolSnapshot& observe() const noexcept { return cached_; }
    std::uint64_t polls()    const noexcept { return polls_; }
    std::uint64_t failures() const noexcept { return failures_; }

private:
    node::IMonerodTransport& tx_;
    PoolSnapshot  cached_ = no_pool_observation("monerod", "not polled yet");
    std::uint64_t polls_ = 0, failures_ = 0;
};

} // namespace c2pool::xmr::native::parity
