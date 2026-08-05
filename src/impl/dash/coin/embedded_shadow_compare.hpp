// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DASH Embedded-vs-dashd block-template SHADOW-COMPARE DIAGNOSTIC
/// (--embedded-shadow-compare).
///
/// ══ WHAT THIS IS (and, emphatically, WHAT IT IS NOT) ════════════════════════
/// A pure OBSERVABILITY probe. On every block-template SERVE resolution (the
/// same trigger that produces the template a miner mines) it best-effort obtains
/// dashd's getblocktemplate for the SAME height and field-compares the two, then
/// LOGS one self-describing [SHADOW] line and bumps a counter. That is the whole
/// contract.
///
/// THIS IS NOT A SERVE GATE. It never selects, blocks, delays, re-orders, or
/// alters the template that gets served. It is deliberately SEPARATE from the
/// EmbeddedOracleShadow graduation gate (embedded_oracle_shadow.hpp): that one is
/// tip-triggered and drives a revocable "safe to disable dashd" verdict; THIS one
/// is serve-triggered, keeps no graduation state, and makes no claim beyond "at
/// height H, the field-by-field diff between what we served and what dashd would
/// have served looks like <X>". A [SHADOW] MISMATCH is DIAGNOSTIC EVIDENCE, not
/// proof of a bad served block (see the SEMANTIC note below).
///
/// ══ HOT-PATH DISCIPLINE (hard invariant) ════════════════════════════════════
/// The dashd oracle fetch is ALWAYS off the miner-facing path. on_serve() only
/// ENQUEUES a copy of the just-resolved template (coalescing to the newest) and
/// returns; a dedicated worker thread runs the dashd RPC + compare + log. The
/// serve path therefore NEVER waits on the oracle: if dashd is slow, hung, or
/// absent the miner-facing response is completely unaffected and the worker
/// simply logs `no-oracle` for that sample. Nothing this class does can add
/// latency to, or change the bytes of, the served template.
///
/// ══ DEFAULT OFF / DAEMONLESS ════════════════════════════════════════════════
/// Only meaningful when a dashd RPC oracle is reachable (the getblocktemplate
/// closure is bound). In pure-daemonless production no oracle is bound, so the
/// probe is never constructed and this is a strict no-op. Flag-gated
/// (--embedded-shadow-compare), default false.
///
/// ══ SEMANTIC — why a MISMATCH is not a served-block bug ══════════════════════
/// Two legitimate ways the compare can diverge WITHOUT anything wrong being
/// served:
///   (1) The fail-closed serve gate may have REFUSED the embedded arm at this
///       height (source == DashdFallback). Then the embedded fields we log are a
///       template that was NEVER served — a divergence here proves the gate did
///       its job, not that a bad block went out.
///   (2) dashd's template can legitimately differ in TX SELECTION (separate
///       mempool), which perturbs fee-dependent amounts and the tx-set. Those are
///       NOT validity-bearing for the coinbase-commitment fields.
/// The single high-value signal — the ONLY combination that would indicate a real
/// validity problem — is: the embedded arm was SERVED (not refused) at height H
/// AND a CONSENSUS-COMMITMENT field (coinbase payee, merkleRootMNList, or
/// merkleRootQuorums) diverged from dashd. That combination is surfaced
/// distinctly as `[SHADOW] h=H SERVED-MISMATCH ...` so it stands out from the
/// benign mismatch noise.
///
/// STRICTLY single-coin: src/impl/dash/coin/ only. Header-only so the pure
/// evaluate()/diff logic is KAT-pinnable without a live node or a thread.

#include <impl/dash/coin/work_source.hpp>       // WorkSource
#include <impl/dash/coin/rpc_data.hpp>          // DashWorkData, PackedPayment
#include <impl/dash/coin/vendor/cbtx.hpp>       // vendor::CCbTx, vendor::parse_cbtx

#include <core/log.hpp>

#include <nlohmann/json.hpp>

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

// ─────────────────────────────────────────────────────────────────────────────
// Pure comparison layer (no thread, no RPC, no node) — KAT-pinnable.
// ─────────────────────────────────────────────────────────────────────────────

/// One diverging field. `commitment` marks the consensus-commitment trio
/// (payee / merkleRootMNList / merkleRootQuorums) whose divergence — when the
/// embedded arm was SERVED — is the real-validity-problem signal.
struct ShadowFieldDiff {
    std::string field;
    std::string embedded;
    std::string dashd;
    bool        commitment{false};
};

/// The verdict for one served height.
struct ShadowOutcome {
    enum class Kind { NoOracle, Match, Mismatch };
    Kind                        kind{Kind::NoOracle};
    uint32_t                    height{0};
    bool                        served{false};   // source == WorkSource::Embedded
    std::string                 no_oracle_reason;
    std::vector<ShadowFieldDiff> diffs;          // diverging fields only
    bool                        served_mismatch{false}; // served && a commitment field diverged
    std::vector<std::string>    log_lines;        // the [SHADOW] lines, ready to emit
};

/// Counters, surfaced the way the existing gate markers surface: named tallies a
/// monitor/dashboard can read, plus a per-field breakdown keyed
/// "shadow-mismatch-<field>".
struct ShadowCounters {
    uint64_t shadow_match{0};
    uint64_t shadow_no_oracle{0};
    uint64_t shadow_served_mismatch{0};
    std::map<std::string, uint64_t> shadow_mismatch_by_field;   // field -> count

    void apply(const ShadowOutcome& o) {
        switch (o.kind) {
        case ShadowOutcome::Kind::NoOracle: shadow_no_oracle++; break;
        case ShadowOutcome::Kind::Match:    shadow_match++;     break;
        case ShadowOutcome::Kind::Mismatch:
            for (const auto& d : o.diffs) shadow_mismatch_by_field[d.field]++;
            if (o.served_mismatch) shadow_served_mismatch++;
            break;
        }
    }
    nlohmann::json to_json() const {
        nlohmann::json j;
        j["shadow-match"]           = shadow_match;
        j["shadow-no-oracle"]       = shadow_no_oracle;
        j["shadow-served-mismatch"] = shadow_served_mismatch;
        nlohmann::json byf = nlohmann::json::object();
        for (const auto& kv : shadow_mismatch_by_field)
            byf["shadow-mismatch-" + kv.first] = kv.second;
        j["shadow-mismatch-by-field"] = byf;
        return j;
    }
};

/// First non-platform-burn payee ("!6a" is the DASH platform credit-pool
/// OP_RETURN burn, not a real payee) — the masternode payee identity.
inline std::string shadow_mn_payee(const std::vector<PackedPayment>& pps) {
    for (const auto& p : pps)
        if (p.payee != "!6a") return p.payee;
    return "(none)";
}

/// Pure evaluate: given the SERVED template, whether the embedded arm produced it
/// (source), and dashd's template for the SAME height (nullopt == oracle
/// unavailable / did not arrive in time / tip-skew), produce the outcome + the
/// exact [SHADOW] log lines. No side effects: does not read or mutate anything
/// beyond its arguments, so a reviewer can see the served template is untouched.
inline ShadowOutcome shadow_evaluate(WorkSource source,
                                     const DashWorkData& embedded,
                                     const std::optional<DashWorkData>& dashd_opt) {
    ShadowOutcome o;
    o.height = embedded.m_height;
    o.served = (source == WorkSource::Embedded);

    if (!dashd_opt) {
        o.kind = ShadowOutcome::Kind::NoOracle;
        o.log_lines.push_back("[SHADOW] h=" + std::to_string(o.height) + " no-oracle");
        return o;
    }
    const DashWorkData& dashd = *dashd_opt;

    // Same-height alignment is a precondition to compare at all: a template for a
    // DIFFERENT height is not the oracle for THIS one. Treat tip-skew as
    // "no oracle for this height" rather than false-flagging every field.
    if (dashd.m_height != embedded.m_height) {
        o.kind = ShadowOutcome::Kind::NoOracle;
        o.no_oracle_reason = "tip-skew(dashd_h=" + std::to_string(dashd.m_height) + ")";
        o.log_lines.push_back("[SHADOW] h=" + std::to_string(o.height)
                              + " no-oracle reason=" + o.no_oracle_reason);
        return o;
    }

    auto add = [&](const char* field, bool commitment,
                   const std::string& e, const std::string& d) {
        if (e != d) o.diffs.push_back({field, e, d, commitment});
    };

    // ── Consensus-commitment trio (validity-bearing for the SERVED signal) ────
    add("payee", /*commitment=*/true,
        shadow_mn_payee(embedded.m_packed_payments),
        shadow_mn_payee(dashd.m_packed_payments));

    vendor::CCbTx ecb, dcb;
    const bool eok = vendor::parse_cbtx(embedded.m_coinbase_payload, ecb);
    const bool dok = vendor::parse_cbtx(dashd.m_coinbase_payload, dcb);
    if (eok && dok) {
        add("merkleRootMNList",  /*commitment=*/true,
            ecb.merkleRootMNList.GetHex(),  dcb.merkleRootMNList.GetHex());
        add("merkleRootQuorums", /*commitment=*/true,
            ecb.merkleRootQuorums.GetHex(), dcb.merkleRootQuorums.GetHex());
        add("cbtx_version", /*commitment=*/false,
            std::to_string(ecb.nVersion), std::to_string(dcb.nVersion));
        add("cbtx_height",  /*commitment=*/false,
            std::to_string(ecb.nHeight),  std::to_string(dcb.nHeight));
    } else {
        // A CbTx we cannot parse is itself a divergence worth logging (but not a
        // commitment-trio member: we cannot read the roots to judge them).
        add("cbtx_parse", /*commitment=*/false,
            eok ? "ok" : "fail", dok ? "ok" : "fail");
    }

    // Coinbase scriptSig height (BIP34). At serve-resolution the assembled
    // coinbase input is not yet materialized in DashWorkData — the coinbase
    // builder BIP34-encodes the block height (m_height) into the scriptSig. So we
    // compare the height VALUE that will be encoded, which is exactly the
    // validity-bearing quantity a scriptSig-height check would catch.
    add("scriptsig_height", /*commitment=*/false,
        std::to_string(embedded.m_height), std::to_string(dashd.m_height));

    if (o.diffs.empty()) {
        o.kind = ShadowOutcome::Kind::Match;
        o.log_lines.push_back("[SHADOW] h=" + std::to_string(o.height) + " MATCH");
        return o;
    }

    o.kind = ShadowOutcome::Kind::Mismatch;
    for (const auto& d : o.diffs)
        if (d.commitment && o.served) o.served_mismatch = true;

    // One line per diverging field. The served + commitment combination is the
    // ONLY real-validity-problem signal, so it gets the distinct SERVED-MISMATCH
    // marker; every other divergence is benign-until-proven and gets MISMATCH.
    for (const auto& d : o.diffs) {
        const bool served_bad = o.served && d.commitment;
        o.log_lines.push_back(
            std::string("[SHADOW] h=") + std::to_string(o.height)
            + (served_bad ? " SERVED-MISMATCH" : " MISMATCH")
            + " field=" + d.field
            + " embedded=" + d.embedded
            + " dashd=" + d.dashd);
    }
    return o;
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime driver. Enqueue-only on the serve path; a worker thread does the RPC +
// compare + log so the miner-facing response never waits on dashd.
// ─────────────────────────────────────────────────────────────────────────────
class EmbeddedShadowCompare {
public:
    /// Returns dashd's getblocktemplate as a DashWorkData for the current tip,
    /// or nullopt on any failure/absence (so a slow/hung/missing dashd degrades
    /// to a `no-oracle` log line, never a stall). Bound in main_dash.cpp.
    using OracleFn = std::function<std::optional<DashWorkData>()>;

    explicit EmbeddedShadowCompare(OracleFn oracle)
        : oracle_(std::move(oracle)) {
        LOG_INFO << "[SHADOW] embedded-vs-dashd shadow-compare ARMED (diagnostic "
                    "only; NOT a serve gate; oracle fetch off the hot path)";
        worker_ = std::thread([this] { worker_loop(); });
    }

    ~EmbeddedShadowCompare() {
        { std::lock_guard<std::mutex> lk(q_mu_); stop_ = true; }
        q_cv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

    EmbeddedShadowCompare(const EmbeddedShadowCompare&) = delete;
    EmbeddedShadowCompare& operator=(const EmbeddedShadowCompare&) = delete;

    /// SERVE-PATH ENTRY. ENQUEUE ONLY — copies the just-resolved template + the
    /// arm that produced it and returns immediately. NEVER blocks the caller and
    /// NEVER touches `served`. Coalesces to the newest pending job (a shadow
    /// samples serves; a skipped intermediate is a coverage gap, never a wrong
    /// count). Safe to call whether the resolved arm was Embedded or fallback.
    void on_serve(WorkSource source, const DashWorkData& served) {
        {
            std::lock_guard<std::mutex> lk(q_mu_);
            pending_ = std::make_pair(source, served);   // copy
        }
        q_cv_.notify_one();
    }

    nlohmann::json stats_json() const {
        std::lock_guard<std::mutex> lk(mu_);
        nlohmann::json j = counters_.to_json();
        j["mode"] = "embedded-shadow-compare";
        j["note"] = "diagnostic only — NOT a serve gate";
        return j;
    }

private:
    void worker_loop() {
        for (;;) {
            std::pair<WorkSource, DashWorkData> job;
            {
                std::unique_lock<std::mutex> lk(q_mu_);
                q_cv_.wait(lk, [this] { return stop_ || pending_.has_value(); });
                if (stop_ && !pending_.has_value()) return;
                job = std::move(*pending_);
                pending_.reset();
            }
            try { process(job.first, job.second); }
            catch (const std::exception& e) {
                LOG_WARNING << "[SHADOW] worker exception: " << e.what();
            }
        }
    }

    void process(WorkSource source, const DashWorkData& served) {
        // The dashd oracle RPC runs HERE, on the worker thread — off the hot
        // path. A throw/absence maps to nullopt -> a `no-oracle` sample.
        std::optional<DashWorkData> dashd;
        if (oracle_) {
            try { dashd = oracle_(); }
            catch (const std::exception& e) {
                LOG_WARNING << "[SHADOW] oracle threw: " << e.what() << " — no-oracle";
                dashd.reset();
            }
        }
        // If the oracle returned an empty set-gap template (unarmed fallback:
        // m_height==0 / null prev), treat it as no-oracle rather than diffing
        // every field against zeros.
        if (dashd && (dashd->m_bits == 0 || dashd->m_previous_block.IsNull()))
            dashd.reset();

        const ShadowOutcome o = shadow_evaluate(source, served, dashd);

        for (const auto& line : o.log_lines) {
            if (o.served_mismatch) LOG_WARNING << line;   // the real-problem signal
            else                   LOG_INFO    << line;
        }
        std::lock_guard<std::mutex> lk(mu_);
        counters_.apply(o);
    }

    OracleFn oracle_;

    mutable std::mutex mu_;          // guards counters_
    ShadowCounters     counters_;

    std::thread             worker_;
    std::mutex              q_mu_;
    std::condition_variable q_cv_;
    std::optional<std::pair<WorkSource, DashWorkData>> pending_;
    bool                    stop_{false};
};

} // namespace coin
} // namespace dash
