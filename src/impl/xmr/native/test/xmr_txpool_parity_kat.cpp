// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_txpool_parity_kat.cpp
//
// M1: the P-POOL seam, and the OFFLINE REPLAY of the live parity run.
//
// The live proof needs a regtest monerod, a wallet with funds and five minutes.
// This KAT is what makes it a REGRESSION rather than an anecdote: the daemon's
// own /get_transaction_pool answer is checked in (xmr_txpool_parity_golden.hpp),
// and the replay walks the same path the live probe walked --
//
//     the daemon's JSON  -> MonerodTxpoolRpc::parse   -> the monerod arm
//     the daemon's blobs -> RelayedTxPool::on_relayed -> the native arm
//                        -> compare_txpools
//
// -- with only the socket removed. Every {weight, fee, blob_size} on the native
// side is computed here, now, by C3's decoder from the transaction bytes; every
// one on the monerod side is a number a real daemon printed. If the two ever
// stop agreeing, this fails in CI without anybody having to notice.
//
// What is asserted, in order:
//
//   1. the seam table -- three required EQUALITY fields, two of them sentinels,
//      the id as the alignment key, and the comparator version bumped for it;
//   2. the parse -- the daemon's ids and numbers recovered, and ABSENCE
//      preserved as absence rather than defaulted to zero;
//   3. the replay -- real transactions in, per-transaction CLEAN out;
//   4. the judgement -- a wrong weight, a wrong fee, a wrong size and a missing
//      field each produce the verdict they should, and never CLEAN;
//   5. the set problem -- intersection judged, differences measured, and an
//      empty intersection reported as NO SAMPLES rather than as agreement;
//   6. the tally -- coverage over a whole run, and the one deliberate hole;
//   7. facts() -- the whole pool, not the selection;
//   8. eviction as the probe sees it -- mined, and key-image conflict;
//   9. the DoS buckets under a relay flood, and the pool's state after one.
// ---------------------------------------------------------------------------

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "impl/xmr/native/p2p/xmr_p2p_dos.hpp"
#include "impl/xmr/native/parity/xmr_txpool_parity.hpp"
#include "impl/xmr/native/txpool/xmr_relayed_txpool.hpp"
#include "xmr_tx_weight_golden.hpp"
#include "xmr_txpool_parity_golden.hpp"

using namespace c2pool::xmr::native;
namespace P   = c2pool::xmr::native::parity;
namespace G   = c2pool::xmr::native::golden;
namespace p2p = c2pool::xmr::native::p2p;
namespace levin = c2pool::xmr::native::levin;

static int g_checks = 0;
static int g_fail   = 0;

static void check(bool cond, const char* what) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        if (g_fail <= 25) std::fprintf(stderr, "FAIL: %s\n", what);
    }
}

static void checkf(bool cond, const char* fmt, ...) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        if (g_fail <= 25) {
            va_list ap;
            va_start(ap, fmt);
            std::vfprintf(stderr, fmt, ap);
            va_end(ap);
            std::fputc('\n', stderr);
        }
    }
}

static std::vector<std::uint8_t> from_hex(const char* hex) {
    std::vector<std::uint8_t> out;
    const std::size_t n = std::strlen(hex);
    out.reserve(n / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < n; i += 2) {
        const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) break;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

static Hash hash_from_hex(const char* hex) {
    Hash h{};
    const std::vector<std::uint8_t> b = from_hex(hex);
    if (b.size() == 32) std::memcpy(h.data(), b.data(), 32);
    return h;
}

static std::string to_hex(const Hash& h) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (std::uint8_t b : h) { s.push_back(d[b >> 4]); s.push_back(d[b & 0xf]); }
    return s;
}

static PeerRef peer(std::uint64_t id) {
    PeerRef p;
    p.peer_id = id;
    p.addr    = "10.0.0." + std::to_string(id) + ":18080";
    return p;
}

static std::unique_ptr<RelayedTxPool> make_pool(TxpoolConfig cfg = TxpoolConfig{}) {
    auto p = std::make_unique<RelayedTxPool>(std::move(cfg));
    p->set_synced(true);
    return p;
}

// RelayedTxPool owns a mutex, so it is neither copyable nor movable; the holder
// keeps the tests reading like the pool is a local.
#define SYNCED(name)                                  \
    auto name##_owned = make_pool();                  \
    RelayedTxPool& name = *name##_owned
#define SYNCED_CFG(name, cfg)                         \
    auto name##_owned = make_pool(cfg);               \
    RelayedTxPool& name = *name##_owned

// The native arm, built the way the node builds it: off facts(), never off the
// blobs a second time.
static P::PoolSnapshot native_snapshot(const RelayedTxPool& pool) {
    P::PoolSnapshot s;
    s.arm  = "native";
    s.have = true;
    for (const TxpoolFact& f : pool.facts()) {
        P::PoolTxObs o;
        o.id        = f.id;
        o.weight    = P::Obs::u64(f.weight);
        o.fee       = P::Obs::u64(f.fee);
        o.blob_size = P::Obs::u64(f.blob_size);
        o.peers     = P::Obs::u64(f.peers);
        s.txs.push_back(std::move(o));
    }
    return s;
}

// ---------------------------------------------------------------------------
// 1: the seam table
// ---------------------------------------------------------------------------
static void test_seam_table() {
    // 3 since M2h added the native_backlog_famine CONSTRAINT to P-TPL. The pin
    // is EXACT, not a floor: its job is to make anyone who edits a table move
    // the ledger key with it, so a clean streak can never be inherited across a
    // change to what is judged.
    check(P::COMPARATOR_VERSION == 3,
          "the comparator version was bumped when the P-TPL backlog constraint joined");
    check(&P::seam_spec(ProbeKind::Pool) == &P::POOL_SEAM,
          "seam_spec() knows about ProbeKind::Pool");
    checkf(P::POOL_SEAM.required_equality_count() == 3,
           "P-POOL requires exactly three EQUALITY comparisons, got %zu",
           P::POOL_SEAM.required_equality_count());

    bool id_is_key = false, weight_sentinel = false, fee_sentinel = false,
         size_required = false;
    for (std::size_t i = 0; i < P::POOL_SEAM.count; ++i) {
        const P::FieldSpec& f = P::POOL_SEAM.fields[i];
        const std::string n = f.name;
        if (n == "tx_id")     id_is_key       = (f.regime == P::Regime::AlignmentKey);
        if (n == "weight")    weight_sentinel = (f.regime == P::Regime::Equality &&
                                                 f.required && f.sentinel);
        if (n == "fee")       fee_sentinel    = (f.regime == P::Regime::Equality &&
                                                 f.required && f.sentinel);
        if (n == "blob_size") size_required   = (f.regime == P::Regime::Equality && f.required);
    }
    check(id_is_key,       "the transaction id is the ALIGNMENT KEY, not a compared field");
    check(weight_sentinel, "weight is a required EQUALITY sentinel");
    check(fee_sentinel,    "fee is a required EQUALITY sentinel");
    check(size_required,   "blob_size is a required EQUALITY field");
    check(std::string(P::to_string(ProbeKind::Pool)) == "POOL", "the seam renders its name");
}

// ---------------------------------------------------------------------------
// 2: parsing what the daemon actually said
// ---------------------------------------------------------------------------
static void test_parse() {
    const P::PoolSnapshot s =
        P::MonerodTxpoolRpc::parse(G::TXPOOL_POOL_JSON, std::strlen(G::TXPOOL_POOL_JSON));
    checkf(s.have, "the captured monerod pool parses (%s)", s.why.c_str());
    checkf(s.txs.size() == G::TXPOOL_TX_COUNT,
           "every captured transaction is recovered: %zu of %zu",
           s.txs.size(), G::TXPOOL_TX_COUNT);

    for (std::size_t i = 0; i < G::TXPOOL_TX_COUNT; ++i) {
        const G::GoldenPoolTx& g = G::TXPOOL_TXS[i];
        const P::PoolTxObs* t = s.find(hash_from_hex(g.id_hex));
        if (t == nullptr) { check(false, "a captured id is missing from the parse"); continue; }
        checkf(t->weight.present && t->weight.value == std::to_string(g.weight),
               "%.16s weight parsed as the daemon's own %llu", g.id_hex,
               (unsigned long long)g.weight);
        checkf(t->fee.present && t->fee.value == std::to_string(g.fee),
               "%.16s fee parsed as the daemon's own %llu", g.id_hex,
               (unsigned long long)g.fee);
        checkf(t->blob_size.present && t->blob_size.value == std::to_string(g.blob_size),
               "%.16s blob_size parsed as the daemon's own %llu", g.id_hex,
               (unsigned long long)g.blob_size);
    }

    // ABSENCE IS PARSED, NOT DEFAULTED. This is the whole reason the fields are
    // Obs: a daemon that stops returning `weight` must make the sample FAIL,
    // never compare 0 against 0 and call it agreement.
    const char* no_weight =
        "{\"status\":\"OK\",\"transactions\":[{"
        "\"id_hash\":\"0000000000000000000000000000000000000000000000000000000000000001\","
        "\"fee\":7,\"blob_size\":9}]}";
    const P::PoolSnapshot m = P::MonerodTxpoolRpc::parse(no_weight, std::strlen(no_weight));
    check(m.have && m.txs.size() == 1, "an entry with a missing field still parses");
    check(!m.txs[0].weight.present, "the missing weight is ABSENT, not zero");
    check(m.txs[0].fee.present && m.txs[0].fee.value == "7", "and the present ones survive");

    // An empty pool is an ANSWER of nothing, not a failure to answer.
    const char* empty = "{\"status\":\"OK\"}";
    const P::PoolSnapshot e = P::MonerodTxpoolRpc::parse(empty, std::strlen(empty));
    check(e.have && e.txs.empty(), "an empty pool is an answer, not an error");

    // A daemon that says it is busy has not answered at all.
    const char* busy = "{\"status\":\"BUSY\"}";
    const P::PoolSnapshot b = P::MonerodTxpoolRpc::parse(busy, std::strlen(busy));
    check(!b.have && !b.why.empty(), "a non-OK status yields NO observation, with a reason");

    const char* junk = "not json at all";
    check(!P::MonerodTxpoolRpc::parse(junk, std::strlen(junk)).have,
          "junk yields no observation");
}

// The blobs the daemon was holding, straight out of the captured response.
static std::vector<std::vector<std::uint8_t>> golden_blobs() {
    std::vector<std::vector<std::uint8_t>> out;
    ::c2pool::xmr::node::minijson::Value root;
    if (!::c2pool::xmr::node::minijson::parse(
            G::TXPOOL_POOL_JSON, std::strlen(G::TXPOOL_POOL_JSON), root))
        return out;
    for (const auto& t : root["transactions"].arr) {
        const std::string& h = t["tx_blob"].as_string();
        if (!h.empty()) out.push_back(from_hex(h.c_str()));
    }
    return out;
}

// ---------------------------------------------------------------------------
// 3: THE REPLAY. The live run, minus the socket.
// ---------------------------------------------------------------------------
static void test_replay_live_capture() {
    const std::vector<std::vector<std::uint8_t>> blobs = golden_blobs();
    checkf(blobs.size() == G::TXPOOL_TX_COUNT,
           "the capture carries a blob per transaction (%zu of %zu)",
           blobs.size(), G::TXPOOL_TX_COUNT);
    if (blobs.empty()) return;

    SYNCED(pool);
    std::vector<std::vector<std::uint8_t>> batch = blobs;
    const std::vector<TxRelayVerdict> v = pool.on_relayed(peer(1), std::move(batch), true);
    checkf(v.size() == blobs.size(), "one verdict per relayed transaction");
    std::size_t accepted = 0;
    for (const TxRelayVerdict& r : v)
        if (r.reason == TxRelayVerdict::Reason::Accepted) ++accepted;
    checkf(accepted == blobs.size(),
           "every transaction the daemon held is admitted by C3 (%zu of %zu)",
           accepted, blobs.size());

    const P::PoolSnapshot mine = native_snapshot(pool);
    const P::PoolSnapshot theirs =
        P::MonerodTxpoolRpc::parse(G::TXPOOL_POOL_JSON, std::strlen(G::TXPOOL_POOL_JSON));

    const Hash tip = hash_from_hex(G::TXPOOL_TIP_ID);
    const P::TxpoolParityReport rep =
        P::compare_txpools(mine, theirs, G::TXPOOL_TIP_HEIGHT, tip);

    check(rep.judged, "both arms answered");
    check(rep.aligned(), "the two pools hold exactly the same set of ids");
    checkf(rep.samples.size() == blobs.size(),
           "every transaction was compared (%zu samples for %zu transactions)",
           rep.samples.size(), blobs.size());
    checkf(rep.clean == blobs.size() && rep.fail == 0 && rep.voided == 0,
           "every comparison is CLEAN: clean=%zu fail=%zu void=%zu",
           rep.clean, rep.fail, rep.voided);
    checkf(rep.fields_compared == 3 * blobs.size() && rep.fields_equal == rep.fields_compared,
           "three fields per transaction, all equal: %zu/%zu",
           rep.fields_equal, rep.fields_compared);
    check(rep.fields_absent == 0, "no required field went unanswered");
    check(rep.all_equal(), "and the report says so in one predicate");

    // The claim in its own words: OUR number came from the bytes, not from the
    // daemon. Spot-check it against the daemon's table directly.
    for (std::size_t i = 0; i < G::TXPOOL_TX_COUNT; ++i) {
        const G::GoldenPoolTx& g = G::TXPOOL_TXS[i];
        RelayedTx e;
        if (!pool.lookup(hash_from_hex(g.id_hex), e)) {
            check(false, "a captured transaction is in our pool");
            continue;
        }
        checkf(e.weight == g.weight, "%.16s: C3 weighed it %llu, monerod said %llu",
               g.id_hex, (unsigned long long)e.weight, (unsigned long long)g.weight);
        checkf(e.fee == g.fee, "%.16s: C3 priced it %llu, monerod said %llu",
               g.id_hex, (unsigned long long)e.fee, (unsigned long long)g.fee);
        checkf(e.blob_size == g.blob_size, "%.16s: C3 measured %llu bytes, monerod said %llu",
               g.id_hex, (unsigned long long)e.blob_size, (unsigned long long)g.blob_size);
    }
}

// ---------------------------------------------------------------------------
// 4 + 5: the judgement, and the set problem
// ---------------------------------------------------------------------------
static P::PoolTxObs obs(const char* id_hex, const char* w, const char* f, const char* b) {
    P::PoolTxObs o;
    o.id = hash_from_hex(id_hex);
    if (w) o.weight    = P::Obs::text(w);
    if (f) o.fee       = P::Obs::text(f);
    if (b) o.blob_size = P::Obs::text(b);
    return o;
}

static const char* ID1 =
    "1111111111111111111111111111111111111111111111111111111111111111";
static const char* ID2 =
    "2222222222222222222222222222222222222222222222222222222222222222";
static const char* ID3 =
    "3333333333333333333333333333333333333333333333333333333333333333";

static P::PoolSnapshot snap(const char* arm, std::vector<P::PoolTxObs> txs) {
    P::PoolSnapshot s;
    s.arm  = arm;
    s.have = true;
    s.txs  = std::move(txs);
    return s;
}

static void test_judgement() {
    const Hash prev = hash_from_hex(ID3);

    // Agreement.
    {
        const auto r = P::compare_txpools(snap("native",  {obs(ID1, "2166", "2599200000", "2166")}),
                                          snap("monerod", {obs(ID1, "2166", "2599200000", "2166")}),
                                          100, prev);
        check(r.judged && r.clean == 1 && r.all_equal(), "identical entries are CLEAN");
    }
    // A wrong weight is a FAIL and trips a sentinel: it is what the block-weight
    // limit and the fee are denominated in, so it is not a rounding difference.
    {
        const auto r = P::compare_txpools(snap("native",  {obs(ID1, "2167", "2599200000", "2166")}),
                                          snap("monerod", {obs(ID1, "2166", "2599200000", "2166")}),
                                          100, prev);
        check(r.fail == 1 && r.clean == 0, "a weight disagreement FAILS");
        check(!r.all_equal(), "and all_equal() says so");
        check(!r.samples.empty() && r.samples[0].sentinel_tripped,
              "weight is a sentinel: the ledger revokes on it rather than averaging it");
        check(r.failed_ids.size() == 1, "the failing id is named");
    }
    // A wrong fee, likewise.
    {
        const auto r = P::compare_txpools(snap("native",  {obs(ID1, "2166", "1", "2166")}),
                                          snap("monerod", {obs(ID1, "2166", "2599200000", "2166")}),
                                          100, prev);
        check(r.fail == 1 && !r.samples.empty() && r.samples[0].sentinel_tripped,
              "a fee disagreement FAILS and is a sentinel");
    }
    // A wrong size fails without being a sentinel.
    {
        const auto r = P::compare_txpools(snap("native",  {obs(ID1, "2166", "2599200000", "2165")}),
                                          snap("monerod", {obs(ID1, "2166", "2599200000", "2166")}),
                                          100, prev);
        check(r.fail == 1, "a blob_size disagreement FAILS");
        check(!r.samples.empty() && !r.samples[0].sentinel_tripped,
              "but it is not a revocation sentinel");
    }
    // An answered arm that left a required field empty is a FAILURE, not a hole
    // to be skipped. This is the non-vacuity rule doing its job.
    {
        const auto r = P::compare_txpools(snap("native",  {obs(ID1, "2166", "2599200000", "2166")}),
                                          snap("monerod", {obs(ID1, nullptr, "2599200000", "2166")}),
                                          100, prev);
        check(r.fail == 1 && r.clean == 0, "an unanswered required field FAILS");
        checkf(r.fields_absent == 1, "and is counted as absent, not compared (%zu)",
               r.fields_absent);
        check(!r.samples.empty() && r.samples[0].sentinel_tripped,
              "an unanswered SENTINEL trips the sentinel too");
    }
    // The set problem: the intersection is judged, the differences are measured.
    {
        const auto r = P::compare_txpools(
            snap("native",  {obs(ID1, "10", "1", "10"), obs(ID2, "20", "2", "20")}),
            snap("monerod", {obs(ID1, "10", "1", "10"), obs(ID3, "30", "3", "30")}),
            100, prev);
        check(r.judged, "a set difference does not stop the comparison");
        check(r.clean == 1 && r.fail == 0, "the intersection is judged");
        check(r.ours_only.size() == 1 && r.ours_only[0] == hash_from_hex(ID2),
              "what only we hold is measured and named");
        check(r.theirs_only.size() == 1 && r.theirs_only[0] == hash_from_hex(ID3),
              "and so is what only the daemon holds");
        check(!r.aligned(), "the sample is not aligned");
        check(r.native_ids.size() == 2, "the whole native pool is carried for the eviction diff");
    }
    // An empty intersection produces NO samples. It must never read as
    // agreement, and the report has no way to say it does.
    {
        const auto r = P::compare_txpools(snap("native",  {obs(ID2, "20", "2", "20")}),
                                          snap("monerod", {obs(ID3, "30", "3", "30")}),
                                          100, prev);
        check(r.judged && r.samples.empty() && r.clean == 0,
              "disjoint pools produce zero samples and zero clean verdicts");
        check(r.compared_ids.empty(), "and nothing is claimed as compared");
    }
    // An arm that could not answer at all: VOID, with the reason kept.
    {
        P::PoolSnapshot dead = P::no_pool_observation("monerod", "transport: connect failed");
        const auto r = P::compare_txpools(snap("native", {obs(ID1, "1", "1", "1")}), dead,
                                          100, prev);
        check(!r.judged, "an arm that did not answer yields an UNJUDGED report");
        check(r.why.find("connect failed") != std::string::npos,
              "and the transport's reason survives into it");
    }
}

// ---------------------------------------------------------------------------
// 6: the tally -- coverage across a run
// ---------------------------------------------------------------------------
static void test_tally() {
    const Hash prev = hash_from_hex(ID3);
    P::TxpoolParityTally t;
    std::string why;

    // Nothing yet.
    check(!t.passes(1, 0, why), "an empty tally passes nothing");

    // An aligned sample: both pools held the same one transaction.
    t.add(P::compare_txpools(snap("native",  {obs(ID1, "10", "1", "10")}),
                             snap("monerod", {obs(ID1, "10", "1", "10")}),
                             100, prev));
    check(t.aligned_samples() == 1, "an aligned sample is recognised as one");
    check(t.passes(1, 0, why), "and one clean aligned sample is a pass at that floor");

    // Now one where the daemon held a transaction we did not.
    t.add(P::compare_txpools(snap("native",  {obs(ID1, "10", "1", "10")}),
                             snap("monerod", {obs(ID1, "10", "1", "10"),
                                              obs(ID2, "20", "2", "20")}),
                             100, prev));
    check(t.samples() == 2, "the sample is counted");
    check(t.distinct_txs_compared() == 1, "still one distinct transaction compared");
    checkf(t.never_compared().size() == 1,
           "and the one we never saw is remembered (%zu)", t.never_compared().size());
    check(!t.passes(1, 0, why), "a run with an uncompared daemon id does not pass");
    check(why.find("never compared") != std::string::npos, "and says why");
    check(t.passes(1, 1, why),
          "unless the scenario declared, in its own arguments, that it would hold one");

    // The next sample compares it. The hole closes.
    t.add(P::compare_txpools(snap("native",  {obs(ID1, "10", "1", "10"),
                                              obs(ID2, "20", "2", "20")}),
                             snap("monerod", {obs(ID1, "10", "1", "10"),
                                              obs(ID2, "20", "2", "20")}),
                             100, prev));
    check(t.never_compared().empty(), "a propagation delay closes; a blind spot does not");
    check(t.aligned_samples() == 2, "and that sample is aligned as well");
    check(t.passes(2, 0, why), "the run now passes with no allowance at all");

    // A run whose pools were always empty compared nothing, and must not pass.
    P::TxpoolParityTally quiet;
    for (int i = 0; i < 20; ++i)
        quiet.add(P::compare_txpools(snap("native", {}), snap("monerod", {}), 100, prev));
    check(quiet.samples() == 20 && quiet.empty_samples() == 20,
          "twenty samples over two empty pools are twenty EMPTY samples");
    check(!quiet.passes(1, 0, why), "and they are not a pass");
    check(quiet.fields_compared() == 0, "because nothing was compared");

    // One failed transaction poisons the run however many clean ones follow.
    P::TxpoolParityTally poisoned;
    poisoned.add(P::compare_txpools(snap("native",  {obs(ID1, "11", "1", "10")}),
                                    snap("monerod", {obs(ID1, "10", "1", "10")}), 100, prev));
    for (int i = 0; i < 50; ++i)
        poisoned.add(P::compare_txpools(snap("native",  {obs(ID2, "20", "2", "20")}),
                                        snap("monerod", {obs(ID2, "20", "2", "20")}), 100, prev));
    check(!poisoned.passes(1, 0, why), "one disagreement is not outvoted by fifty agreements");
    check(poisoned.failed_ids().size() == 1, "and the offender is named");
}

// ---------------------------------------------------------------------------
// 7: facts() is the POOL, not the SELECTION
// ---------------------------------------------------------------------------
static std::vector<std::vector<std::uint8_t>> corpus() {
    std::vector<std::vector<std::uint8_t>> out;
    for (std::size_t i = 0; i < G::FULL_TX_COUNT; ++i) {
        std::vector<std::uint8_t> blob = from_hex(G::FULL_TXS[i].full_hex);
        DecodedTx d;
        if (decode_relayed_tx(blob, d) == TxDecodeStatus::Ok) out.push_back(std::move(blob));
    }
    return out;
}

static void test_facts_surface() {
    const auto txs = corpus();
    if (txs.size() < 3) { check(false, "the stagenet corpus is usable"); return; }

    // A policy that demands evidence this component cannot produce selects
    // nothing -- and facts() must still report everything, because monerod's
    // pool will report it whatever our policy thinks of it.
    TxpoolConfig cfg;
    cfg.policy.required = AdmissionEvidence::Structural | AdmissionEvidence::FeePolicy;
    SYNCED_CFG(pool, cfg);
    for (const auto& b : txs) {
        std::vector<std::vector<std::uint8_t>> one{b};
        pool.on_relayed(peer(1), std::move(one), true);
    }
    check(pool.selectable_backlog().empty(),
          "an unsatisfiable policy selects nothing (fail-closed)");
    checkf(pool.facts().size() == pool.size(),
           "facts() reports the whole pool anyway: %zu of %zu",
           pool.facts().size(), pool.size());

    // And every fact is the decoder's own answer for that blob.
    std::map<Hash, const TxpoolFact*> by_id;
    const std::vector<TxpoolFact> f = pool.facts();
    for (const TxpoolFact& x : f) by_id[x.id] = &x;
    std::size_t matched = 0;
    for (const auto& b : txs) {
        DecodedTx d;
        if (decode_relayed_tx(b, d) != TxDecodeStatus::Ok) continue;
        auto it = by_id.find(d.id);
        if (it == by_id.end()) continue;
        ++matched;
        checkf(it->second->weight == d.w.weight && it->second->fee == d.w.fee &&
                   it->second->blob_size == b.size(),
               "%.16s: facts() reports what the decoder measured", to_hex(d.id).c_str());
    }
    checkf(matched == txs.size(), "every corpus transaction has a fact (%zu of %zu)",
           matched, txs.size());
}

// ---------------------------------------------------------------------------
// 8: eviction, as the parity probe sees it
// ---------------------------------------------------------------------------
static void test_eviction_through_the_probe() {
    const auto txs = corpus();
    if (txs.size() < 3) return;

    SYNCED(pool);
    for (const auto& b : txs) {
        std::vector<std::vector<std::uint8_t>> one{b};
        pool.on_relayed(peer(1), std::move(one), true);
    }
    const Hash prev = hash_from_hex(ID3);
    auto ids_now = [&] {
        const auto r = P::compare_txpools(native_snapshot(pool), snap("monerod", {}), 100, prev);
        return std::set<Hash>(r.native_ids.begin(), r.native_ids.end());
    };
    const std::set<Hash> before = ids_now();
    checkf(before.size() == txs.size(), "the pool holds the corpus (%zu)", before.size());

    DecodedTx d0, d1;
    decode_relayed_tx(txs[0], d0);
    decode_relayed_tx(txs[1], d1);

    // MINED: the block carries the transaction's own id.
    BlockTxEvent mined;
    mined.kind   = BlockTxEvent::Kind::Connected;
    mined.height = 2204800;
    mined.tx_hashes.push_back(d0.id);
    pool.on_block_connected(mined);

    const std::set<Hash> after_mined = ids_now();
    check(after_mined.count(d0.id) == 0, "a mined transaction leaves the native pool");
    checkf(before.size() - after_mined.size() == 1,
           "exactly one entry left (%zu -> %zu)", before.size(), after_mined.size());
    check(pool.stats().evicted_mined == 1, "and the pool accounts for it as MINED");

    // KEY-IMAGE CONFLICT: the block carries a key image we hold, inside a
    // transaction whose id we have never seen. This is the shape the live M1
    // proof manufactures on purpose -- our pool holds the twin, the daemon's
    // holds the original, and the block that mines the original evicts the twin
    // by key image because its ID is nowhere in the block.
    BlockTxEvent other_spend;
    other_spend.kind       = BlockTxEvent::Kind::Connected;
    other_spend.height     = 2204801;
    other_spend.tx_hashes.push_back(hash_from_hex(ID1));   // an id we do not hold
    other_spend.key_images = d1.rct.key_images;
    check(!other_spend.key_images.empty(), "the block event carries key images");
    pool.on_block_connected(other_spend);

    const std::set<Hash> after_conflict = ids_now();
    check(after_conflict.count(d1.id) == 0,
          "an entry whose key image a block spent elsewhere leaves the pool");
    check(pool.stats().evicted_conflict == 1,
          "and the pool accounts for it as a KEY-IMAGE CONFLICT, not as mined");
    check(pool.stats().evicted_mined == 1, "the mined counter did not move for it");

    // The twin the live proof injects, built the way the harness builds it.
    check(d0.w.extra_size > 0 && d0.prefix_size > d0.w.extra_size,
          "a real transaction has a tx_extra to flip a byte of");
    std::vector<std::uint8_t> twin = txs[0];
    twin[d0.prefix_size - d0.w.extra_size] ^= 0x01;
    DecodedTx dt;
    check(decode_relayed_tx(twin, dt) == TxDecodeStatus::Ok, "the twin decodes");
    check(dt.id != d0.id, "the twin has a different id");
    check(dt.rct.key_images == d0.rct.key_images, "and the SAME key images");
    checkf(dt.w.weight == d0.w.weight && dt.w.blob_size == d0.w.blob_size,
           "the flip changes no length, so weight and size are untouched");
}

// ---------------------------------------------------------------------------
// 9: the DoS buckets under a relay flood
//
// The claim M1 owes is not "the buckets exist" -- xmr_p2p_dos_kat pins their
// arithmetic. It is that a flood is absorbed BY THE GUARD and that what reaches
// the pool afterwards is exactly what the guard let through: no torn entry, no
// id in the pool that was never admitted, and a pool that still answers.
// ---------------------------------------------------------------------------
static p2p::DosConfig flood_cfg() {
    p2p::DosConfig c;
    c.bytes_capacity = 10'000'000;   // out of the way: this is a TX-bucket test
    c.bytes_refill   =  1'000'000;
    c.tx_capacity    = 8;            // small enough to exhaust by hand
    c.tx_refill      = 4;            // per second
    return c;
}

// Drive `n` single-transaction relay frames through the guard, and feed the
// pool exactly what the guard let through. Returns what the guard did.
struct FloodResult {
    std::size_t passed = 0, dropped = 0;
    std::size_t disconnects = 0, bans = 0;
    std::set<Hash> admitted;
};

static FloodResult flood(p2p::PeerDosGuard& guard, RelayedTxPool& pool,
                         const std::vector<std::vector<std::uint8_t>>& txs,
                         int n, p2p::Millis& now) {
    FloodResult r;
    for (int i = 0; i < n; ++i) {
        const std::vector<std::uint8_t>& blob = txs[static_cast<std::size_t>(i) % txs.size()];
        p2p::DosFault fault = p2p::DosFault::None;
        const p2p::DosAction a =
            guard.on_frame(levin::CMD_NEW_TRANSACTIONS, blob.size(), 1, now, fault);
        now += 10;
        if (a != p2p::DosAction::Accept) {
            ++r.dropped;
            check(fault == p2p::DosFault::BucketExhausted,
                  "a frame the guard refuses is refused for bucket exhaustion");
            if (a == p2p::DosAction::Disconnect) ++r.disconnects;
            if (a == p2p::DosAction::Ban)        ++r.bans;
            continue;   // THE POOL NEVER SEES IT: this is the point of the guard
        }
        ++r.passed;
        std::vector<std::vector<std::uint8_t>> one{blob};
        const auto v = pool.on_relayed(peer(7), std::move(one), true);
        if (!v.empty() && (v[0].reason == TxRelayVerdict::Reason::Accepted ||
                           v[0].reason == TxRelayVerdict::Reason::Duplicate))
            r.admitted.insert(v[0].id);
    }
    return r;
}

static void test_dos_under_flood() {
    const auto txs = corpus();
    if (txs.size() < 3) return;
    const p2p::DosConfig cfg = flood_cfg();

    // --- a BURST: more than the budget, but fewer exhaustions than the ban
    //     threshold. The frames are dropped, the connection is kept, and the
    //     budget recovers. A defer, not an offence.
    {
        p2p::PeerDosGuard guard(cfg);
        SYNCED(pool);
        p2p::Millis now = 0;
        const FloodResult r = flood(guard, pool, txs, 16, now);

        checkf(r.passed == static_cast<std::size_t>(cfg.tx_capacity),
               "exactly the burst budget got through (%zu of 16, capacity %g)",
               r.passed, cfg.tx_capacity);
        checkf(r.dropped == 16 - r.passed, "and the rest were dropped (%zu)", r.dropped);
        check(guard.exhaustions() == r.dropped, "every drop is an accounted exhaustion");
        check(r.bans == 0 && r.disconnects == 0,
              "a burst under the ban threshold neither bans nor disconnects the peer");
        checkf(guard.score() < cfg.fails_before_ban,
               "the fail score stayed under the ban threshold (%u of %u)",
               guard.score(), cfg.fails_before_ban);

        // The pool holds exactly what the guard let through, and nothing else.
        check(pool.size() == r.admitted.size(),
              "the pool holds exactly the transactions it returned a verdict for");
        checkf(pool.size() <= r.passed,
               "and no more than the guard allowed (%zu of %zu)", pool.size(), r.passed);
        check(pool.stats().rejected == 0, "nothing malformed reached it");
        check(pool.stats().accepted + pool.stats().duplicates == r.passed,
              "and the pool's own accounting matches the guard's, frame for frame");

        // The guard is a rate limit, not a latch.
        now += 5'000;
        p2p::DosFault fault = p2p::DosFault::None;
        check(guard.on_frame(levin::CMD_NEW_TRANSACTIONS, txs[0].size(), 1, now, fault) ==
                  p2p::DosAction::Accept,
              "after the refill the same peer is served again");

        // The pool is still a pool, and the parity probe can still read it.
        const P::PoolSnapshot mine = native_snapshot(pool);
        check(mine.have && mine.txs.size() == pool.size(),
              "the parity probe can still read the pool after a flood");
    }

    // --- a SUSTAINED FLOOD: the exhaustions accumulate and the guard escalates.
    //     A peer that keeps spending budget it does not have is not a fast link.
    {
        p2p::PeerDosGuard guard(cfg);
        SYNCED(pool);
        p2p::Millis now = 0;
        const FloodResult r = flood(guard, pool, txs, 64, now);

        checkf(r.bans >= 1, "a sustained flood escalates to a ban (%zu)", r.bans);
        checkf(guard.score() >= cfg.fails_before_ban,
               "because the exhaustion faults accumulated past the threshold (%u)",
               guard.score());
        // And the pool is STILL consistent: escalation is a connection decision,
        // never a reason for a half-admitted transaction.
        check(pool.size() == r.admitted.size(),
              "the pool is intact after the escalation");
        check(pool.stats().rejected == 0, "and admitted nothing malformed");
    }
}

// ---------------------------------------------------------------------------
int main() {
    test_seam_table();
    test_parse();
    test_replay_live_capture();
    test_judgement();
    test_tally();
    test_facts_surface();
    test_eviction_through_the_probe();
    test_dos_under_flood();

    std::printf("xmr_txpool_parity_kat: %d checks, %d failures "
                "(golden: monerod %s %s, height %llu, %zu transactions)\n",
                g_checks, g_fail, G::TXPOOL_MONEROD_VERSION, G::TXPOOL_NETWORK,
                (unsigned long long)G::TXPOOL_TIP_HEIGHT, G::TXPOOL_TX_COUNT);
    return g_fail == 0 ? 0 : 1;
}
