// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_txpool_kat.cpp
//
// Component C3, the relayed txpool, driven end to end with REAL stagenet
// transactions (the same corpus the tx-weight golden pins, so every blob here
// is one a live monerod accepted and mined).
//
// What is asserted, in the order the pool meets it:
//
//   1. the fail-closed gates -- nothing is admitted before the index says it is
//      at the tip, and nothing gains evidence the component cannot produce;
//   2. admission -- real transactions are accepted, and the evidence recorded
//      is exactly Structural | NonInputConsensus (ruling R-VAL);
//   3. the structural refusal table -- reason AND drop-offence, per monerod's
//      split, because C1 scores peers on that flag;
//   4. sighting bookkeeping -- distinct peers, stem versus fluff, and the rule
//      that a re-sighting never resets the arrival time;
//   5. the snapshot contract -- policy filtering, fee-rate order, and a
//      backlog_version that moves whenever the selectable set could differ;
//   6. KEY-IMAGE CONFLICT, including the twin attack the header describes: a
//      copy of a real transaction with one byte changed in tx_extra keeps every
//      key image and still passes non-input consensus, so first-seen-wins is
//      what stops it from evicting the original from our template;
//   7. mined removal and chain-side key-image eviction;
//   8. eviction under the cap and under age, and the pin that outranks both;
//   9. the body surfaces C2 and C5 read.
// ---------------------------------------------------------------------------

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "impl/xmr/native/txpool/xmr_relayed_txpool.hpp"
#include "xmr_tx_weight_golden.hpp"

using namespace c2pool::xmr::native;
namespace R = c2pool::xmr::native::rct;
namespace G = c2pool::xmr::native::golden;

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

// The Bulletproof+ half of the golden corpus: everything the relay rules at
// HF16 can admit at all.
static std::vector<std::vector<std::uint8_t>> corpus() {
    std::vector<std::vector<std::uint8_t>> out;
    for (std::size_t i = 0; i < G::FULL_TX_COUNT; ++i) {
        std::vector<std::uint8_t> blob = from_hex(G::FULL_TXS[i].full_hex);
        DecodedTx d;
        if (decode_relayed_tx(blob, d) == TxDecodeStatus::Ok) out.push_back(std::move(blob));
    }
    return out;
}

// The first golden transaction whose rct type the relay rules refuse.
static std::vector<std::uint8_t> legacy_rct_tx() {
    for (std::size_t i = 0; i < G::FULL_TX_COUNT; ++i) {
        std::vector<std::uint8_t> blob = from_hex(G::FULL_TXS[i].full_hex);
        DecodedTx d;
        if (decode_relayed_tx(blob, d) == TxDecodeStatus::UnsupportedRctType) return blob;
    }
    return {};
}

static PeerRef peer(std::uint64_t id) {
    PeerRef p;
    p.peer_id = id;
    p.addr    = "10.0.0." + std::to_string(id) + ":18080";
    return p;
}

static TxRelayVerdict relay_one(RelayedTxPool& pool, const PeerRef& from,
                                const std::vector<std::uint8_t>& blob, bool fluff = true) {
    std::vector<std::vector<std::uint8_t>> batch{blob};
    auto v = pool.on_relayed(from, std::move(batch), fluff);
    return v.empty() ? TxRelayVerdict{} : v[0];
}

static Hash id_of(const std::vector<std::uint8_t>& blob) {
    DecodedTx d;
    decode_relayed_tx(blob, d);
    return d.id;
}

static std::vector<Hash> key_images_of(const std::vector<std::uint8_t>& blob) {
    DecodedTx d;
    decode_relayed_tx(blob, d);
    return d.rct.key_images;
}

// A synced pool with the ruling's default policy. The pool owns a mutex, so it
// is neither copyable nor movable and the factory hands back a holder.
static std::unique_ptr<RelayedTxPool> make_pool(TxpoolConfig cfg = TxpoolConfig{},
                                                RelayedTxPool::ClockFn clock = nullptr) {
    auto p = std::make_unique<RelayedTxPool>(std::move(cfg), std::move(clock));
    p->set_synced(true);
    return p;
}

#define SYNCED_POOL(name, ...)                        \
    auto name##_owned = make_pool(__VA_ARGS__);       \
    RelayedTxPool& name = *name##_owned

// ---------------------------------------------------------------------------
// 1 + 2: the gates and admission
// ---------------------------------------------------------------------------
static void test_admission() {
    const auto txs = corpus();
    checkf(txs.size() >= 5, "the corpus carries at least five relayable transactions (%zu)",
           txs.size());
    if (txs.empty()) return;

    // Nothing at all before the index says it is at the tip.
    RelayedTxPool cold;
    const TxRelayVerdict v = relay_one(cold, peer(1), txs[0]);
    check(v.reason == TxRelayVerdict::Reason::NotSynced,
          "an unsynced pool admits nothing (NotSynced)");
    check(!v.drop_offense, "NotSynced is not the peer's fault");
    check(cold.size() == 0, "an unsynced pool stays empty");

    SYNCED_POOL(pool);
    for (const auto& blob : txs) {
        const TxRelayVerdict a = relay_one(pool, peer(1), blob);
        checkf(a.reason == TxRelayVerdict::Reason::Accepted,
               "a real stagenet transaction is accepted (got %s)", to_string(a.reason));
        check(!a.drop_offense, "an accepted transaction is not a peer offence");
        check(a.evidence == (AdmissionEvidence::Structural | AdmissionEvidence::NonInputConsensus),
              "the recorded evidence is exactly Structural | NonInputConsensus (R-VAL)");
        check(covers(a.evidence, EVIDENCE_DAEMONLESS_DEFAULT) == false,
              "the daemonless DEFAULT mask is NOT covered: FeePolicy is not produced here");
    }
    checkf(pool.size() == txs.size(), "every corpus transaction is held (%zu of %zu)",
           pool.size(), txs.size());

    const TxpoolStats s = pool.stats();
    checkf(s.accepted == txs.size(), "stats count every acceptance");
    check(s.bytes > 0 && s.weight > 0, "stats carry pool bytes and weight");

    // The backlog: one entry per transaction, in fee-rate order.
    const auto backlog = pool.selectable_backlog();
    checkf(backlog.size() == txs.size(), "the backlog offers every held transaction (%zu)",
           backlog.size());
    bool ordered = true;
    for (std::size_t i = 1; i < backlog.size(); ++i) {
        const auto& a = backlog[i - 1];
        const auto& b = backlog[i];
        // a.fee/a.weight >= b.fee/b.weight, cross-multiplied.
        if (static_cast<long double>(a.fee) * static_cast<long double>(b.weight)
            < static_cast<long double>(b.fee) * static_cast<long double>(a.weight))
            ordered = false;
    }
    check(ordered, "the backlog is in descending fee-rate order");
    for (const auto& e : backlog) {
        check(e.weight >= e.blob_size, "weight is never below blob size");
        check(e.time_received > 0, "time_received is real, so the 5-second gate is live");
    }

    // A policy asking for evidence this component cannot produce selects
    // nothing, rather than quietly relaxing to what it has.
    TxpoolSelectPolicy fee_policy;
    fee_policy.required = AdmissionEvidence::Structural | AdmissionEvidence::FeePolicy;
    check(pool.selectable_backlog(fee_policy).empty(),
          "a policy requiring FeePolicy evidence selects nothing (fail-closed)");

    TxpoolSelectPolicy daemon_policy;
    daemon_policy.required = AdmissionEvidence::DaemonConfirmed;
    check(pool.selectable_backlog(daemon_policy).empty(),
          "a policy requiring DaemonConfirmed evidence selects nothing here");
}

// ---------------------------------------------------------------------------
// 3: the structural refusal table
// ---------------------------------------------------------------------------
static void test_refusals() {
    const auto txs = corpus();
    if (txs.empty()) return;

    {   // over the maximum transaction size
        SYNCED_POOL(pool);
        std::vector<std::uint8_t> huge(1000001, 0x11);
        const auto v = relay_one(pool, peer(1), huge);
        check(v.reason == TxRelayVerdict::Reason::TooBig, "an oversize blob is TooBig");
        check(v.drop_offense, "an oversize blob is a drop offence");
    }
    {   // not a transaction at all
        SYNCED_POOL(pool);
        const auto v = relay_one(pool, peer(1), std::vector<std::uint8_t>{0xde, 0xad, 0xbe, 0xef});
        check(v.reason == TxRelayVerdict::Reason::Structural, "garbage is Structural");
        check(v.drop_offense, "garbage is a drop offence");
    }
    {   // a real transaction of a pre-HF15 rct type
        const auto legacy = legacy_rct_tx();
        check(!legacy.empty(), "the corpus carries a pre-HF15 rct transaction");
        if (!legacy.empty()) {
            SYNCED_POOL(pool);
            const auto v = relay_one(pool, peer(1), legacy);
            check(v.reason == TxRelayVerdict::Reason::BadVersion,
                  "a pre-HF15 rct type is refused as BadVersion");
            check(v.drop_offense, "an unrelayable rct type is a drop offence");
            check(pool.size() == 0, "it is not held");
        }
    }
    {   // a non-zero unlock time: one byte, same length, and the transaction is
        // otherwise byte-identical to one monerod accepted
        SYNCED_POOL(pool);
        std::vector<std::uint8_t> tampered = txs[0];
        check(tampered[1] == 0x00, "the corpus transaction has unlock_time == 0");
        tampered[1] = 0x01;
        const auto v = relay_one(pool, peer(1), tampered);
        check(v.reason == TxRelayVerdict::Reason::UnlockNotZero,
              "a non-zero unlock time is refused");
        check(!v.drop_offense,
              "unlock-time is relay policy, not consensus: NOT a drop offence");
    }
    {   // the weight limit
        TxpoolConfig cfg;
        cfg.max_tx_weight = 100;
        SYNCED_POOL(pool, cfg);
        const auto v = relay_one(pool, peer(1), txs[0]);
        check(v.reason == TxRelayVerdict::Reason::WeightLimit, "over the weight limit");
        check(v.drop_offense, "the weight limit is consensus: a drop offence");
    }
    {   // the ring size consensus fixes for the fork
        TxpoolConfig cfg;
        cfg.required_ring_size = 11;   // the pre-HF15 value
        SYNCED_POOL(pool, cfg);
        const auto v = relay_one(pool, peer(1), txs[0]);
        check(v.reason == TxRelayVerdict::Reason::BadRing, "the wrong ring size is BadRing");
        check(v.drop_offense, "ring size is consensus: a drop offence");
    }
    {   // the tx_extra relay cap
        TxpoolConfig cfg;
        cfg.max_extra_size = 0;
        SYNCED_POOL(pool, cfg);
        const auto v = relay_one(pool, peer(1), txs[0]);
        check(v.reason == TxRelayVerdict::Reason::ExtraTooBig, "over the tx_extra cap");
        check(!v.drop_offense, "the tx_extra cap is relay policy: NOT a drop offence");
    }
    {   // the output-count bounds
        TxpoolConfig cfg;
        cfg.min_outputs = 64;
        SYNCED_POOL(pool, cfg);
        const auto v = relay_one(pool, peer(1), txs[0]);
        check(v.reason == TxRelayVerdict::Reason::Structural,
              "an output count outside the consensus bounds is Structural");
    }
    {   // a tampered range proof: the transaction decodes, and is refused on
        // the evidence rather than on its shape
        SYNCED_POOL(pool);
        DecodedTx probe;
        check(decode_relayed_tx(txs[0], probe) == TxDecodeStatus::Ok, "control decode");
        std::vector<std::uint8_t> tampered = txs[0];
        tampered[probe.prefix_size + probe.base_size + 1 + 7] ^= 0x40;
        const auto v = relay_one(pool, peer(1), tampered);
        check(v.reason == TxRelayVerdict::Reason::ProofFail,
              "a transaction whose range proof does not verify is ProofFail");
        check(v.drop_offense, "a failed proof is a drop offence");
        check(pool.size() == 0, "it is not held");
    }
}

// ---------------------------------------------------------------------------
// 4 + 5: sightings, the stem gate, and the backlog version
// ---------------------------------------------------------------------------
static void test_sightings() {
    const auto txs = corpus();
    if (txs.empty()) return;

    SYNCED_POOL(pool);
    const Hash id = id_of(txs[0]);

    check(relay_one(pool, peer(1), txs[0]).reason == TxRelayVerdict::Reason::Accepted,
          "first sighting is accepted");
    const std::uint64_t v_after_first = pool.backlog_version();

    RelayedTx e;
    check(pool.lookup(id, e), "the entry is retrievable");
    const std::uint64_t first_time = e.time_received;
    check(e.seen_from_peers() == 1, "one distinct peer so far");

    // The same peer again: a duplicate that changes nothing.
    const auto dup = relay_one(pool, peer(1), txs[0]);
    check(dup.reason == TxRelayVerdict::Reason::Duplicate, "a re-sighting is a Duplicate");
    check(!dup.drop_offense, "a duplicate across notifications is not the peer's fault");
    check(pool.backlog_version() == v_after_first,
          "a duplicate from a known peer does not move the backlog version");

    // A second peer: corroboration, which a min_peers policy can see.
    check(relay_one(pool, peer(2), txs[0]).reason == TxRelayVerdict::Reason::Duplicate,
          "a second peer's copy is still a Duplicate");
    check(pool.lookup(id, e) && e.seen_from_peers() == 2, "two distinct peers now");
    check(e.time_received == first_time, "a re-sighting never resets the arrival time");
    check(pool.backlog_version() != v_after_first,
          "new corroboration moves the backlog version");

    TxpoolSelectPolicy two_peers;
    two_peers.required  = AdmissionEvidence::Structural | AdmissionEvidence::NonInputConsensus;
    two_peers.min_peers = 3;
    check(pool.selectable_backlog(two_peers).empty(),
          "a min_peers policy above the corroboration count selects nothing");
    two_peers.min_peers = 2;
    check(pool.selectable_backlog(two_peers).size() == 1,
          "and selects the transaction once it is corroborated enough");

    // The Dandelion++ stem gate: a transaction only ever seen in the stem phase
    // is not mined, because mining it would leak the path back to its origin.
    SYNCED_POOL(stem_pool);
    check(relay_one(stem_pool, peer(1), txs[1], /*fluff=*/false).reason
                  == TxRelayVerdict::Reason::Accepted,
          "a stem-phase transaction is still admitted to the pool");
    check(stem_pool.selectable_backlog().empty(),
          "but it is not selectable while it has only been seen in the stem phase");
    TxpoolSelectPolicy stem_ok;
    stem_ok.required   = AdmissionEvidence::Structural | AdmissionEvidence::NonInputConsensus;
    stem_ok.allow_stem = true;
    check(stem_ok.min_peers == 1 && stem_pool.selectable_backlog(stem_ok).size() == 1,
          "an explicit allow_stem policy sees it");
    check(relay_one(stem_pool, peer(2), txs[1], /*fluff=*/true).reason
                  == TxRelayVerdict::Reason::Duplicate,
          "the fluff sighting arrives as a duplicate");
    check(stem_pool.selectable_backlog().size() == 1,
          "and the transaction becomes selectable once it has been fluffed");
}

// ---------------------------------------------------------------------------
// 6: key-image conflict and the twin attack
// ---------------------------------------------------------------------------
static void test_key_image_conflict() {
    const auto txs = corpus();
    if (txs.empty()) return;

    // Build the twin: the same transaction with ONE byte changed inside
    // tx_extra. tx_extra is the tail of the prefix, so this changes the id and
    // nothing else -- same key images, same commitments, same proof.
    DecodedTx probe;
    check(decode_relayed_tx(txs[0], probe) == TxDecodeStatus::Ok, "control decode");
    check(probe.w.extra_size > 0, "the transaction has a tx_extra to mutate");
    std::vector<std::uint8_t> twin = txs[0];
    const std::size_t extra_off = probe.prefix_size - probe.w.extra_size;
    twin[extra_off] ^= 0x01;

    DecodedTx twin_d;
    check(decode_relayed_tx(twin, twin_d) == TxDecodeStatus::Ok, "the twin decodes");
    check(twin_d.id != probe.id, "the twin has a DIFFERENT transaction id");
    check(twin_d.rct.key_images == probe.rct.key_images,
          "the twin spends the SAME key images");
    R::RctNonInput in = twin_d.rct;
    check(R::verify_non_input_consensus(in) == R::RctVerifyStatus::Ok,
          "the twin passes non-input consensus -- which is exactly why first-seen-wins "
          "is the only safe rule at this admission depth");

    SYNCED_POOL(pool);
    check(relay_one(pool, peer(1), txs[0]).reason == TxRelayVerdict::Reason::Accepted,
          "the original is accepted");
    const auto v = relay_one(pool, peer(9), twin);
    check(v.reason == TxRelayVerdict::Reason::KeyImageConflict,
          "the twin is refused as a key-image conflict");
    check(!v.drop_offense,
          "a double spend is a no-drop offence, as it is in monerod");
    check(pool.size() == 1, "the pool still holds exactly the original");
    check(pool.contains(probe.id), "and it is the ORIGINAL that survives");
    check(pool.selectable_backlog().size() == 1,
          "the original is still selectable: the twin bought no censorship");
}

// ---------------------------------------------------------------------------
// 7: what a connected block does to the pool
// ---------------------------------------------------------------------------
static void test_chain_events() {
    const auto txs = corpus();
    if (txs.size() < 3) return;

    SYNCED_POOL(pool);
    for (const auto& b : txs) relay_one(pool, peer(1), b);
    const std::size_t held = pool.size();

    // A block containing the first transaction removes it by id.
    BlockTxEvent mined;
    mined.kind   = BlockTxEvent::Kind::Connected;
    mined.height = 2204800;
    mined.tx_hashes.push_back(id_of(txs[0]));

    const std::uint64_t before = pool.backlog_version();
    pool.on_block_connected(mined);
    check(pool.size() == held - 1, "a mined transaction leaves the pool");
    check(!pool.contains(id_of(txs[0])), "by id");
    check(pool.backlog_version() != before, "and the backlog version moves");

    // A block that spends a key image we hold, in a transaction we have never
    // seen, evicts our entry: the double-spend race the pool CAN resolve.
    BlockTxEvent other_spend;
    other_spend.kind       = BlockTxEvent::Kind::Connected;
    other_spend.height     = 2204801;
    other_spend.key_images = key_images_of(txs[1]);
    check(!other_spend.key_images.empty(), "the block event carries key images");
    pool.on_block_connected(other_spend);
    check(!pool.contains(id_of(txs[1])),
          "an entry whose key image was spent on chain is evicted");

    const TxpoolStats s = pool.stats();
    check(s.evicted_mined >= 1, "the mined eviction is counted");
    check(s.evicted_conflict >= 1, "the conflict eviction is counted");

    // A rolled-back block hands bodies back BEST EFFORT; they go through the
    // whole admission path again, so a body that no longer verifies is simply
    // not re-admitted.
    BlockTxEvent rolled_back;
    rolled_back.kind = BlockTxEvent::Kind::Disconnected;
    rolled_back.tx_hashes.push_back(id_of(txs[0]));
    rolled_back.tx_blobs.push_back(txs[0]);
    pool.on_block_disconnected(rolled_back);
    check(pool.contains(id_of(txs[0])),
          "a rolled-back transaction returns to the pool through admission");
}

// ---------------------------------------------------------------------------
// 8 + 9: eviction, pinning, and the body surfaces
// ---------------------------------------------------------------------------
static void test_eviction_and_bodies() {
    const auto txs = corpus();
    if (txs.size() < 3) return;

    // --- the cap ------------------------------------------------------------
    // Room for two of these transactions and no more.
    TxpoolConfig cfg;
    cfg.max_pool_bytes = txs[0].size() + txs[1].size() + txs[2].size();
    SYNCED_POOL(pool, cfg);
    for (const auto& b : txs) relay_one(pool, peer(1), b);
    check(pool.stats().bytes <= cfg.max_pool_bytes, "the pool never exceeds its byte cap");
    check(pool.stats().evicted_cap > 0 || pool.size() == txs.size(),
          "and it evicted to stay under it");

    const auto backlog = pool.selectable_backlog();
    check(!backlog.empty(), "something survived the cap");

    // A transaction LARGER than the whole cap can never be held, and must not
    // cost the pool a single eviction on its way to being refused. Evicting
    // first and failing afterwards would make an oversized relay a free way to
    // wipe the pool -- which is what the first cut of this code did, and what
    // this assertion exists to keep out.
    const std::size_t survivors = pool.size();
    const std::uint64_t evicted_before = pool.stats().evicted_cap;
    std::vector<std::uint8_t> too_big = txs[0];
    too_big.resize(cfg.max_pool_bytes + 1, 0x00);
    const auto refused = relay_one(pool, peer(1), too_big);
    check(refused.reason != TxRelayVerdict::Reason::Accepted,
          "a transaction bigger than the whole cap is refused");
    check(pool.size() == survivors, "and it evicts nothing on its way out");
    check(pool.stats().evicted_cap == evicted_before, "no eviction was charged for it");

    // --- the pin outranks the cap -------------------------------------------
    TxpoolConfig pin_cfg;
    pin_cfg.max_pool_bytes = txs[0].size() + 16;
    SYNCED_POOL(pinned_pool, pin_cfg);
    check(relay_one(pinned_pool, peer(1), txs[0]).reason == TxRelayVerdict::Reason::Accepted,
          "the first transaction is accepted into the tiny pool");

    Hash template_id{};
    template_id[0] = 0x77;
    pinned_pool.pin(template_id, {id_of(txs[0])});
    check(pinned_pool.stats().pinned_templates == 1, "the template is pinned");

    // A better-paying transaction cannot displace a pinned body: the pinned
    // blob is the body of a template that can still win a block, and C5 must be
    // able to serve it.
    for (std::size_t i = 1; i < txs.size(); ++i) relay_one(pinned_pool, peer(1), txs[i]);
    check(pinned_pool.contains(id_of(txs[0])), "the pinned transaction survives the cap");

    // --- the body surfaces ---------------------------------------------------
    std::vector<std::uint8_t> body;
    check(pinned_pool.get_tx(id_of(txs[0]), body), "C2 can read a body back by id");
    check(body == txs[0], "and the bytes are EXACTLY the bytes received");

    std::vector<std::vector<std::uint8_t>> blobs;
    std::vector<Hash>                      missing;
    check(pinned_pool.get_blobs({id_of(txs[0])}, blobs, missing),
          "C5 can read the pinned bodies for a block it is about to relay");
    check(blobs.size() == 1 && missing.empty(), "with nothing missing");

    Hash absent{};
    absent[0] = 0xAB;
    check(!pinned_pool.get_blobs({absent}, blobs, missing),
          "and an unknown id is reported, not silently skipped");
    check(missing.size() == 1 && missing[0] == absent, "by id");

    pinned_pool.unpin(template_id);
    check(pinned_pool.stats().pinned_templates == 0, "the template can be unpinned");

    // --- age ------------------------------------------------------------------
    std::uint64_t fake_now = 1000000;
    TxpoolConfig  age_cfg;
    age_cfg.max_age_seconds = 100;
    SYNCED_POOL(aged, age_cfg, [&fake_now] { return fake_now; });
    check(relay_one(aged, peer(1), txs[0]).reason == TxRelayVerdict::Reason::Accepted,
          "a transaction is admitted at t0");
    fake_now += 99;
    check(aged.expire_old() == 0, "it is not expired one second early");
    check(aged.size() == 1, "and is still held");
    fake_now += 2;
    check(aged.expire_old() == 1, "it is expired once it is older than the livetime");
    check(aged.size() == 0, "and the pool is empty");
    check(aged.stats().evicted_age == 1, "the age eviction is counted");

    // --- the complement id set -----------------------------------------------
    SYNCED_POOL(comp);
    for (const auto& b : txs) relay_one(comp, peer(1), b);
    const auto ids = comp.complement_request_ids();
    checkf(ids.size() == comp.size(), "the complement request offers every held id (%zu)",
           ids.size());
    check(ids.size() <= MAX_TXPOOL_COMPLEMENT_IDS, "and never more than the wire allows");
}

int main() {
    std::printf("xmr_txpool_kat: corpus from monerod %s (%s) at tip %llu\n",
                G::MONEROD_VERSION, G::NETWORK,
                static_cast<unsigned long long>(G::CAPTURE_TIP));
    test_admission();
    test_refusals();
    test_sightings();
    test_key_image_conflict();
    test_chain_events();
    test_eviction_and_bodies();
    std::printf("xmr_txpool_kat: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
