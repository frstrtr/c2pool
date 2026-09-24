// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_template_dup_tx_kat.cpp
//
// TEMPLATE DUP-TX: a template on a new tip must never carry a tx the chain it
// extends already mined (or a key image already spent there), our own found
// block must be checked for exactly that before PREFER-OWN adopts it, and an
// own fork that no peer adopts must not hold the node forever.
//
// THE DEFECT, as the publish-arm verify rig showed it (runs-fix-p2p): B's block
// 512 (a371d5df) mined tx 86f666b7; node A's pool learned that on its POOL
// thread, after the index had already moved the tip; A's template id=35 for
// h=513 on the NEW tip still carried 86f666b7; A found 8b2efacf on it; every
// monerod logged "attempting to add transaction already in blockchain" and
// dropped A's connection; A adopted its own invalid block (PREFER-OWN), mined
// 514..522 on it with peers=0, and never came back (a levin-only node cannot
// hear monerod's refusal, and monerod refuses to serve A's fork).
//
// Everything here runs on the REAL chain index (anchor-booted, stagenet
// numbers, real mainnet transactions in the blocks, a model RandomX verifier):
//
//   A  ORACLE    -- probe_mined() answers "mined / spent in the chain ending at
//                   this parent", and forgets on disconnect.
//   C  REORG     -- the Disconnected event carries the rolled-back bodies (the
//                   pool re-admits them; before: always empty), and the oracle
//                   follows the switch.
//   D  TEMPLATE  -- NativeMinerDataSource over the real index, with a pool that
//                   was NOT told about the block: the mined tx and the tx
//                   spending a mined key image are left out, the valid one is
//                   still served (good citizen).
//
// All three are RED on 00bb77c0 (with the test surfaces stubbed in) and GREEN
// with the fix. Registered in BOTH `--target` lists in
// .github/workflows/build.yml (the #1539 lesson).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "impl/xmr/native/anchor/xmr_anchor_codec.hpp"
#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/chain/xmr_pow_gate.hpp"
#include "impl/xmr/native/consensus/xmr_block_id.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/contracts/fakes/fake_fetcher.hpp"
#include "impl/xmr/native/contracts/fakes/fake_txpool.hpp"
#include "impl/xmr/native/template/xmr_native_miner_data.hpp"
#include "impl/xmr/native/txpool/xmr_tx_decode.hpp"
#include "xmr_input_consensus_golden.hpp"
#include "xmr_p2p_kat_util.hpp"

namespace native = c2pool::xmr::native;
namespace kat    = c2pool::xmr::native::kat;
namespace T      = c2pool::xmr::native::test;

using native::BlockEntry;
using native::Hash;
using native::OfferOutcome;
using native::PeerRef;
using native::PeerSyncData;
using native::U128;

namespace {

constexpr std::uint64_t kAnchorHeight = 2204000;      // a real stagenet height, HF 16
constexpr std::uint64_t kAnchorTs     = 1788965550;
constexpr std::uint64_t kBase         = 600000000000ull;   // tail emission at these coins
constexpr std::uint64_t kBoundMs      = 10'000;

class ModelVerifier {
public:
    enum class VerifyStatus { Accept, BelowTarget, SeedNotResident, NotInitialized };
    bool prefetch_epoch(const Hash& current, const std::optional<Hash>& next) {
        cur_ = current;
        nxt_ = next;
        return true;
    }
    bool seed_resident(const Hash& s) const {
        if (cur_ && *cur_ == s) return true;
        return nxt_ && *nxt_ == s;
    }
    VerifyStatus verify(const std::uint8_t*, std::size_t, const Hash& seed,
                        std::uint64_t, std::uint64_t, std::uint8_t out[32]) {
        if (!seed_resident(seed)) return VerifyStatus::SeedNotResident;
        for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(i);
        return VerifyStatus::Accept;
    }

private:
    std::optional<Hash> cur_, nxt_;
};

void put_varint(std::vector<std::uint8_t>& o, std::uint64_t v) { native::blob_write_varint(o, v); }

Hash tag_hash(std::uint64_t seed, std::uint8_t tag) {
    Hash h{};
    for (std::size_t i = 0; i < 8; ++i) h[i] = static_cast<std::uint8_t>(seed >> (8 * i));
    for (std::size_t i = 8; i < h.size(); ++i) h[i] = static_cast<std::uint8_t>(tag + i);
    return h;
}

std::string hex8(const Hash& h) {
    char b[17];
    for (int i = 0; i < 8; ++i) std::snprintf(b + 2 * i, 3, "%02x", h[static_cast<std::size_t>(i)]);
    return std::string(b, 16);
}

// A structurally real HF-16 block: v2 coinbase paying `reward`, `txids` committed.
std::vector<std::uint8_t> build_blob(std::uint64_t height, std::uint64_t ts, const Hash* prev,
                                     std::uint32_t nonce, std::uint64_t reward,
                                     std::uint8_t flavour, const std::vector<Hash>& txids) {
    std::vector<std::uint8_t> b;
    put_varint(b, 16);
    put_varint(b, 16);
    put_varint(b, ts);
    if (prev) {
        b.insert(b.end(), prev->begin(), prev->end());
    } else {
        for (std::size_t i = 0; i < 32; ++i)
            b.push_back(static_cast<std::uint8_t>((height - 1 + i) ^ flavour));
    }
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>((nonce >> (8 * i)) & 0xff));
    put_varint(b, 2);
    put_varint(b, height + 60);
    put_varint(b, 1);
    b.push_back(native::TX_IN_GEN);
    put_varint(b, height);
    put_varint(b, 1);
    put_varint(b, reward);
    b.push_back(native::TX_OUT_TO_TAGGED_KEY);
    for (std::size_t i = 0; i < 33; ++i)
        b.push_back(static_cast<std::uint8_t>((i * 7u) ^ flavour ^ (height & 0xff)));
    {
        std::vector<std::uint8_t> extra;
        extra.push_back(0x01);
        for (std::size_t i = 0; i < 32; ++i)
            extra.push_back(static_cast<std::uint8_t>((i * 3u) + flavour));
        put_varint(b, extra.size());
        b.insert(b.end(), extra.begin(), extra.end());
    }
    b.push_back(0x00);
    put_varint(b, txids.size());
    for (const Hash& t : txids) b.insert(b.end(), t.begin(), t.end());
    return b;
}

Hash id_of_blob(const std::vector<std::uint8_t>& blob) {
    native::ParsedBlock pb;
    if (native::parse_block(blob, pb) != native::BlockParseStatus::Ok) return Hash{};
    return native::block_identity(blob.data(), pb).id;
}

// One real mainnet transaction.
struct Tx {
    Hash                      id{};
    std::vector<std::uint8_t> blob;
    std::vector<Hash>         kis;
};

Tx golden_tx(std::size_t i) {
    const auto& g = T::input_consensus_golden();
    Tx t;
    t.blob = kat::from_hex(g[i % g.size()].full_hex);
    native::DecodedTx d;
    native::decode_relayed_tx(t.blob, d);
    t.id  = d.id;
    t.kis = d.rct.key_images;
    return t;
}

// The same transaction with one tx_extra byte flipped: a different id spending
// the SAME key images (the double spend a block must never carry twice).
Tx twin_of(const Tx& src) {
    native::DecodedTx d;
    native::decode_relayed_tx(src.blob, d);
    Tx t;
    t.blob = src.blob;
    t.blob[d.prefix_size - d.w.extra_size] ^= 0x01;
    native::DecodedTx dt;
    native::decode_relayed_tx(t.blob, dt);
    t.id  = dt.id;
    t.kis = dt.rct.key_images;
    return t;
}

PeerRef peer(const char* addr, std::uint64_t id) {
    PeerRef p;
    p.addr    = addr;
    p.peer_id = id;
    return p;
}

native::AnchorBundle make_bundle(const Hash& id) {
    native::AnchorBundle b;
    b.network       = "stagenet";
    b.height        = kAnchorHeight;
    b.id            = id;
    b.prev_id       = tag_hash(kAnchorHeight - 1, 0x10);
    b.timestamp     = kAnchorTs;
    b.major_version = 16;
    b.cumulative_difficulty.hi = 0;
    b.cumulative_difficulty.lo = 0xc3772e00dbull;
    b.already_generated_coins  = 18163913490712907281ull;
    const std::uint64_t seed_h = native::rx_seedheight(b.height + 1);
    b.seed_ids.emplace_back(seed_h, tag_hash(seed_h, 0x20));
    U128 cd{};
    cd.lo = 0xc2cb6d9d38ull;
    for (std::size_t i = 0; i < native::ANCHOR_DIFFICULTY_WINDOW; ++i) {
        b.difficulty_window.emplace_back(1788876380ull + i * 37ull, cd);
        cd = native::u128_add(cd, U128{0, 3766353ull});
    }
    for (std::size_t i = 0; i < native::ANCHOR_SHORT_TERM_WEIGHTS; ++i)
        b.short_term_weights.push_back(87ull + (i % 5));
    b.long_term_weights.assign(native::ANCHOR_LONG_TERM_WEIGHTS, 176470ull);
    b.digest = native::anchor_digest(b);
    return b;
}

// The chain under test: an anchor-booted ChainIndex, synced, with a capture of
// every tx event it raises.
struct Chain {
    ModelVerifier                                 mv;
    native::LightVerifierPowSource<ModelVerifier> src{mv};
    native::ChainIndex*                           idx = nullptr;
    native::fakes::FakeFetcher                    fetcher;
    Hash                                          anchor_id{};
    std::vector<native::BlockTxEvent>             tx_events;
    PeerRef pa = peer("198.51.100.1:38080", 1001);
    PeerRef pb = peer("198.51.100.2:38080", 1002);
    bool    ok = false;

    explicit Chain(std::uint64_t bound_ms = kBoundMs) {
        const std::vector<std::uint8_t> anchor_blob =
            build_blob(kAnchorHeight, kAnchorTs, nullptr, 0x0badc0de, kBase, 0x11, {});
        anchor_id = id_of_blob(anchor_blob);
        native::ChainIndexOptions o;
        o.net               = native::XmrNet::Stagenet;
        (void)bound_ms;   // the own-fork guard arrives with goal 3
        idx = new native::ChainIndex(o, src);
        idx->set_fetcher(&fetcher);
        std::string why;
        ok = idx->boot_from_anchor(make_bundle(anchor_id), {}, why);
        kat::checkf(ok, "rig: the index boots from the anchor (%s)", why.c_str());
        idx->force_synced(true);
        idx->subscribe_txs([this](const native::BlockTxEvent& e) { tx_events.push_back(e); });
    }
    ~Chain() { delete idx; }

    std::uint64_t tip_height() const { return idx->tip() ? idx->tip()->height : 0; }
    Hash          tip_id() const { return idx->tip() ? idx->tip()->id : Hash{}; }

    // A block on `prev` at height `h` carrying `txs` (in order), its coinbase
    // priced to base + fees so it evaluates.
    BlockEntry make(const Hash& prev, std::uint64_t h, const std::vector<const Tx*>& txs,
                    std::uint8_t flavour) const {
        const std::uint64_t ts = kAnchorTs + 120 * (h - kAnchorHeight);
        std::vector<Hash>                txids;
        std::vector<native::TxBlobEntry> bodies;
        for (const Tx* t : txs) {
            txids.push_back(t->id);
            native::TxBlobEntry te;
            te.blob = t->blob;
            bodies.push_back(std::move(te));
        }
        std::uint64_t fees = 0;
        {
            BlockEntry trial;
            trial.block_blob = build_blob(h, ts, &prev, static_cast<std::uint32_t>(h), kBase,
                                          flavour, txids);
            trial.txs = bodies;
            native::EvaluatedBlock ev;
            std::string            why;
            const bool good = native::evaluate_block(trial, ev, why) == native::EvalStatus::Ok
                            && ev.input.bodies_complete;
            kat::checkf(good, "rig: block %llu evaluates with its bodies (%s)",
                        (unsigned long long)h, why.c_str());
            fees = ev.input.fees;
        }
        BlockEntry e;
        e.block_blob = build_blob(h, ts, &prev, static_cast<std::uint32_t>(h), kBase + fees,
                                  flavour, txids);
        e.txs        = std::move(bodies);
        return e;
    }

    native::OfferResult offer(const BlockEntry& e, const PeerRef& from) {
        return idx->offer_block(&from, e, /*own_mined=*/false);
    }

    void advertise(const PeerRef& p, const Hash& top, std::uint64_t top_height) {
        PeerSyncData d;
        d.current_height = top_height + 1;
        d.top_id         = top;
        d.top_version    = 16;
        d.cumulative_difficulty = U128{0, 1};
        d.support_flags  = 1;
        idx->on_peer_sync_data(p, d);
    }
};

bool has(const std::vector<Hash>& v, const Hash& id) {
    for (const Hash& x : v) if (x == id) return true;
    return false;
}

// ===========================================================================
// A. the oracle
// ===========================================================================
void test_a_oracle() {
    std::printf("== A. the mined oracle (probe_mined) ==\n");
    Chain c;
    if (!c.ok) return;
    const Tx t0 = golden_tx(0), t1 = golden_tx(1);
    const std::uint64_t h1 = kAnchorHeight + 1;
    const auto r = c.offer(c.make(c.anchor_id, h1, {&t0}, 0x22), c.pa);
    kat::checkf(r.outcome == OfferOutcome::Connected, "A: a peer block carrying t0 connects (%s)",
                r.why.c_str());
    const Hash b1 = c.tip_id();

    std::vector<Hash> kis = t0.kis;
    kis.insert(kis.end(), t1.kis.begin(), t1.kis.end());
    std::vector<Hash> mined, spent;
    const bool at_tip = c.idx->probe_mined(b1, {t0.id, t1.id}, kis, mined, spent);
    kat::check(at_tip, "A1 the oracle answers for the tip");
    kat::checkf(mined.size() == 1 && has(mined, t0.id),
                "A2 t0 is mined in the chain ending at the tip (%zu mined)", mined.size());
    kat::checkf(spent.size() == t0.kis.size() && !t0.kis.empty() && has(spent, t0.kis[0]),
                "A3 t0's %zu key image(s) are spent there, t1's are not (%zu spent)",
                t0.kis.size(), spent.size());

    const bool at_parent = c.idx->probe_mined(c.anchor_id, {t0.id}, t0.kis, mined, spent);
    kat::check(at_parent && mined.empty() && spent.empty(),
               "A4 in the chain ending at the PARENT, t0 is not mined (a block on the parent may "
               "carry it)");
    kat::check(!c.idx->probe_mined(tag_hash(7, 0x77), {t0.id}, {}, mined, spent),
               "A5 a parent not on the best chain is unanswerable");
}

// ===========================================================================
// C. the reorg returns the bodies, and the oracle follows it
// ===========================================================================
void test_c_reorg() {
    std::printf("== C. reorg: bodies back to the pool, oracle follows ==\n");
    Chain c;
    if (!c.ok) return;
    const Tx t0 = golden_tx(0), t1 = golden_tx(1);
    const std::uint64_t h1 = kAnchorHeight + 1;
    (void)c.offer(c.make(c.anchor_id, h1, {&t0}, 0x22), c.pa);
    const Hash b1 = c.tip_id();
    c.tx_events.clear();

    // A heavier branch off the anchor: two blocks, the first mining t1.
    const BlockEntry c1 = c.make(c.anchor_id, h1, {&t1}, 0x44);
    const Hash       c1_id = id_of_blob(c1.block_blob);
    (void)c.offer(c1, c.pb);
    const BlockEntry c2 = c.make(c1_id, h1 + 1, {}, 0x45);
    (void)c.offer(c2, c.pb);
    kat::checkf(c.tip_id() == id_of_blob(c2.block_blob), "C: the heavier branch was adopted "
                "(tip h=%llu)", (unsigned long long)c.tip_height());

    const native::BlockTxEvent* disc = nullptr;
    for (const auto& e : c.tx_events)
        if (e.kind == native::BlockTxEvent::Kind::Disconnected && e.block_id == b1) disc = &e;
    kat::check(disc != nullptr, "C1 the switch raised a Disconnected event for the old block");
    if (disc) {
        kat::checkf(disc->tx_blobs.size() == 1 && disc->tx_blobs[0] == t0.blob
                        && disc->tx_blobs_complete,
                    "C2 it CARRIES t0's body back to the pool (%zu blobs; before the fix: 0, so "
                    "a reorg silently dropped every fee of the losing branch)",
                    disc->tx_blobs.size());
    }
    std::vector<Hash> mined, spent;
    const bool ans = c.idx->probe_mined(c.tip_id(), {t0.id, t1.id}, {}, mined, spent);
    kat::checkf(ans && mined.size() == 1 && has(mined, t1.id),
                "C3 after the switch the oracle says t1 is mined and t0 is not (%zu mined)",
                mined.size());
}

// ===========================================================================
// D. the template, over the real index, with a pool that was never told
// ===========================================================================
void test_d_template() {
    std::printf("== D. template on the new tip (NativeMinerDataSource over the index) ==\n");
    Chain c;
    if (!c.ok) return;
    const Tx t0 = golden_tx(0), t1 = golden_tx(1), t2 = golden_tx(2);
    const Tx tw = twin_of(t2);

    native::fakes::FakeTxpool pool;
    pool.configured.min_peers = 0;
    auto add = [&](const Tx& t, std::uint64_t fee) {
        pool.add(t.id, t.blob.size(), fee, native::EVIDENCE_DAEMONLESS_DEFAULT, /*peers=*/2);
        pool.entries[native::fakes::FakeTxpool::key_of(t.id)].key_images = t.kis;
        pool.entries[native::fakes::FakeTxpool::key_of(t.id)].blob       = t.blob;
    };
    add(t0, 90000000);   // will be mined by the peer block
    add(t1, 80000000);   // stays valid
    add(tw, 70000000);   // spends t2's key images, which the peer block mines

    native::tmpl::NativeTemplatePolicy pol;
    pol.band_div = 0;   // the band is not what this suite is about
    native::tmpl::NativeMinerDataSource src(*c.idx, pool, pol, &pool);

    std::string why;
    const auto before = src.snapshot(&why);
    kat::checkf(before.has_value() && before->tx_backlog.size() == 3,
                "D0 (control) on the anchor all three pooled txs are served (%zu, %s)",
                before ? before->tx_backlog.size() : 0, why.c_str());

    // The peer block lands; the pool is NOT told (the race: its eviction runs
    // on another thread, later).
    (void)c.offer(c.make(c.anchor_id, kAnchorHeight + 1, {&t0, &t2}, 0x22), c.pa);
    const auto md = src.snapshot(&why);
    kat::checkf(md.has_value(), "D1 a template is served on the new tip (%s)", why.c_str());
    if (!md) return;
    kat::check(md->prev_id == c.tip_id(), "D2 ...built on the new tip");
    bool has_t0 = false, has_t1 = false, has_tw = false;
    for (const auto& e : md->tx_backlog) {
        has_t0 = has_t0 || e.id == t0.id;
        has_t1 = has_t1 || e.id == t1.id;
        has_tw = has_tw || e.id == tw.id;
    }
    kat::checkf(!has_t0, "D3 it does NOT carry t0, which the new tip mined (the 86f666b7 case)");
    kat::checkf(!has_tw, "D4 it does NOT carry the tx spending a key image the tip spent");
    kat::checkf(has_t1, "D5 it DOES carry t1 (good citizen: every valid tx stays in)");
    kat::checkf(src.last_dropped_mined() == 2 && src.dropped_mined() == 2,
                "D6 two entries were dropped for the chain (%zu last, %llu total)",
                src.last_dropped_mined(), (unsigned long long)src.dropped_mined());
    kat::check(src.good_citizen_violations() == 0, "D7 no good-citizen violation");
}

} // namespace

int main() {
    std::printf("=== xmr_template_dup_tx_kat ===\n");
    test_a_oracle();
    test_c_reorg();
    test_d_template();
    return kat::report("xmr_template_dup_tx_kat");
}
