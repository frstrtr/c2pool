// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_neartip_stall_kat.cpp
//
// NEAR-TIP STALL: an anchor-booted node that catches up across a gap wider
// than its row window must reach the network tip, whatever the network pushes
// at it while it is still behind.
//
// THE DEFECT, as the mainnet format-2 dry run showed it (anchor 3765865, gap
// 2705 > row_retention 2048, --output-set seeded): catch-up verified up to
// 3768570 and then sat there for the rest of the run --
//
//     h=3768570/3768583 verified=3768570 synced=0 rows=2048 | alt=512 ...
//
// with fluffy_req=0 from start to end. The peers had pushed 3768571..3768575
// as NOTIFY_NEW_FLUFFY_BLOCK (blob, no transactions) while the node was still
// behind; each was parked with its parent unknown. When 3768570 connected, the
// fast path resolved those parks (difficulty, proof of work) and made them
// adoptable -- WITHOUT marking them bodies_missing, which only the fast-path
// NeedsBodies park did (#1680). From then on nothing could ask for the
// transactions: bodies_wanted() lists only flagged parks, refetch_wanted()
// skips ids whose blob is held, and a chain entry skips ids already in the
// pool. Every later push attached to the stranded branch, the fork choice
// planned a switch onto it, the apply failed on the bodiless block, and the
// rollback erased only the branch TOP and charged the pushing peer with
// BadData. One block in, one block peeled, forever.
//
// A SECOND, INDEPENDENT STRAND (seen in the traced reproduction at 3768592):
// AltPool::erase_key_() dropped the erased block's own children list, so a
// block that sat in the pool before it connected (held: the verifier was not
// ready) took the edges to its parked children with it, and they were never
// drained onto the new tip.
//
// WHAT IS BUILT HERE, and why each part is not decoration:
//
//   * a FORMAT-2 stagenet anchor bundle whose committed output set is a real
//     ChainOutputSet snapshot, booted through ChainBoot with gate 4 confirmed
//     by the network, and the output set seeded from that snapshot exactly as
//     --output-set does (seed_from_snapshot against the anchor's roots) and fed
//     from the index's own tx events as blocks connect;
//   * row_retention set just above the 735-row difficulty window and a
//     catch-up gap LONGER than it, so the anchor row and everything near it
//     has left the window by the time the tip is reached -- the live shape,
//     scaled down so the KAT runs in seconds (the branch windows near the tip
//     are still assemblable, as they are at 2048);
//   * the pushes arrive while the node is behind, carry real mainnet
//     BulletproofPlus transactions (so "bodies" are real bodies, hashed to the
//     ids the block commits to and paid for in the coinbase), and the sync
//     driver is modelled by what it actually does: GET_OBJECTS for
//     bodies_wanted() and refetch_wanted(), answered from the network's copy.
//
//   A  STRAND    -- after catch-up the stranded park is listed by
//                   bodies_wanted(); a further push does not peel it; nobody
//                   is penalised; the driver model brings the tip to the
//                   network tip, synced, with the output set consistent.
//   B  EDGES     -- a parent held (verifier down) before it connects still
//                   drains its parked child once it does.
//
// Both A and B FAIL on master 481c76af (tip frozen at the gap / one below the
// child) and pass with the fix. No sockets, no RandomX, no daemon: a model
// verifier stands in for the PoW source, as in the chain-index KAT.
// Registered in BOTH `--target` lists in .github/workflows/build.yml -- a
// registered-but-unbuilt target reads as "***Not Run" (the #1539 lesson).
// ---------------------------------------------------------------------------

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/anchor/xmr_anchor_codec.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_load.hpp"
#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/chain/xmr_output_set.hpp"
#include "impl/xmr/native/chain/xmr_pow_gate.hpp"
#include "impl/xmr/native/consensus/xmr_block_id.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/contracts/fakes/fake_fetcher.hpp"
#include "impl/xmr/native/node/xmr_chain_boot.hpp"
#include "impl/xmr/native/node/xmr_sync_driver.hpp"
#include "impl/xmr/native/p2p/chain_seeds.hpp"
#include "xmr_input_consensus_golden.hpp"
#include "xmr_p2p_kat_util.hpp"

namespace native = c2pool::xmr::native;
namespace rt     = c2pool::xmr::native::rt;
namespace kat    = c2pool::xmr::native::kat;
namespace T      = c2pool::xmr::native::test;

using native::BlockEntry;
using native::Hash;
using native::OfferOutcome;
using native::PeerRef;
using native::PeerSyncData;
using native::U128;

namespace {

// ===========================================================================
// 0. fixtures
// ===========================================================================
constexpr std::uint64_t kAnchorHeight = 2204000;      // a real stagenet height, HF 16
constexpr std::uint64_t kAnchorTs     = 1788965550;
constexpr std::size_t   kRetention    = 768;          // > DIFFICULTY_BLOCKS_COUNT (735)
constexpr std::uint64_t kGap          = 800;          // > kRetention: the anchor leaves the window

// Shaped exactly like c2pool::xmr::LightVerifier (the chain-index KAT's model).
class ModelVerifier {
public:
    enum class VerifyStatus { Accept, BelowTarget, SeedNotResident, NotInitialized };

    bool prefetch_epoch(const Hash& current, const std::optional<Hash>& next) {
        if (down_) return false;
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
        if (down_) return VerifyStatus::NotInitialized;
        if (!seed_resident(seed)) return VerifyStatus::SeedNotResident;
        ++hashes;
        for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(i);
        return VerifyStatus::Accept;
    }
    void set_down(bool v) { down_ = v; }

    std::uint64_t hashes = 0;

private:
    std::optional<Hash> cur_, nxt_;
    bool down_ = false;
};

void put_varint(std::vector<std::uint8_t>& o, std::uint64_t v) { native::blob_write_varint(o, v); }

Hash hash_from_hex(const char* hex) {
    const std::vector<std::uint8_t> b = kat::from_hex(hex);
    Hash h{};
    for (std::size_t i = 0; i < h.size() && i < b.size(); ++i) h[i] = b[i];
    return h;
}

Hash tag_hash(std::uint64_t seed, std::uint8_t tag) {
    Hash h{};
    for (std::size_t i = 0; i < 8; ++i) h[i] = static_cast<std::uint8_t>(seed >> (8 * i));
    for (std::size_t i = 8; i < h.size(); ++i) h[i] = static_cast<std::uint8_t>(tag + i);
    return h;
}

// A structurally real HF-16 Monero block: v2 coinbase paying `reward` to one
// tagged-key output, and `txids` as the committed transaction ids.
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

    put_varint(b, 2);                                        // miner_tx version
    put_varint(b, height + 60);                              // unlock_time
    put_varint(b, 1);                                        // one input
    b.push_back(native::TX_IN_GEN);
    put_varint(b, height);
    put_varint(b, 1);                                        // one output
    put_varint(b, reward);
    b.push_back(native::TX_OUT_TO_TAGGED_KEY);
    for (std::size_t i = 0; i < 33; ++i)
        b.push_back(static_cast<std::uint8_t>((i * 7u) ^ flavour ^ (height & 0xff)));
    {
        std::vector<std::uint8_t> extra;
        extra.push_back(0x01);                               // TX_EXTRA_TAG_PUBKEY
        for (std::size_t i = 0; i < 32; ++i)
            extra.push_back(static_cast<std::uint8_t>((i * 3u) + flavour));
        put_varint(b, extra.size());
        b.insert(b.end(), extra.begin(), extra.end());
    }
    b.push_back(0x00);                                       // rct type NULL
    put_varint(b, txids.size());
    for (const Hash& t : txids) b.insert(b.end(), t.begin(), t.end());
    return b;
}

Hash id_of_blob(const std::vector<std::uint8_t>& blob) {
    native::ParsedBlock pb;
    if (native::parse_block(blob, pb) != native::BlockParseStatus::Ok) return Hash{};
    return native::block_identity(blob.data(), pb).id;
}

// The network's copy of one block: the full entry (what GET_OBJECTS returns)
// and the bare blob (what a fluffy push carries when we hold none of its txs).
struct NetBlock {
    std::uint64_t height = 0;
    Hash          id{};
    BlockEntry    full;
    BlockEntry    bodiless() const {
        BlockEntry e;
        e.block_blob = full.block_blob;
        return e;
    }
};

PeerRef peer(const char* addr, std::uint64_t id) {
    PeerRef p;
    p.addr    = addr;
    p.peer_id = id;
    return p;
}

// A valid stagenet bundle at a real stagenet height (the gate-4 / snapshot
// KATs' fixture), made FORMAT-2 by committing `set`.
native::AnchorBundle make_bundle(const Hash& id, const native::ChainOutputSet& set,
                                 std::uint64_t os_base_height) {
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
    // No monerod checkpoint above the anchor, as on mainnet today (monerod's
    // compiled-in list ends far below a fresh anchor). A checkpoint above the
    // tip would refuse EVERY switch as BelowCheckpoint and hide the failed-switch
    // path this file exercises.

    // FORMAT 2: the committed output set (what --output-set is verified against).
    b.rct_output_count       = set.frontier();
    b.output_set_base_height = os_base_height;
    b.output_set_leaves      = set.output_leaf_count();
    b.output_set_root        = set.output_root();
    b.spent_set_leaves       = set.spent_leaf_count();
    b.spent_set_root         = set.spent_root();

    b.digest = native::anchor_digest(b);
    return b;
}

// ===========================================================================
// The rig: anchor boot + output set + a network chain, and the driver model.
// ===========================================================================
struct Rig {
    ModelVerifier                                   mv;
    native::LightVerifierPowSource<ModelVerifier>   src{mv};
    native::ChainIndex*                             idx  = nullptr;
    rt::ChainBoot*                                  boot = nullptr;
    native::fakes::FakeFetcher                      fetcher;
    native::ChainOutputSet                          outs{0};
    std::vector<std::uint8_t>                       anchor_blob;
    Hash                                            anchor_id{};
    std::vector<NetBlock>                           net;   // net[k] is height anchor+1+k
    std::map<std::string, std::size_t>              net_by_id;
    std::uint64_t                                   out_connected = 0;
    std::uint64_t                                   out_failed    = 0;
    std::size_t                                     golden_next   = 0;
    PeerRef                                         pa = peer("198.51.100.1:38080", 1001);
    PeerRef                                         pb = peer("198.51.100.2:38080", 1002);
    bool                                            ok = false;

    static std::string key(const Hash& h) {
        return std::string(reinterpret_cast<const char*>(h.data()), h.size());
    }

    Rig() {
        // --- the anchor block and the pre-anchor output set it commits ---------
        anchor_blob = build_blob(kAnchorHeight, kAnchorTs, nullptr, 0x0badc0de,
                                 600000000000ull, 0x11, {});
        anchor_id = id_of_blob(anchor_blob);

        const std::uint64_t os_base = kAnchorHeight - 3;
        native::ChainOutputSet built(0);
        for (std::uint64_t h = os_base; h <= kAnchorHeight; ++h) {
            native::BlockTxEvent e;
            e.kind                    = native::BlockTxEvent::Kind::Connected;
            e.height                  = h;
            e.first_output_index      = built.frontier();
            e.block_id                = h == kAnchorHeight ? anchor_id : tag_hash(h, 0x44);
            e.coinbase_amount_pubkeys = {{600000000000ull, tag_hash(h, 0x55)}};
            e.coinbase_unlock_time    = h + 60;
            e.key_images              = {tag_hash(h, 0x66)};
            kat::checkf(built.on_block_connected(e), "rig: pre-anchor block %llu feeds the set",
                        (unsigned long long)h);
        }
        const std::string snapshot = built.serialize();
        const native::AnchorBundle bundle = make_bundle(anchor_id, built, os_base);
        kat::check(bundle.has_output_set(), "rig: the bundle is FORMAT-2 (commits an output set)");

        const std::string path = "neartip_kat_anchor_f2.inc";
        {
            std::ofstream f(path, std::ios::binary | std::ios::trunc);
            f << native::write_anchor_inc(bundle, "near-tip stall KAT bundle (format 2)");
        }

        native::ChainIndexOptions o;
        o.net           = native::XmrNet::Stagenet;
        o.row_retention = kRetention;
        idx  = new native::ChainIndex(o, src);
        idx->set_fetcher(&fetcher);
        boot = new rt::ChainBoot(*idx, rt::BootMode::Anchor,
                                 native::p2p::genesis_id(native::p2p::XmrNet::Stagenet),
                                 native::XmrNet::Stagenet);
        std::string why;
        const bool installed = boot->boot_from_anchor(path, native::XmrNet::Stagenet, {}, why);
        std::remove(path.c_str());
        kat::checkf(installed, "rig: gates 1..3 accept the format-2 bundle (%s)", why.c_str());
        if (!installed) return;
        const native::AnchorBundle* ab = boot->anchor();
        kat::check(ab && ab->has_output_set(), "rig: the booted anchor is format-2");
        if (!ab) return;

        // --output-set: seeded against the anchor's committed roots, before any
        // block connects, exactly as NativeNode::start() does it.
        kat::check(outs.reset_base(idx->view().rct_output_count()),
                   "rig: output set numbered from the anchor's rct_output_count");
        std::string seed_why;
        kat::checkf(outs.seed_from_snapshot(snapshot, *ab, seed_why),
                    "rig: the output-set snapshot seeds against the anchor (%s)", seed_why.c_str());
        idx->subscribe_txs([this](const native::BlockTxEvent& e) {
            const bool fed = e.kind == native::BlockTxEvent::Kind::Connected
                           ? outs.on_block_connected(e) : outs.on_block_disconnected(e);
            if (e.kind == native::BlockTxEvent::Kind::Connected) ++out_connected;
            if (!fed) ++out_failed;
        });

        // Gate 4: the network confirms the anchor (its block arrives as the
        // answer to our GET_OBJECTS).
        {
            std::vector<BlockEntry> blocks(1);
            blocks[0].block_blob = anchor_blob;
            boot->on_objects(pa, std::move(blocks), {}, kAnchorHeight + 1);
        }
        kat::check(boot->serving_ready(), "rig: gate 4 confirmed the anchor");
        ok = boot->serving_ready();
    }

    ~Rig() {
        delete boot;
        delete idx;
    }

    std::uint64_t tip_height() const { return idx->tip() ? idx->tip()->height : 0; }
    std::uint64_t net_top() const { return kAnchorHeight + net.size(); }
    const NetBlock& at(std::uint64_t h) const { return net[static_cast<std::size_t>(h - kAnchorHeight - 1)]; }

    // Extend the network's chain by one block, optionally carrying one real
    // mainnet transaction (so its body is a real body, paid for in the coinbase).
    void grow(bool with_tx) {
        const std::uint64_t h    = net_top() + 1;
        const Hash          prev = net.empty() ? anchor_id : net.back().id;
        const std::uint64_t ts   = kAnchorTs + 120 * (h - kAnchorHeight);
        const std::uint64_t base = 600000000000ull;   // stagenet tail emission here

        std::vector<Hash>              txids;
        std::vector<native::TxBlobEntry> bodies;
        if (with_tx) {
            const auto& g = T::input_consensus_golden();
            const T::GoldenTx& tx = g[golden_next++ % g.size()];
            txids.push_back(hash_from_hex(tx.id));
            native::TxBlobEntry te;
            te.blob = kat::from_hex(tx.full_hex);
            bodies.push_back(std::move(te));
        }
        // Price the coinbase: base plus whatever the bodies pay in fees.
        std::uint64_t fees = 0;
        {
            BlockEntry trial;
            trial.block_blob = build_blob(h, ts, &prev, static_cast<std::uint32_t>(h), base,
                                          0x22, txids);
            trial.txs = bodies;
            native::EvaluatedBlock ev;
            std::string            why;
            const bool good = native::evaluate_block(trial, ev, why) == native::EvalStatus::Ok
                            && ev.input.bodies_complete;
            kat::checkf(good, "net: block %llu evaluates with its bodies (%s)",
                        (unsigned long long)h, why.c_str());
            fees = ev.input.fees;
        }
        NetBlock nb;
        nb.height           = h;
        nb.full.block_blob  = build_blob(h, ts, &prev, static_cast<std::uint32_t>(h),
                                         base + fees, 0x22, txids);
        nb.full.txs         = std::move(bodies);
        nb.id               = id_of_blob(nb.full.block_blob);
        net_by_id[key(nb.id)] = net.size();
        net.push_back(std::move(nb));
    }

    void advertise() {
        PeerSyncData d;
        d.current_height = net_top() + 1;   // monerod's "one past the tip"
        d.top_id         = net.empty() ? anchor_id : net.back().id;
        d.top_version    = 16;
        d.cumulative_difficulty = U128{0, 1};
        d.support_flags  = 1;
        boot->on_peer_sync_data(pa, d);
        boot->on_peer_sync_data(pb, d);
    }

    // GET_OBJECTS answer for a span of network heights [lo, hi].
    void deliver_span(std::uint64_t lo, std::uint64_t hi) {
        std::vector<BlockEntry> blocks;
        for (std::uint64_t h = lo; h <= hi; ++h) blocks.push_back(at(h).full);
        boot->on_objects(pa, std::move(blocks), {}, net_top() + 1);
    }

    void push_fluffy(std::uint64_t h) {
        boot->on_new_block(pb, at(h).bodiless(), net_top() + 1, /*fluffy=*/true);
    }
    void push_full(std::uint64_t h) {
        boot->on_new_block(pb, BlockEntry(at(h).full), net_top() + 1, /*fluffy=*/false);
    }

    // The sync driver, reduced to what it does between ticks once the grace
    // timers have run: ask for bodies_wanted() (#1680's GET_OBJECTS fallback)
    // and refetch_wanted(), and take whatever the network answers.
    std::size_t drive(int rounds) {
        std::size_t delivered = 0;
        for (int r = 0; r < rounds; ++r) {
            std::vector<Hash> want = idx->bodies_wanted();
            for (const Hash& h : idx->refetch_wanted()) want.push_back(h);
            std::vector<BlockEntry> reply;
            std::vector<Hash>       missed;
            for (const Hash& h : want) {
                const auto it = net_by_id.find(key(h));
                if (it == net_by_id.end()) { missed.push_back(h); continue; }
                reply.push_back(net[it->second].full);
            }
            if (reply.empty()) break;
            delivered += reply.size();
            boot->on_objects(pa, std::move(reply), std::move(missed), net_top() + 1);
        }
        return delivered;
    }
};

bool has(const std::vector<Hash>& v, const Hash& id) {
    for (const Hash& x : v) if (x == id) return true;
    return false;
}

// ===========================================================================
// A. the stranded bodiless park
// ===========================================================================
void test_strand_after_gap() {
    Rig rig;
    if (!rig.ok) return;

    // The network is kGap + 2 blocks ahead of the anchor when we start; the two
    // newest are non-empty (they carry transactions), as every mainnet block is.
    for (std::uint64_t k = 0; k < kGap; ++k) rig.grow(/*with_tx=*/false);
    rig.grow(true);                                   // G+1
    rig.grow(true);                                   // G+2
    rig.advertise();
    const std::uint64_t G = kAnchorHeight + kGap;

    // Catch-up: GET_OBJECTS spans of 100, all but the last.
    std::uint64_t h = kAnchorHeight + 1;
    for (; h + 100 <= G - 100 + 1; h += 100) rig.deliver_span(h, h + 99);
    kat::checkf(rig.tip_height() == h - 1, "A: catch-up reached %llu (tip %llu)",
                (unsigned long long)(h - 1), (unsigned long long)rig.tip_height());

    // While we are still behind, the peers push the two newest blocks as fluffy
    // blocks (blob, no transactions). Their parents are not in the index yet.
    rig.push_fluffy(G + 1);
    rig.push_fluffy(G + 2);
    kat::check(rig.idx->have_block(rig.at(G + 1).id) && rig.idx->have_block(rig.at(G + 2).id),
               "A: both pushes are parked while we are behind");

    // The last span lands: the gap is closed, and the parent of the first push
    // is the tip.
    rig.deliver_span(h, G);
    kat::checkf(rig.tip_height() == G, "A: catch-up closed the gap (tip %llu, expected %llu)",
                (unsigned long long)rig.tip_height(), (unsigned long long)G);
    kat::checkf(rig.idx->have_block(rig.at(G + 1).id) && rig.idx->have_block(rig.at(G + 2).id),
                "A: both parks survive their parent's connect (held %d/%d; on master the failed "
                "switch onto them erased the branch top)",
                rig.idx->have_block(rig.at(G + 1).id) ? 1 : 0,
                rig.idx->have_block(rig.at(G + 2).id) ? 1 : 0);
    kat::checkf(rig.fetcher.penalties.empty(),
                "A: no peer is penalised when the parent connects (%zu penalties%s%s)",
                rig.fetcher.penalties.size(), rig.fetcher.penalties.empty() ? "" : ": ",
                rig.fetcher.penalties.empty() ? "" : rig.fetcher.penalties[0].why.c_str());

    // The window has moved past the anchor: this IS the gap > row-window shape.
    const native::SyncState s0 = rig.idx->sync_state();
    kat::checkf(s0.rows == kRetention, "A: the row window is full (%llu rows)",
                (unsigned long long)s0.rows);
    kat::check(!rig.idx->have_block(rig.anchor_id),
               "A: the anchor row has left the retained window (gap > row window)");

    // THE DEFECT: the resolved, bodiless push must be listed for a bodies fetch.
    const std::vector<Hash> bw = rig.idx->bodies_wanted();
    kat::check(has(bw, rig.at(G + 1).id),
               "A: bodies_wanted() lists the bodiless push whose parent just connected "
               "(on master it is invisible to every re-ask path and the tip freezes)");

    // The network moves on and pushes the next block the same way. On master
    // this is the steady state: it attaches to the stranded branch, the switch
    // fails on the bodiless block, and the pushed block is peeled off again.
    rig.grow(true);                                   // G+3
    rig.advertise();
    rig.push_fluffy(G + 3);
    kat::check(rig.idx->have_block(rig.at(G + 1).id) && rig.idx->have_block(rig.at(G + 3).id),
               "A: a push onto the bodiless branch is kept, not peeled off");
    kat::checkf(rig.fetcher.penalties.empty(),
                "A: no peer is penalised for OUR missing bodies (%zu penalties)",
                rig.fetcher.penalties.size());

    // The driver asks for what the index says it is missing.
    const std::size_t delivered = rig.drive(6);
    kat::checkf(delivered > 0, "A: the driver model found something to ask for");
    kat::checkf(rig.tip_height() == rig.net_top(),
                "A: the tip reached the network tip (tip %llu, network %llu; on master it "
                "stays at %llu)",
                (unsigned long long)rig.tip_height(), (unsigned long long)rig.net_top(),
                (unsigned long long)G);

    // And a push that arrives once we ARE at the tip completes the same way
    // (the #1680 fast-path park, which already worked, still works).
    rig.grow(true);                                   // G+4
    rig.advertise();
    rig.push_fluffy(G + 4);
    rig.drive(3);
    kat::checkf(rig.tip_height() == rig.net_top(), "A: a push at the tip connects (tip %llu)",
                (unsigned long long)rig.tip_height());

    const native::SyncState s1 = rig.idx->sync_state();
    kat::check(s1.synced, "A: the node reports synced at the network tip");
    kat::checkf(rig.idx->bodies_wanted().empty(), "A: nothing is left waiting for bodies");
    kat::checkf(rig.fetcher.penalties.empty(), "A: still no peer penalised (%zu)",
                rig.fetcher.penalties.size());

    // The output set followed every connected block from the seeded frontier.
    kat::checkf(rig.out_failed == 0, "A: the output set accepted every tx event (%llu failed)",
                (unsigned long long)rig.out_failed);
    kat::checkf(rig.outs.frontier() == rig.idx->view().rct_output_count(),
                "A: output-set frontier %llu == index rct_output_count %llu",
                (unsigned long long)rig.outs.frontier(),
                (unsigned long long)rig.idx->view().rct_output_count());
    kat::checkf(rig.out_connected == rig.tip_height() - kAnchorHeight,
                "A: one output-set connect per post-anchor block (%llu, expected %llu)",
                (unsigned long long)rig.out_connected,
                (unsigned long long)(rig.tip_height() - kAnchorHeight));
}

// ===========================================================================
// B. a held parent keeps its children's edges
// ===========================================================================
void test_held_parent_drains_child() {
    Rig rig;
    if (!rig.ok) return;
    for (std::uint64_t k = 0; k < kGap; ++k) rig.grow(false);
    rig.advertise();
    const std::uint64_t G = kAnchorHeight + kGap;
    for (std::uint64_t h = kAnchorHeight + 1; h <= G; h += 100)
        rig.deliver_span(h, std::min(G, h + 99));
    kat::checkf(rig.tip_height() == G, "B: caught up to %llu (tip %llu)",
                (unsigned long long)G, (unsigned long long)rig.tip_height());

    rig.grow(true);                                   // P = G+1
    rig.grow(true);                                   // C = G+2
    rig.advertise();

    // The child arrives first (complete), and is parked: parent unknown.
    rig.push_full(G + 2);
    kat::check(rig.idx->have_block(rig.at(G + 2).id), "B: the child is parked");

    // The parent arrives while the verifier is not ready: held in the pool.
    rig.mv.set_down(true);
    rig.push_full(G + 1);
    rig.mv.set_down(false);
    kat::checkf(rig.tip_height() == G, "B: the held parent did not connect (tip %llu)",
                (unsigned long long)rig.tip_height());

    // It arrives again with the verifier up and connects on the fast path --
    // and its parked child must follow it onto the tip.
    rig.push_full(G + 1);
    kat::checkf(rig.tip_height() == G + 2,
                "B: the parked child was drained onto the tip (tip %llu, expected %llu; on "
                "master the parent's children edges left the pool with it)",
                (unsigned long long)rig.tip_height(), (unsigned long long)(G + 2));
    kat::checkf(rig.out_failed == 0, "B: the output set accepted every tx event (%llu failed)",
                (unsigned long long)rig.out_failed);
}

// ===========================================================================
// C. the cohort: peers behind us are not votes, and a connection is one vote
// ===========================================================================
// The mainnet dry run went from `h=3768570/3768586 synced=0` to
// `h=3768570/1 synced=1` on the next status line and served templates for
// hours at a tip 30-150 blocks stale: fresh-from-genesis monerods (they
// advertise current_height ~1) had dragged the cohort MEDIAN down to 1.
void say(Rig& rig, const PeerRef& p, std::uint64_t current_height) {
    PeerSyncData d;
    d.current_height        = current_height;
    d.top_id                = rig.net.empty() ? rig.anchor_id : rig.net.back().id;
    d.top_version           = 16;
    d.cumulative_difficulty = U128{0, 1};
    d.support_flags         = 1;
    rig.boot->on_peer_sync_data(p, d);
}

void test_cohort_ignores_peers_behind_us() {
    Rig rig;
    if (!rig.ok) return;
    const std::uint64_t G = kAnchorHeight + 200;
    for (std::uint64_t k = 0; k < 200; ++k) rig.grow(false);
    for (std::uint64_t h = kAnchorHeight + 1; h <= G; h += 100)
        rig.deliver_span(h, std::min(G, h + 99));
    rig.advertise();
    kat::checkf(rig.tip_height() == G, "C: caught up to %llu", (unsigned long long)G);
    kat::check(rig.idx->sync_state().synced, "C: level with the honest cohort: synced");

    // The network moves 30 blocks on; the honest peers say so.
    for (int k = 0; k < 30; ++k) rig.grow(false);
    rig.advertise();
    kat::check(!rig.idx->sync_state().synced, "C: 30 behind the honest cohort: NOT synced");

    // Three fresh-from-genesis peers connect.
    const PeerRef f1 = peer("203.0.113.1:18080", 0x0f01);
    const PeerRef f2 = peer("203.0.113.2:18080", 0x0f02);
    const PeerRef f3 = peer("203.0.113.3:18080", 0x0f03);
    say(rig, f1, 1);
    say(rig, f2, 1);
    say(rig, f3, 1);
    const native::SyncState s1 = rig.idx->sync_state();
    kat::checkf(!s1.synced,
                "C: three peers advertising height 1 do not make a stale node synced "
                "(cohort %llu, tip %llu; on master the median fell to 1)",
                (unsigned long long)s1.cohort_height, (unsigned long long)rig.tip_height());
    kat::checkf(s1.cohort_height == rig.net_top() + 1, "C: the cohort is the honest %llu (got %llu)",
                (unsigned long long)(rig.net_top() + 1), (unsigned long long)s1.cohort_height);

    // Three honest anonymity-network peers, all with levin peer_id 0, at the
    // network tip: three connections, three votes. Keyed by peer_id they were
    // one vote, and a single fresh peer could tie them.
    rig.boot->on_peer_gone(rig.pa);
    rig.boot->on_peer_gone(rig.pb);
    const PeerRef z1 = peer("198.51.100.11:18080", 0);
    const PeerRef z2 = peer("198.51.100.12:18080", 0);
    const PeerRef z3 = peer("198.51.100.13:18080", 0);
    say(rig, z1, rig.net_top() + 1);
    say(rig, z2, rig.net_top() + 1);
    say(rig, z3, rig.net_top() + 1);
    // A peer a little ahead of us but behind the network is still plausible.
    const PeerRef s = peer("198.51.100.20:18080", 0x5555);
    const PeerRef t = peer("198.51.100.21:18080", 0x5556);
    say(rig, s, G + 2);
    say(rig, t, G + 2);
    kat::checkf(rig.idx->sync_state().cohort_height == rig.net_top() + 1,
                "C: three peer_id-0 peers are three votes (cohort %llu, expected %llu)",
                (unsigned long long)rig.idx->sync_state().cohort_height,
                (unsigned long long)(rig.net_top() + 1));
    // One of them leaving takes one vote, not all three.
    rig.boot->on_peer_gone(z1);
    kat::checkf(rig.idx->sync_state().cohort_height == rig.net_top() + 1,
                "C: one peer_id-0 peer leaving does not erase the others (cohort %llu)",
                (unsigned long long)rig.idx->sync_state().cohort_height);

    // Catch up: synced again, and the fresh peers do not stop it.
    for (std::uint64_t h = G + 1; h <= rig.net_top(); h += 100)
        rig.deliver_span(h, std::min(rig.net_top(), h + 99));
    kat::checkf(rig.tip_height() == rig.net_top(), "C: caught up again (tip %llu)",
                (unsigned long long)rig.tip_height());
    kat::check(rig.idx->sync_state().synced, "C: level with the network: synced");

    // A liar shouting a huge height is one vote among the plausible ones: it
    // cannot hold us unsynced while two honest peers are level with us.
    const PeerRef liar = peer("192.0.2.66:18080", 0x6666);
    say(rig, liar, 999'999'999);
    kat::check(rig.idx->sync_state().synced, "C: one liar cannot hold us unsynced");

    // Every peer behind or level: nothing says we are behind.
    rig.boot->on_peer_gone(liar);
    rig.boot->on_peer_gone(z2);
    rig.boot->on_peer_gone(z3);
    rig.boot->on_peer_gone(s);
    rig.boot->on_peer_gone(t);
    const native::SyncState s2 = rig.idx->sync_state();
    kat::checkf(s2.synced && s2.cohort_height == rig.tip_height() + 1,
                "C: only peers behind us left: synced, cohort = our tip + 1 (cohort %llu)",
                (unsigned long long)s2.cohort_height);
}

// ===========================================================================
// D. the catch-up livelock (> alt-pool-size blocks outstanding)
// ===========================================================================
// Mainnet, format-2 anchor, ~2650 blocks behind: the tip sat at anchor+64/+128
// for 6-25+ minutes (a whole run on the dry run), alt=512, orphans 45k-76k,
// refetch climbing ~2/s with ~95% of chain requests "timing out". Four parts,
// asserted on their own (D1, D2 here; D3 in xmr_chain_index_kat's wire test,
// the silent span drop in xmr_peer_pool_kat) and then together in D4:
//   D1 the alt pool evicted the OLDEST unresolved block -- the one nearest the
//      tip, asked for first;
//   D2 every push far above the tip was parked while behind, and its parent
//      went onto an UNBOUNDED refetch list (one GET_OBJECTS per round trip,
//      walking down from the network tip);
//   D3 the index put a whole chain entry (up to 2048 ids) on the wire as ONE
//      span, which the pool delivers only when all of its chunks are in, and
//      the pool dropped a span over its caps silently after the driver had
//      booked its ids as asked;
//   D4 end to end, against a model of the pool (D-3 caps, a span delivered
//      whole when its last <=100-id chunk lands, a peer dropping now and then
//      and taking its spans with it) and the REAL SyncDriver.

// D1 ---------------------------------------------------------------------
void test_evict_far_unresolved_first() {
    native::AltPool pool;
    pool.set_caps(4, 0);
    std::uint64_t seq = 0;
    auto park = [&](std::uint64_t height) {
        native::AltBlock b;
        b.id             = tag_hash(height, 0x70);
        b.prev_id        = tag_hash(height - 1, 0x71);   // unknown parent: unresolved
        b.height         = height;
        b.resolved       = false;
        b.first_seen_seq = ++seq;
        pool.insert(std::move(b));
    };
    park(101);                        // the next block we need: asked (and arrived) first
    park(105);
    park(104);
    park(103);
    park(102);                        // pool full: somebody goes
    kat::check(pool.contains(tag_hash(101, 0x70)),
               "D1: the unresolved block nearest the tip survives eviction "
               "(on master the oldest arrival -- this one -- was the victim)");
    kat::check(!pool.contains(tag_hash(105, 0x70)),
               "D1: the farthest unresolved block is the one evicted");
    kat::check(pool.size() == 4, "D1: the cap holds");
}

// D2 ---------------------------------------------------------------------
void test_far_pushes_not_parked_while_behind() {
    Rig rig;
    if (!rig.ok) return;
    const std::uint64_t N = 900;
    for (std::uint64_t k = 0; k < N; ++k) rig.grow(false);
    rig.advertise();
    kat::check(!rig.idx->sync_state().synced, "D2: behind the cohort");

    // 300 pushes of blocks 600..899 above the anchor: every one of them farther
    // above our tip than the 512-block pool.
    for (std::uint64_t h = kAnchorHeight + 600; h < kAnchorHeight + N; ++h) rig.push_full(h);
    const std::size_t alt = rig.idx->alt_size();
    const std::size_t rf  = rig.idx->refetch_wanted().size();
    kat::checkf(alt == 0, "D2: far pushes are not parked while behind (alt %zu)", alt);
    kat::checkf(rf == 0, "D2: and ask for no parents (refetch %zu)", rf);
    kat::checkf(rig.idx->orphans_parked() == 0, "D2: none counted as parked (%llu)",
                (unsigned long long)rig.idx->orphans_parked());

    // A push NEAR the tip still parks (it is what a chain entry is about to
    // explain), and its parent is asked for.
    rig.push_full(kAnchorHeight + 10);
    kat::check(rig.idx->have_block(rig.at(kAnchorHeight + 10).id), "D2: a near push still parks");

    // And the refetch list is bounded on this path too. Synced (so pushes park
    // wherever they claim to be), 450 parks with distinct unknown parents name
    // at most 256 of them; on master the list grew by one per park, unbounded.
    Rig r2;
    if (!r2.ok) return;
    r2.idx->force_synced(true);
    for (std::uint64_t k = 0; k < 900; ++k) r2.grow(false);
    for (std::uint64_t h = kAnchorHeight + 3; h < kAnchorHeight + 900; h += 2) r2.push_full(h);
    kat::checkf(r2.idx->refetch_wanted().size() <= 256,
                "D2: the refetch list stays bounded (%zu)", r2.idx->refetch_wanted().size());
}

// D4: the pool model ------------------------------------------------------
class PoolModel final : public native::IChainFetcher {
public:
    explicit PoolModel(Rig& rig) : rig_(rig) {}

    std::uint64_t kWireSteps = 3;   // steps (500 ms each) one wire round takes

    struct Link {
        PeerRef       ref;
        bool          up = true;
        std::uint64_t clock = 0;
        struct Span { std::vector<Hash> ids; std::size_t done = 0; };
        std::deque<Span>                 spans;
        std::deque<std::vector<Hash>>    chain_asks;
    };
    std::vector<Link> links;

    std::uint64_t spans_accepted = 0, spans_refused = 0, spans_lost = 0, chains = 0;

    bool request_chain(const PeerRef& p, std::vector<Hash> locator, bool) override {
        Link* l = find_(p);
        if (!l || !l->up) return false;
        l->chain_asks.push_back(std::move(locator));
        ++chains;
        return true;
    }
    bool request_objects(const PeerRef& p, std::vector<Hash> ids, bool) override {
        Link* l = find_(p);
        if (!l || !l->up || ids.empty() || ids.size() > native::MAX_SPAN_IDS) return false;
        std::size_t total = 0;
        for (const Link& x : links) total += x.spans.size();
        if (l->spans.size() >= native::MAX_SPANS_PER_PEER || total >= native::MAX_SPANS_TOTAL) {
            ++spans_refused;
            return false;
        }
        l->spans.push_back({std::move(ids), 0});
        ++spans_accepted;
        return true;
    }
    bool request_fluffy_missing(const PeerRef&, const Hash&, std::uint64_t,
                                std::vector<std::uint64_t>) override { return true; }
    void penalize(const PeerRef&, native::PeerFault, const std::string&) override {}
    std::vector<std::pair<PeerRef, PeerSyncData>> peers() const override {
        std::vector<std::pair<PeerRef, PeerSyncData>> out;
        for (const Link& l : links) if (l.up) out.emplace_back(l.ref, sync_());
        return out;
    }

    // One wire round per link every kWireSteps: a chain answer if one is
    // queued (it shares the wire with the span chunks), else one <=100-id
    // chunk of the head span; the span reaches the index only when its LAST
    // chunk is in.
    void step() {
        for (Link& l : links) {
            if (!l.up) continue;
            if (++l.clock % kWireSteps != 0) continue;
            if (!l.chain_asks.empty()) {
                answer_chain_(l, l.chain_asks.front());
                l.chain_asks.pop_front();
                continue;
            }
            if (l.spans.empty()) continue;
            Link::Span& sp = l.spans.front();
            sp.done = std::min(sp.ids.size(), sp.done + native::MAX_OBJECT_REQUEST_IDS);
            if (sp.done < sp.ids.size()) continue;
            std::vector<BlockEntry> blocks;
            std::vector<Hash>       missed;
            for (const Hash& h : sp.ids) {
                const auto it = rig_.net_by_id.find(Rig::key(h));
                if (it == rig_.net_by_id.end()) missed.push_back(h);
                else blocks.push_back(rig_.net[it->second].full);
            }
            l.spans.pop_front();
            rig_.boot->on_objects(l.ref, std::move(blocks), std::move(missed), rig_.net_top() + 1);
        }
    }

    // close_peer(): the link and everything queued on it are gone.
    void drop(std::size_t i) {
        Link& l = links[i];
        spans_lost += l.spans.size();
        l.spans.clear();
        l.chain_asks.clear();
        l.up = false;
        rig_.boot->on_peer_gone(l.ref);
    }
    void reconnect(std::size_t i) {
        links[i].up = true;
        rig_.boot->on_peer_sync_data(links[i].ref, sync_());
    }

private:
    Link* find_(const PeerRef& p) {
        for (Link& l : links) if (l.ref.addr == p.addr) return &l;
        return nullptr;
    }
    PeerSyncData sync_() const {
        PeerSyncData d;
        d.current_height        = rig_.net_top() + 1;
        d.top_id                = rig_.net.empty() ? rig_.anchor_id : rig_.net.back().id;
        d.top_version           = 16;
        d.cumulative_difficulty = U128{0, 1};
        d.support_flags         = 1;
        return d;
    }
    // monerod's find_blockchain_supplement, on the network's chain.
    void answer_chain_(Link& l, const std::vector<Hash>& locator) {
        std::uint64_t splice = 0;
        Hash          splice_id{};
        for (const Hash& h : locator) {
            if (h == rig_.anchor_id) { splice = kAnchorHeight; splice_id = h; break; }
            const auto it = rig_.net_by_id.find(Rig::key(h));
            if (it != rig_.net_by_id.end()) { splice = rig_.net[it->second].height; splice_id = h; break; }
        }
        if (splice == 0) return;
        native::ChainEntry e;
        e.start_height = splice;
        e.total_height = rig_.net_top() + 1;
        e.ids.push_back(splice_id);
        for (std::uint64_t h = splice + 1; h <= rig_.net_top() && e.ids.size() < 2001; ++h)
            e.ids.push_back(rig_.at(h).id);
        rig_.boot->on_chain_entry(l.ref, std::move(e));
    }

    Rig& rig_;
};

struct CatchUp {
    std::uint64_t steps_to_tip  = 0;     // 0 = never reached
    std::uint64_t longest_flat  = 0;     // steps without the tip moving, while behind
    std::size_t   alt_max       = 0;
    std::uint64_t orphans       = 0;
    std::uint64_t spans_refused = 0, spans_lost = 0, chains = 0;
    std::uint64_t chain_timeouts = 0;
};

// The live shape: the network 2600 blocks ahead of the anchor (the mainnet gap;
// > the 512-block alt pool and > one 2048-id chain entry), three peers, one
// wire round (a chain answer or a <=100-id chunk) every 3 s, a peer dropping
// every 20 s and back 1 s later, and the network finding a block every 30 s
// that every peer pushes to us. Steps are the driver's 500 ms ticks.
//
// On d24844b5 this reproduces the mainnet signature: the tip freezes at
// anchor+128..+320 for the rest of the budget, alt=512, orphans in the tens of
// thousands, a chain "timeout" roughly every 20 s.
CatchUp run_catch_up(std::uint64_t budget_steps) {
    CatchUp out;
    Rig rig;
    if (!rig.ok) return out;
    const std::uint64_t GAP = 2600, WIRE = 6, DROP = 40, PUSH = 60;
    for (std::uint64_t k = 0; k < GAP; ++k) rig.grow(false);

    PoolModel pool(rig);
    pool.kWireSteps = WIRE;
    for (int i = 0; i < 3; ++i) {
        PoolModel::Link l;
        l.ref = peer(i == 0 ? "198.51.100.31:18080" : i == 1 ? "198.51.100.32:18080"
                                                              : "198.51.100.33:18080",
                     static_cast<std::uint64_t>(3100 + i));
        pool.links.push_back(std::move(l));
    }
    for (std::size_t i = 0; i < pool.links.size(); ++i) pool.reconnect(i);

    rt::SyncDriver driver(pool, *rig.boot, *rig.idx,
                          native::p2p::genesis_id(native::p2p::XmrNet::Stagenet),
                          [&] { return rig.boot->booted(); },
                          [&] { return rig.idx->refetch_wanted(); },
                          [&] { return rig.idx->bodies_wanted(); });

    std::uint64_t now = 1'000'000, last_tip = rig.tip_height(), flat = 0;
    std::size_t   dropped = SIZE_MAX;
    for (std::uint64_t step = 1; step <= budget_steps; ++step) {
        now += 500;
        if (step % PUSH == 0) {                                // the network finds a block
            rig.grow(false);
            for (std::size_t i = 0; i < pool.links.size(); ++i)
                if (pool.links[i].up)
                    rig.boot->on_new_block(pool.links[i].ref, BlockEntry(rig.at(rig.net_top()).full),
                                           rig.net_top() + 1, /*fluffy=*/false);
        }
        if (step % DROP == 0) { dropped = (step / DROP) % pool.links.size(); pool.drop(dropped); }
        if (dropped != SIZE_MAX && step % DROP == 2) { pool.reconnect(dropped); dropped = SIZE_MAX; }

        driver.tick(now);
        pool.step();

        out.alt_max = std::max(out.alt_max, rig.idx->alt_size());
        const std::uint64_t tip = rig.tip_height();
        if (tip == rig.net_top()) { out.steps_to_tip = step; break; }
        if (tip == last_tip) out.longest_flat = std::max(out.longest_flat, ++flat);
        else { flat = 0; last_tip = tip; }
    }
    out.orphans        = rig.idx->orphans_parked();
    out.spans_refused  = pool.spans_refused;
    out.spans_lost     = pool.spans_lost;
    out.chains         = pool.chains;
    out.chain_timeouts = driver.stats().chain_timeouts;
    std::printf("  D4: steps_to_tip=%llu longest_flat=%llu alt_max=%zu orphans=%llu "
                "chains=%llu chain_timeouts=%llu spans_refused=%llu spans_lost=%llu "
                "(tip %llu / network %llu)\n",
                (unsigned long long)out.steps_to_tip, (unsigned long long)out.longest_flat,
                out.alt_max, (unsigned long long)out.orphans, (unsigned long long)out.chains,
                (unsigned long long)out.chain_timeouts, (unsigned long long)out.spans_refused,
                (unsigned long long)out.spans_lost, (unsigned long long)rig.tip_height(),
                (unsigned long long)rig.net_top());
    return out;
}

void test_catch_up_is_bounded() {
    // 1200 steps = 10 simulated minutes for 2600 blocks.
    const CatchUp c = run_catch_up(1200);
    kat::checkf(c.steps_to_tip != 0,
                "D4: catch-up across > alt-pool-size blocks reaches the network tip within "
                "10 simulated minutes (on master the tip plateaus at anchor+64/+128)");
    kat::checkf(c.longest_flat <= 60,
                "D4: no plateau longer than 30 s while behind (longest %llu steps)",
                (unsigned long long)c.longest_flat);
    kat::checkf(c.alt_max <= 512, "D4: the alt pool never overflows (max %zu)", c.alt_max);
}

} // namespace

int main() {
    test_strand_after_gap();
    test_held_parent_drains_child();
    test_cohort_ignores_peers_behind_us();
    test_evict_far_unresolved_first();
    test_far_pushes_not_parked_while_behind();
    test_catch_up_is_bounded();
    return kat::report("xmr_neartip_stall_kat");
}
