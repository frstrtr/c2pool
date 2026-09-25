// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_output_set_overlay_kat.cpp
//
// RESTART COST WITH AN OUTPUT SET. A node booted with --output-set used to
// ignore its chain snapshot on restart ("resume skipped: an output-set was
// seeded ... pins outputs_ to the anchor base"): the chain image carries no
// output set, and the seeded set cannot be re-seated to a resumed tip, so every
// restart re-walked from the anchor (~950 stagenet blocks, one late_unbooked
// alarm per block in the pool, the lane suspended while it re-booked).
//
// The fix persists the POST-ANCHOR OVERLAY of ChainOutputSet (the outputs, key
// images, per-block leaves and undo frames the chain added on top of the
// read-only anchor snapshot) beside the chain snapshot and replays it onto the
// freshly seeded set on restart. This file pins the set-level half:
//
//   A  ROUND TRIP  -- a set seeded from an anchor snapshot FILE (the node's
//                     mmap path), advanced by post-anchor blocks with coinbase
//                     outputs, re-spent snapshot key images, in-block duplicates
//                     and a reorg, is saved; a fresh set seeded from the same
//                     file loads the overlay and answers EVERY question the
//                     same: roots, counts, set digest, tip, 100,000 random
//                     ring lookups, 100,000 key-image spent checks, membership
//                     proofs. It also equals a third set that re-walked the same
//                     blocks from the anchor (the fallback path).
//   B  CONTINUES   -- the resumed set keeps following the chain: new blocks
//                     connect, and a reorg that unwinds BELOW the resume point
//                     restores the roots bit-exact (the undo frames were
//                     re-derived, not dropped).
//   C  FAIL-CLOSED -- a truncated overlay, a flipped byte, a recorded tip that
//                     does not match the replay, a tampered output row (digest
//                     re-signed, so only the replay's roots can catch it), an
//                     overlay bound to a different anchor snapshot, and a load
//                     over an already-advanced set are all REFUSED, and every
//                     refusal leaves the set at the bare anchor snapshot (so the
//                     node can fall back to the from-anchor re-walk).
//
// RED ON THE BASE: before the fix ChainOutputSet has no overlay persistence;
// the helpers below detect that at compile time and the KAT FAILS at run time
// ("no overlay persistence: a restart with --output-set re-walks from the
// anchor") instead of not compiling.
//
// MEASUREMENT MODE (the live smoke's M2 check):
//   xmr_native_output_set_overlay_kat --compare <output_set.bin> <anchor.inc>
//                                     <overlayA> <overlayB> [n] [txdir]
// seeds two sets from the (read-only) anchor snapshot, lays each node's
// persisted overlay file (the `<snapshot>.outset` the node writes; its first 32
// bytes are the chain-image binding and are skipped) over one of them, and
// compares tip, roots, counts, n random ring lookups and n key-image spent
// checks (default 100,000 each). With [txdir] (real transactions as *.hex) it
// also resolves each ring from both sets and runs the txpool's CLSAG verify:
// every real tx must verify and a copy with a flipped CLSAG c1 must be
// RingSigFail. Exit 0 only on zero mismatches.
//
// Registered in BOTH `--target` lists in .github/workflows/build.yml.
// ---------------------------------------------------------------------------

#include <algorithm>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <vector>

#include <unistd.h>

#include "impl/xmr/native/anchor/xmr_anchor_codec.hpp"
#include "impl/xmr/native/chain/xmr_output_set.hpp"
#include "impl/xmr/native/contracts/anchor.hpp"
#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/rct/xmr_clsag_verify.hpp"
#include "impl/xmr/native/txpool/xmr_tx_decode.hpp"

#include <dirent.h>

using namespace c2pool::xmr::native;

static int g_checks = 0;
static int g_fail   = 0;

static void checkf(bool cond, const char* fmt, ...) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        if (g_fail <= 40) {
            va_list ap; va_start(ap, fmt);
            std::fprintf(stderr, "FAIL: ");
            std::vfprintf(stderr, fmt, ap); va_end(ap);
            std::fputc('\n', stderr);
        }
    }
}

// ---------------------------------------------------------------------------
// The overlay API, whichever side of the change this is built on.
// ---------------------------------------------------------------------------
static const char* kNoOverlay =
    "ChainOutputSet has no overlay persistence: a restart with --output-set cannot resume "
    "and re-walks from the anchor";

template <class S>
static bool ovl_save(const S& s, std::vector<std::uint8_t>& out, std::string& why) {
    if constexpr (requires { s.serialize_overlay(out, why); }) return s.serialize_overlay(out, why);
    else { why = kNoOverlay; return false; }
}
template <class S>
static bool ovl_load(S& s, const std::vector<std::uint8_t>& in, std::string& why) {
    if constexpr (requires { s.load_overlay(in, why); }) return s.load_overlay(in, why);
    else { why = kNoOverlay; return false; }
}
template <class S>
static std::uint64_t tip_h(const S& s) {
    if constexpr (requires { s.tip_height(); }) return s.tip_height();
    else return 0;
}
template <class S>
static Hash tip_i(const S& s) {
    if constexpr (requires { s.tip_id(); }) return s.tip_id();
    else return Hash{};
}
template <class S>
static std::size_t ovl_blocks(const S& s) {
    if constexpr (requires { s.overlay_block_count(); }) return s.overlay_block_count();
    else return 0;
}
template <class S>
static bool ovl_drop(S& s) {
    if constexpr (requires { s.drop_overlay(); }) return s.drop_overlay();
    else return false;
}

// ---------------------------------------------------------------------------
// Fixture helpers (the shapes of xmr_output_set_mmap_kat).
// ---------------------------------------------------------------------------
static bool write_file(const std::string& path, const std::string& bytes) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(f);
}
static bool read_file(const std::string& path, std::vector<std::uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return true;
}
static bool same(const OutputRecord& a, const OutputRecord& b) {
    return a.pubkey == b.pubkey && a.commitment == b.commitment
        && a.unlock_time == b.unlock_time && a.height == b.height;
}
static Hash rnd_hash(std::mt19937_64& r) {
    Hash h{};
    for (int i = 0; i < 4; ++i) {
        const std::uint64_t v = r();
        std::memcpy(h.data() + 8 * i, &v, 8);
    }
    return h;
}
static Hash id_of(std::uint64_t h, std::uint8_t fork = 0) {
    Hash id{};
    std::memcpy(id.data(), &h, 8);
    id[30] = fork;
    id[31] = 0xb1;
    return id;
}
static AnchorBundle bundle_for(const ChainOutputSet& set, std::uint64_t height, const Hash& tip_id) {
    AnchorBundle b;
    b.network                = "regtest";
    b.height                 = height;
    b.id                     = tip_id;
    b.rct_output_count       = set.frontier();
    b.output_set_base_height = 1;
    b.output_set_leaves      = set.output_leaf_count();
    b.output_set_root        = set.output_root();
    b.spent_set_leaves       = set.spent_leaf_count();
    b.spent_set_root         = set.spent_root();
    return b;
}
static BlockTxEvent block(std::uint64_t h, std::uint64_t first, const Hash& id,
                          std::vector<OutputRecord> outs, std::vector<Hash> kis,
                          std::vector<std::pair<std::uint64_t, Hash>> cb = {}) {
    BlockTxEvent e;
    e.kind                    = BlockTxEvent::Kind::Connected;
    e.height                  = h;
    e.first_output_index      = first;
    e.block_id                = id;
    e.coinbase_amount_pubkeys = std::move(cb);
    e.coinbase_unlock_time    = h + 60;
    e.outputs                 = std::move(outs);
    e.key_images              = std::move(kis);
    return e;
}
static BlockTxEvent disc(std::uint64_t h) {
    BlockTxEvent e; e.kind = BlockTxEvent::Kind::Disconnected; e.height = h; return e;
}
static bool seed(ChainOutputSet& s, const std::string& path, const AnchorBundle& b, std::string& why) {
    (void)s.reset_base(b.rct_output_count);
    return s.seed_from_snapshot_file(path, b, why);
}

// Every question a consumer can ask, n ring lookups and n spent checks.
static std::size_t compare_sets(const ChainOutputSet& a, const ChainOutputSet& b,
                                const std::vector<Hash>& kis, std::mt19937_64& r,
                                std::size_t n, const char* stage, bool verbose = false) {
    std::size_t mism = 0;
    auto eq = [&](bool c, const char* what) { checkf(c, "%s: %s", stage, what); if (!c) ++mism; };
    eq(a.frontier() == b.frontier(), "frontier");
    eq(a.first_output_index() == b.first_output_index(), "base");
    eq(a.output_count() == b.output_count(), "output_count");
    eq(a.spent_count() == b.spent_count(), "spent_count");
    eq(a.output_leaf_count() == b.output_leaf_count(), "output leaf count");
    eq(a.spent_leaf_count() == b.spent_leaf_count(), "spent leaf count");
    eq(a.output_root() == b.output_root(), "output root");
    eq(a.spent_root() == b.spent_root(), "spent root");
    eq(a.set_digest() == b.set_digest(), "set digest");

    const std::uint64_t base = a.first_output_index(), fr = std::max(a.frontier(), b.frontier());
    const std::uint64_t lo = base > 3 ? base - 3 : 0;
    const std::uint64_t snap_n = a.snapshot_output_count();
    const std::uint64_t post_lo = base + snap_n;   // first post-anchor index
    std::size_t ring_bad = 0, resolved = 0;
    for (std::size_t t = 0; t < n; ++t) {
        std::vector<std::uint64_t> ring;
        // Half the rings reach into the post-anchor overlay (what the resume
        // restores), half anywhere in the set (snapshot rows + overlay).
        const bool post = (t & 1) == 0 && fr > post_lo;
        const std::uint64_t from = post ? (post_lo > 3 ? post_lo - 3 : 0) : lo;
        const std::uint64_t span = fr - from + 4;
        for (int k = 0; k < 16; ++k) ring.push_back(from + r() % span);
        std::sort(ring.begin(), ring.end());
        std::vector<OutputRecord> ga, gb;
        const bool ra = a.resolve(0, ring, ga), rb = b.resolve(0, ring, gb);
        bool ok = ra == rb && ga.size() == gb.size();
        for (std::size_t k = 0; ok && k < ga.size(); ++k) ok = same(ga[k], gb[k]);
        if (!ok) ++ring_bad;
        resolved += ra;
    }
    checkf(ring_bad == 0, "%s: %zu of %zu ring lookups differ", stage, ring_bad, n);
    std::size_t ki_bad = 0, hits = 0;
    for (std::size_t t = 0; t < n; ++t) {
        Hash k;
        switch (t % 4) {
            case 0: case 1: k = kis.empty() ? rnd_hash(r) : kis[r() % kis.size()]; break;
            case 2: k = kis.empty() ? rnd_hash(r) : kis[r() % kis.size()]; k[31] ^= 0x5a; break;
            default: k = rnd_hash(r); break;
        }
        const bool sa = a.is_spent(k);
        if (sa != b.is_spent(k)) ++ki_bad;
        hits += sa;
    }
    checkf(ki_bad == 0, "%s: %zu of %zu key-image spent checks differ", stage, ki_bad, n);
    for (int t = 0; t < 200 && fr > base; ++t) {
        const std::uint64_t gi = base + r() % (fr - base);
        const bool va = a.verify_member(gi), vb = b.verify_member(gi);
        if (va != vb) ++mism;
        checkf(va == vb, "%s: verify_member(%llu)", stage, (unsigned long long)gi);
    }
    if (verbose)
        std::printf("[%s] rings=%zu (resolved %zu) ring_mismatch=%zu | spent_checks=%zu (spent %zu) "
                    "spent_mismatch=%zu | other_mismatch=%zu\n",
                    stage, n, resolved, ring_bad, n, hits, ki_bad, mism);
    return ring_bad + ki_bad + mism;
}

// ---------------------------------------------------------------------------
// The KAT.
// ---------------------------------------------------------------------------
static int run_kat() {
    std::mt19937_64 r(0x0e71'a7ee'0000'0001ULL);
    const std::uint64_t BASE = 1000, H = 400;

    // The anchor snapshot: H blocks built from genesis, then written to a file
    // exactly as the operator's --output-set is.
    ChainOutputSet built(BASE);
    std::vector<Hash> kis;
    for (std::uint64_t h = 1; h <= H; ++h) {
        std::vector<OutputRecord> outs(40);
        for (auto& o : outs) {
            o.pubkey = rnd_hash(r); o.commitment = rnd_hash(r);
            o.unlock_time = (r() & 7) == 0 ? h + 10 : 0; o.height = h;
        }
        std::vector<Hash> k(40);
        for (auto& x : k) x = rnd_hash(r);
        std::vector<std::pair<std::uint64_t, Hash>> cb = {{600000000000ULL + h, rnd_hash(r)}};
        checkf(built.on_block_connected(block(h, built.frontier(), id_of(h), std::move(outs), k, std::move(cb))),
               "fixture: connect %llu", (unsigned long long)h);
        kis.insert(kis.end(), k.begin(), k.end());
    }
    const AnchorBundle bnd = bundle_for(built, H, id_of(H));
    const char* tmpdir = std::getenv("TMPDIR");
    const std::string dir = tmpdir && *tmpdir ? tmpdir : "/tmp";
    const std::string tag = std::to_string(::getpid());
    const std::string path  = dir + "/xmr_output_set_overlay_kat." + tag + ".bin";
    const std::string path2 = dir + "/xmr_output_set_overlay_kat." + tag + ".other.bin";
    checkf(write_file(path, built.serialize()), "write anchor snapshot %s", path.c_str());

    // The post-anchor chain, as the node's live set sees it.
    ChainOutputSet live(0);
    std::string why;
    checkf(seed(live, path, bnd, why), "seed live: %s", why.c_str());
    ChainOutputSet bare(0);                               // the reference "bare anchor snapshot"
    checkf(seed(bare, path, bnd, why), "seed bare: %s", why.c_str());

    std::vector<BlockTxEvent> stream;                     // every event the live set consumed
    auto post_block = [&](std::uint64_t h, std::uint8_t fork) {
        std::vector<OutputRecord> outs(1 + r() % 30);
        for (auto& o : outs) {
            o.pubkey = rnd_hash(r); o.commitment = rnd_hash(r);
            o.unlock_time = (r() & 15) == 0 ? h + 5 : 0; o.height = h;
        }
        if (h % 7 == 0) outs.clear();                     // a block with no RCT outputs
        std::vector<Hash> k;
        for (int i = 0, n = int(r() % 25); i < n; ++i) k.push_back(rnd_hash(r));
        if (h % 3 == 0) k.push_back(kis[r() % kis.size()]);           // re-spend of a snapshot image
        if (h % 5 == 0 && !k.empty()) k.push_back(k.front());          // in-block duplicate
        if (h % 11 == 0 && kis.size() > 50) k.push_back(kis[kis.size() - 1 - r() % 20]); // earlier post image
        std::vector<std::pair<std::uint64_t, Hash>> cb;
        if (h % 4 != 0) cb.push_back({7000000 + h, rnd_hash(r)});
        BlockTxEvent ev = block(h, live.frontier(), id_of(h, fork), outs, k, cb);
        kis.insert(kis.end(), k.begin(), k.end());
        return ev;
    };
    auto feed = [&](ChainOutputSet& s, const BlockTxEvent& ev) {
        return ev.kind == BlockTxEvent::Kind::Connected ? s.on_block_connected(ev)
                                                        : s.on_block_disconnected(ev);
    };
    std::uint64_t tip = H;
    for (int i = 0; i < 60; ++i) {
        const BlockTxEvent ev = post_block(++tip, 0);
        checkf(feed(live, ev), "live: connect %llu", (unsigned long long)tip);
        stream.push_back(ev);
    }
    for (int i = 0; i < 4; ++i) {                          // a reorg before the save
        const BlockTxEvent ev = disc(tip--);
        checkf(feed(live, ev), "live: disconnect %llu", (unsigned long long)(tip + 1));
        stream.push_back(ev);
    }
    for (int i = 0; i < 6; ++i) {
        const BlockTxEvent ev = post_block(++tip, 1);
        checkf(feed(live, ev), "live: connect %llu (fork)", (unsigned long long)tip);
        stream.push_back(ev);
    }
    std::printf("live set: tip=%llu frontier=%llu outputs=%zu spent=%zu\n",
                (unsigned long long)tip, (unsigned long long)live.frontier(), live.output_count(),
                live.spent_count());

    // PART A: save, restart (fresh seed from the same file), load.
    std::vector<std::uint8_t> ovl;
    const bool saved = ovl_save(live, ovl, why);
    checkf(saved, "PART A: serialize the overlay: %s", why.c_str());
    ChainOutputSet resumed(0);
    checkf(seed(resumed, path, bnd, why), "seed resumed: %s", why.c_str());
    const bool loaded = saved && ovl_load(resumed, ovl, why);
    checkf(loaded, "PART A: load the overlay onto a freshly seeded set: %s", why.c_str());
    std::printf("PART A: overlay %zu bytes, loaded=%d\n", ovl.size(), loaded ? 1 : 0);
    compare_sets(live, resumed, kis, r, 100000, "PART A resumed vs live", true);

    // The fallback path (re-walk from the anchor) reaches the same set.
    ChainOutputSet rewalk(0);
    checkf(seed(rewalk, path, bnd, why), "seed rewalk: %s", why.c_str());
    for (const BlockTxEvent& ev : stream) checkf(feed(rewalk, ev), "rewalk: replay");
    compare_sets(rewalk, resumed, kis, r, 100000, "PART A resumed vs from-anchor re-walk", true);

    // PART B: the resumed set keeps following the chain, and a reorg below the
    // resume point unwinds bit-exact on both.
    for (int i = 0; i < 5; ++i) {
        const BlockTxEvent ev = post_block(++tip, 2);
        checkf(feed(live, ev) && feed(resumed, ev), "PART B: connect %llu", (unsigned long long)tip);
    }
    compare_sets(live, resumed, kis, r, 20000, "PART B after new blocks");
    for (int i = 0; i < 12; ++i) {
        const BlockTxEvent ev = disc(tip--);
        checkf(feed(live, ev) && feed(resumed, ev), "PART B: disconnect %llu (below the resume point)",
               (unsigned long long)(tip + 1));
    }
    compare_sets(live, resumed, kis, r, 20000, "PART B after a reorg below the resume point");
    for (int i = 0; i < 3; ++i) {
        const BlockTxEvent ev = post_block(++tip, 3);
        checkf(feed(live, ev) && feed(resumed, ev), "PART B: reconnect %llu", (unsigned long long)tip);
    }
    compare_sets(live, resumed, kis, r, 20000, "PART B after the new branch");

    // PART C: fail-closed. Every refusal leaves the set at the bare snapshot.
    auto refused = [&](const std::vector<std::uint8_t>& blob, const char* what) {
        ChainOutputSet s(0);
        std::string w;
        checkf(seed(s, path, bnd, w), "PART C seed (%s): %s", what, w.c_str());
        const bool ok = ovl_load(s, blob, w);
        checkf(!ok, "PART C: %s must be REFUSED", what);
        if (!ok) std::printf("PART C: %-44s refused: %s\n", what, w.c_str());
        checkf(s.set_digest() == bare.set_digest() && s.output_count() == bare.output_count()
                   && s.spent_count() == bare.spent_count(),
               "PART C: %s left the set at the bare anchor snapshot", what);
    };
    auto redigest = [](std::vector<std::uint8_t>& b) {
        const std::size_t n = b.size() - 32;
        const auto d = ::v37::sha256d(b.data(), n);
        std::memcpy(b.data() + n, d.data(), 32);
    };
    if (saved && ovl.size() > 400) {
        { auto b = ovl; b.resize(b.size() / 2); refused(b, "a truncated overlay"); }
        { auto b = ovl; b.resize(b.size() - 33); refused(b, "an overlay missing its last byte"); }
        { auto b = ovl; b[b.size() / 3] ^= 0x10; refused(b, "a flipped byte"); }
        {   // recorded tip id (header offset: 16 magic/ver + 16 base/n + 40 + 40 + 40 + 8 height)
            auto b = ovl; b[16 + 16 + 40 + 40 + 40 + 8] ^= 1; redigest(b);
            refused(b, "a recorded tip that does not match the replay");
        }
        {   // tip height one higher than the blocks carried
            auto b = ovl; b[16 + 16 + 40 + 40 + 40] += 1; redigest(b);
            refused(b, "a tip height past the blocks it carries");
        }
        {   // a tampered output row inside the first block that carries outputs:
            // the digest is re-signed, so only the replay's roots catch it.
            auto b = ovl;
            const std::size_t hdr = 16 + 16 + 40 + 40 + 40 + 40 + 8 + 40 + 40 + 8;
            // block 0: height(8) id(32) first(8) n_out(8) rows...
            std::uint64_t n_out = 0;
            std::memcpy(&n_out, b.data() + hdr + 48, 8);
            std::size_t at = hdr + 56 + 5;             // inside the first row's pubkey
            if (n_out == 0) at = hdr + 8 + 3;           // else the block id
            b[at] ^= 0x01; redigest(b);
            refused(b, "a tampered row / block id (re-digested)");
        }
        refused({}, "an empty overlay");
    }
    {   // an overlay bound to a DIFFERENT anchor snapshot
        ChainOutputSet other(BASE + 7);
        for (std::uint64_t h = 1; h <= 50; ++h) {
            std::vector<OutputRecord> outs(10);
            for (auto& o : outs) { o.pubkey = rnd_hash(r); o.commitment = rnd_hash(r); o.height = h; }
            (void)other.on_block_connected(block(h, other.frontier(), id_of(h, 9), outs, {rnd_hash(r)}));
        }
        const AnchorBundle ob = bundle_for(other, 50, id_of(50, 9));
        checkf(write_file(path2, other.serialize()), "write the other snapshot");
        ChainOutputSet s(0);
        std::string w;
        checkf(seed(s, path2, ob, w), "seed the other snapshot: %s", w.c_str());
        const std::uint64_t d0 = s.frontier();
        const bool ok = saved && ovl_load(s, ovl, w);
        checkf(saved && !ok, "PART C: an overlay bound to another anchor snapshot must be REFUSED");
        if (saved && !ok) std::printf("PART C: %-44s refused: %s\n", "an overlay for another snapshot", w.c_str());
        checkf(s.frontier() == d0, "PART C: the other set is untouched");
    }
    {   // a load over an already-advanced set
        ChainOutputSet s(0);
        std::string w;
        checkf(seed(s, path, bnd, w), "seed advanced: %s", w.c_str());
        (void)s.on_block_connected(stream.front());
        const std::size_t before = s.output_count();
        const bool ok = saved && ovl_load(s, ovl, w);
        checkf(saved && !ok, "PART C: a load over an advanced set must be REFUSED");
        checkf(s.output_count() == before, "PART C: the advanced set is untouched");
    }
    {   // drop_overlay returns a resumed set to the bare snapshot
        ChainOutputSet s(0);
        std::string w;
        checkf(seed(s, path, bnd, w), "seed drop: %s", w.c_str());
        const bool ok = saved && ovl_load(s, ovl, w) && ovl_drop(s);
        checkf(ok && s.set_digest() == bare.set_digest() && s.spent_count() == bare.spent_count(),
               "PART C: drop_overlay() returns to the bare anchor snapshot");
    }

    std::remove(path.c_str());
    std::remove(path2.c_str());
    std::printf("\nxmr_native_output_set_overlay_kat: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}

// ---------------------------------------------------------------------------
// --compare: the live smoke's M2 (two nodes' persisted overlays over the same
// read-only anchor snapshot).
// ---------------------------------------------------------------------------
static bool load_anchor_file(const std::string& p, AnchorBundle& b) {
    std::ifstream f(p, std::ios::binary);
    if (!f) { std::fprintf(stderr, "cannot open anchor %s\n", p.c_str()); return false; }
    const std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    std::string why;
    if (parse_anchor_inc(text, b, why) != AnchorParse::Ok) {
        std::fprintf(stderr, "anchor parse failed: %s\n", why.c_str());
        return false;
    }
    return true;
}

static bool seed_with_overlay(ChainOutputSet& s, const std::string& snap, const AnchorBundle& b,
                              const std::string& ovl_path, std::vector<Hash>& kis_out) {
    std::string why;
    const auto t0 = std::chrono::steady_clock::now();
    if (!seed(s, snap, b, why)) { std::fprintf(stderr, "seed: %s\n", why.c_str()); return false; }
    std::vector<std::uint8_t> f;
    if (!read_file(ovl_path, f) || f.size() < 32) {
        std::fprintf(stderr, "cannot read overlay %s\n", ovl_path.c_str());
        return false;
    }
    const std::vector<std::uint8_t> ovl(f.begin() + 32, f.end());
    if (!ovl_load(s, ovl, why)) { std::fprintf(stderr, "overlay %s: %s\n", ovl_path.c_str(), why.c_str()); return false; }
    // Collect the overlay's key images (spent-check probes) by walking the file
    // format: header, then per block height|id|first|n_out|rows|n_ins|ins|n_skip|skip.
    const std::uint8_t* d = ovl.data();
    const std::size_t len = ovl.size() - 32;
    std::size_t o = 16 + 16 + 40 + 40 + 40 + 40 + 8 + 40 + 40;
    auto u64 = [&]() { std::uint64_t x = 0; if (o + 8 <= len) std::memcpy(&x, d + o, 8); o += 8; return x; };
    const std::uint64_t nb = u64();
    for (std::uint64_t k = 0; k < nb && o < len; ++k) {
        o += 8 + 32 + 8;
        const std::uint64_t no = u64(); o += no * 80;
        for (int pass = 0; pass < 2; ++pass) {
            const std::uint64_t n = u64();
            for (std::uint64_t i = 0; i < n && o + 32 <= len; ++i, o += 32) {
                Hash h{}; std::memcpy(h.data(), d + o, 32); kis_out.push_back(h);
            }
        }
    }
    std::printf("[seed+overlay] %s: tip=%llu frontier=%llu outputs=%zu spent=%zu overlay_blocks=%zu "
                "overlay_kis=%zu secs=%.1f\n", ovl_path.c_str(), (unsigned long long)tip_h(s),
                (unsigned long long)s.frontier(), s.output_count(), s.spent_count(),
                ovl_blocks(s), kis_out.size(),
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
    return true;
}

// Real transactions against a set: resolve every ring from the set (relative
// key offsets -> absolute, amount 0) and run the CLSAG verify the txpool's
// input-consensus step runs; then the same with c1 of the first input flipped
// (a corrupted CLSAG) -- which must fail. Returns {real_ok, corrupted_rejected}.
static std::pair<std::size_t, std::size_t> clsag_control(const ChainOutputSet& s,
                                                         const std::vector<std::vector<std::uint8_t>>& txs,
                                                         const char* tag) {
    std::size_t real_ok = 0, bad_rej = 0;
    for (const auto& blob : txs) {
        DecodedTx d;
        if (decode_relayed_tx(blob, d) != TxDecodeStatus::Ok || d.clsags.empty()
            || d.rct.bpp.empty()) { std::printf("[clsag %s] tx: decode failed / not CLSAG\n", tag); continue; }
        const rct::Key msg = rct::clsag_message(d.h_prefix, d.h_base, d.rct.bpp[0]);
        auto verify_all = [&](const std::vector<rct::Clsag>& sigs) -> int {   // 1 ok, 0 sig fail, -1 unresolved
            for (std::size_t i = 0; i < sigs.size(); ++i) {
                std::vector<std::uint64_t> abs;
                std::uint64_t acc = 0;
                for (std::uint64_t off : d.key_offsets[i]) { acc += off; abs.push_back(acc); }
                std::vector<OutputRecord> members;
                if (!s.resolve(0, abs, members)) return -1;
                std::vector<rct::CtKey> ring;
                for (const OutputRecord& m : members) ring.push_back(rct::CtKey{m.pubkey, m.commitment});
                if (rct::verify_clsag(msg, sigs[i], ring, d.rct.pseudoOuts[i]) != rct::ClsagStatus::Ok) return 0;
            }
            return 1;
        };
        const int real = verify_all(d.clsags);
        std::vector<rct::Clsag> bad = d.clsags;
        bad[0].c1[0] ^= 0x01;
        const int corrupted = verify_all(bad);
        real_ok += real == 1;
        bad_rej += corrupted == 0;
        std::printf("[clsag %s] tx %02x%02x%02x%02x inputs=%zu real=%s corrupted=%s\n", tag, d.id[0], d.id[1],
                    d.id[2], d.id[3], d.clsags.size(),
                    real == 1 ? "VERIFIES" : real == 0 ? "RingSigFail" : "unresolved",
                    corrupted == 1 ? "VERIFIES(!)" : corrupted == 0 ? "RingSigFail" : "unresolved");
    }
    return {real_ok, bad_rej};
}

static std::vector<std::vector<std::uint8_t>> read_tx_dir(const std::string& dir) {
    std::vector<std::vector<std::uint8_t>> out;
    DIR* dd = ::opendir(dir.c_str());
    if (!dd) return out;
    std::vector<std::string> names;
    for (dirent* e = ::readdir(dd); e; e = ::readdir(dd)) {
        const std::string n = e->d_name;
        if (n.size() > 4 && n.compare(n.size() - 4, 4, ".hex") == 0) names.push_back(n);
    }
    ::closedir(dd);
    std::sort(names.begin(), names.end());
    for (const std::string& n : names) {
        std::ifstream f(dir + "/" + n);
        std::string h((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        while (!h.empty() && (h.back() == '\n' || h.back() == '\r' || h.back() == ' ')) h.pop_back();
        std::vector<std::uint8_t> b;
        auto nib = [](char c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; };
        for (std::size_t i = 0; i + 1 < h.size(); i += 2) b.push_back(std::uint8_t(nib(h[i]) << 4 | nib(h[i + 1])));
        out.push_back(std::move(b));
    }
    return out;
}

static int run_compare(const std::string& snap, const std::string& anc, const std::string& oa,
                       const std::string& ob, std::size_t n, const std::string& txdir) {
    AnchorBundle b;
    if (!load_anchor_file(anc, b)) return 2;
    ChainOutputSet a(0), c(0);
    std::vector<Hash> kis;
    if (!seed_with_overlay(a, snap, b, oa, kis) || !seed_with_overlay(c, snap, b, ob, kis)) return 2;
    {
        const bool same_tip = tip_h(a) == tip_h(c) && tip_i(a) == tip_i(c) && tip_h(a) != 0;
        std::printf("[compare] tips: A=%llu B=%llu same=%d\n", (unsigned long long)tip_h(a),
                    (unsigned long long)tip_h(c), same_tip ? 1 : 0);
        checkf(same_tip, "compare: the two overlays are not at the same tip");
    }
    std::mt19937_64 r(0xc0de'0000'0000'0002ULL);
    const std::size_t mism = compare_sets(a, c, kis, r, n, "compare A vs B", true);
    std::printf("[compare] roots: output=%s spent=%s | total mismatches=%zu | checks=%d failures=%d\n",
                a.output_root() == c.output_root() ? "equal" : "DIFFER",
                a.spent_root() == c.spent_root() ? "equal" : "DIFFER", mism, g_checks, g_fail);
    if (!txdir.empty()) {
        const auto txs = read_tx_dir(txdir);
        const auto ra = clsag_control(a, txs, "A");
        const auto rb = clsag_control(c, txs, "B");
        std::printf("[clsag] txs=%zu | A: real verify=%zu corrupted RingSigFail=%zu | B: real verify=%zu "
                    "corrupted RingSigFail=%zu\n", txs.size(), ra.first, ra.second, rb.first, rb.second);
        checkf(!txs.empty() && ra.first == txs.size() && rb.first == txs.size(),
               "compare: every real tx verifies over both sets");
        checkf(ra.second == txs.size() && rb.second == txs.size(),
               "compare: every corrupted-CLSAG control is RingSigFail over both sets");
    }
    return g_fail == 0 ? 0 : 1;
}

int main(int argc, char** argv) {
    if (argc >= 6 && std::strcmp(argv[1], "--compare") == 0) {
        const std::size_t n = argc >= 7 ? std::strtoull(argv[6], nullptr, 10) : 100000;
        return run_compare(argv[2], argv[3], argv[4], argv[5], n, argc >= 8 ? argv[7] : "");
    }
    return run_kat();
}
