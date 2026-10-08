// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_output_set_mmap_kat.cpp
//
// OUTPUT-SET RAM KAT. The node seeds the format-2 anchor snapshot
// (--output-set) and must serve it IN PLACE -- a read-only mapping of the file
// -- instead of copying the whole historical output table and spent-key-image
// set into the heap (mainnet: an 18.3 GB file that peaked ~38 GB RSS and
// settled ~22 GB). Only post-anchor state may live in the heap.
//
// The seed goes through the node's own entry: seed_from_snapshot_file() when
// the set has it, otherwise exactly what the node did before (read the whole
// file into a string, seed_from_snapshot). So the SAME source runs on either
// side of the change and the heap assertion below is what tells them apart.
//
//   PART A -- HEAP: seeding a ~70 MB synthetic snapshot must grow RssAnon by
//             at most 25% of the file size (the old heap copy grew it by more
//             than the whole file). Linux /proc only; skipped under ASan,
//             whose shadow and quarantine make RssAnon meaningless.
//   PART B -- EQUIVALENCE: the seeded set answers every resolve() (all
//             indices, the frontier edge, below base, multi-member rings) and
//             every is_spent() (every snapshot key image, random misses,
//             8-byte-prefix twins) byte-identically to the set that built the
//             snapshot; roots, digest, counts and membership proofs agree.
//   PART C -- OVERLAY + REORG: post-anchor blocks (new outputs, new key
//             images, re-spends of snapshot key images) connect and disconnect
//             identically on both; a snapshot key image stays spent after the
//             block that re-listed it is disconnected.
//   PART D -- FAIL-CLOSED: a missing, truncated or padded file and a flipped
//             root are refused with a reason and leave the set unresolved; a
//             seeded set refuses a second seed and a base reset.
//
// Measurement modes (not run by ctest; used by the output-set RAM smoke):
//   --load <snapshot> <anchor.inc> [hold_s]
//       seed like the node does and print load time + /proc memory lines.
//   --equiv <snapshot> <anchor.inc> <n_out> <n_ki> <seed> <answers_out>
//       seed, then check n_out random global indices (+ rings) and n_ki key
//       images (half snapshot rows, half misses) against an independent
//       streaming reader of the same file; print mismatches and write every
//       answer to <answers_out> so two builds can be compared byte-for-byte.
// ---------------------------------------------------------------------------

#include <algorithm>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <unistd.h>

#include "impl/xmr/native/anchor/xmr_anchor_codec.hpp"
#include "impl/xmr/native/chain/xmr_output_set.hpp"
#include "impl/xmr/native/contracts/anchor.hpp"
#include "impl/xmr/native/contracts/types.hpp"

#if defined(__SANITIZE_ADDRESS__)
#define OSR_KAT_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define OSR_KAT_ASAN 1
#endif
#endif

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

// The node's seed entry, whichever side of the change this is built on.
template <class Set>
static bool seed_like_node(Set& s, const std::string& path, const AnchorBundle& b, std::string& why) {
    if constexpr (requires { s.seed_from_snapshot_file(path, b, why); }) {
        return s.seed_from_snapshot_file(path, b, why);
    } else {
        std::ifstream f(path, std::ios::binary);
        if (!f) { why = "cannot open output-set snapshot '" + path + "'"; return false; }
        const std::string blob((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        return s.seed_from_snapshot(blob, b, why);
    }
}

// /proc/self/status field in kB (-1 when unavailable).
static long proc_kb(const char* key) {
    std::ifstream f("/proc/self/status");
    if (!f) return -1;
    std::string line;
    const std::size_t kl = std::strlen(key);
    while (std::getline(f, line)) {
        if (line.compare(0, kl, key) == 0 && line.size() > kl && line[kl] == ':')
            return std::strtol(line.c_str() + kl + 1, nullptr, 10);
    }
    return -1;
}
static void print_mem(const char* tag) {
    std::printf("[mem] %s VmRSS=%ld RssAnon=%ld RssFile=%ld VmHWM=%ld (kB)\n", tag,
                proc_kb("VmRSS"), proc_kb("RssAnon"), proc_kb("RssFile"), proc_kb("VmHWM"));
    std::fflush(stdout);
}

static bool write_file(const std::string& path, const std::string& bytes) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(f);
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

// Both sets answer every question the same way.
static void compare_sets(const ChainOutputSet& a, const ChainOutputSet& b,
                         const std::vector<Hash>& kis, std::mt19937_64& r, const char* stage) {
    checkf(a.frontier() == b.frontier(), "%s: frontier %llu vs %llu", stage,
           (unsigned long long)a.frontier(), (unsigned long long)b.frontier());
    checkf(a.first_output_index() == b.first_output_index(), "%s: base", stage);
    checkf(a.output_count() == b.output_count(), "%s: output_count", stage);
    checkf(a.spent_count() == b.spent_count(), "%s: spent_count %zu vs %zu", stage,
           a.spent_count(), b.spent_count());
    checkf(a.output_root() == b.output_root(), "%s: output root", stage);
    checkf(a.spent_root() == b.spent_root(), "%s: spent root", stage);
    checkf(a.set_digest() == b.set_digest(), "%s: set digest", stage);

    const std::uint64_t base = a.first_output_index(), fr = a.frontier();
    std::size_t bad = 0;
    const std::uint64_t lo = base > 3 ? base - 3 : 0;
    for (std::uint64_t i = lo; i < fr + 3; ++i) {
        std::vector<OutputRecord> ga, gb;
        const bool ra = a.resolve(0, {i}, ga), rb = b.resolve(0, {i}, gb);
        if (ra != rb || ga.size() != gb.size() || (ra && !same(ga[0], gb[0]))) ++bad;
    }
    checkf(bad == 0, "%s: %zu single-index resolve mismatches over [%llu,%llu)", stage, bad,
           (unsigned long long)lo, (unsigned long long)(fr + 3));
    bad = 0;
    for (int t = 0; t < 20000; ++t) {
        std::vector<std::uint64_t> ring;
        const std::uint64_t span = fr - lo + 4;
        for (int k = 0; k < 16; ++k) ring.push_back(lo + r() % span);
        std::sort(ring.begin(), ring.end());
        std::vector<OutputRecord> ga, gb;
        const bool ra = a.resolve(0, ring, ga), rb = b.resolve(0, ring, gb);
        bool eq = ra == rb && ga.size() == gb.size();
        for (std::size_t k = 0; eq && k < ga.size(); ++k) eq = same(ga[k], gb[k]);
        if (!eq) ++bad;
        std::vector<OutputRecord> na, nb;   // amount != 0 never resolves
        if (a.resolve(1, ring, na) != b.resolve(1, ring, nb)) ++bad;
    }
    checkf(bad == 0, "%s: %zu ring resolve mismatches", stage, bad);
    bad = 0;
    std::size_t hits = 0;
    for (const Hash& k : kis) {
        const bool sa = a.is_spent(k);
        if (sa != b.is_spent(k)) ++bad;
        hits += sa;
        Hash twin = k; twin[31] ^= 0x5a;               // same 8-byte prefix, different key
        if (a.is_spent(twin) != b.is_spent(twin)) ++bad;
        Hash twin0 = k; twin0[8] ^= 0x01;
        if (a.is_spent(twin0) != b.is_spent(twin0)) ++bad;
    }
    for (int t = 0; t < 200000; ++t) {
        const Hash k = rnd_hash(r);
        if (a.is_spent(k) != b.is_spent(k)) ++bad;
    }
    checkf(bad == 0, "%s: %zu is_spent mismatches (%zu listed key images spent)", stage, bad, hits);
    for (int t = 0; t < 200 && fr > base; ++t) {
        const std::uint64_t gi = base + r() % (fr - base);
        checkf(a.verify_member(gi) == b.verify_member(gi) && b.verify_member(gi),
               "%s: verify_member(%llu)", stage, (unsigned long long)gi);
    }
    checkf(!b.verify_member(fr) && !b.verify_member(fr + 7), "%s: beyond-frontier proves", stage);
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
static Hash id_of(std::uint64_t h) {
    Hash id{};
    std::memcpy(id.data(), &h, 8);
    id[31] = 0xb1;
    return id;
}

static int run_kat() {
    std::mt19937_64 r(0x05e7'0e75'0000'0001ULL);
    const std::uint64_t BASE = 1000, H = 1500;
    ChainOutputSet built(BASE);
    std::vector<Hash> kis;
    Hash tip{};
    for (std::uint64_t h = 1; h <= H; ++h) {
        std::vector<OutputRecord> outs(400);
        for (auto& o : outs) {
            o.pubkey = rnd_hash(r); o.commitment = rnd_hash(r);
            o.unlock_time = (r() & 7) == 0 ? h + 10 : 0; o.height = h;
        }
        std::vector<Hash> k(400);
        for (auto& x : k) x = rnd_hash(r);
        if (h % 97 == 0 && !kis.empty()) {              // 8-byte-prefix twins in the set
            Hash t = kis[r() % kis.size()]; t[20] ^= 0x33; k.push_back(t);
        }
        if (h % 101 == 0 && !kis.empty()) k.push_back(kis[r() % kis.size()]);   // re-listed
        std::vector<std::pair<std::uint64_t, Hash>> cb;
        if (h % 250 == 0) cb.push_back({600000000000ULL + h, rnd_hash(r)});
        const std::uint64_t first = built.frontier();
        checkf(built.on_block_connected(block(h, first, id_of(h), std::move(outs), k, std::move(cb))),
               "build: connect %llu", (unsigned long long)h);
        kis.insert(kis.end(), k.begin(), k.end());
        tip = id_of(h);
    }
    const std::uint64_t F = built.frontier();
    const std::string snap = built.serialize();
    const AnchorBundle bnd = bundle_for(built, H, tip);
    const char* tmpdir = std::getenv("TMPDIR");
    const std::string dir = tmpdir && *tmpdir ? tmpdir : "/tmp";
    const std::string path = dir + "/xmr_output_set_mmap_kat." + std::to_string(::getpid()) + ".bin";
    checkf(write_file(path, snap), "write snapshot %s", path.c_str());
    std::printf("snapshot: %zu bytes, outputs=%llu spent=%zu leaves=%llu\n", snap.size(),
                (unsigned long long)(F - BASE), built.spent_count(),
                (unsigned long long)built.output_leaf_count());

    // PART A + B: seed exactly like the node, measure the heap it took.
    ChainOutputSet node(0);
    checkf(node.reset_base(F), "reset_base to rct_output_count");
    std::string why;
    const long anon0 = proc_kb("RssAnon");
    const bool ok = seed_like_node(node, path, bnd, why);
    const long anon1 = proc_kb("RssAnon");
    checkf(ok, "seed from the snapshot file: %s", why.c_str());
    const long file_kb = static_cast<long>(snap.size() / 1024);
#if defined(OSR_KAT_ASAN)
    std::printf("PART A: skipped under ASan (RssAnon delta %ld kB, file %ld kB)\n", anon1 - anon0, file_kb);
#else
    if (anon0 >= 0 && anon1 >= 0) {
        std::printf("PART A: seeding grew RssAnon by %ld kB for a %ld kB snapshot (%.1f%%)\n",
                    anon1 - anon0, file_kb, 100.0 * double(anon1 - anon0) / double(file_kb));
        checkf((anon1 - anon0) * 4 <= file_kb,
               "PART A: the anchor snapshot is served in place -- RssAnon grew %ld kB, "
               "more than 25%% of the %ld kB file", anon1 - anon0, file_kb);
    } else {
        std::printf("PART A: skipped (no /proc/self/status RssAnon)\n");
    }
#endif
    compare_sets(built, node, kis, r, "PART B seeded");

    // PART C: the post-anchor overlay and its reorg, on both sets.
    for (std::uint64_t h = H + 1; h <= H + 6; ++h) {
        std::vector<OutputRecord> outs(50);
        for (auto& o : outs) { o.pubkey = rnd_hash(r); o.commitment = rnd_hash(r); o.height = h; }
        std::vector<Hash> k;
        for (int i = 0; i < 30; ++i) k.push_back(rnd_hash(r));
        for (int i = 0; i < 5; ++i) k.push_back(kis[r() % kis.size()]);   // re-spend a snapshot image
        std::vector<std::pair<std::uint64_t, Hash>> cb = {{7000000 + h, rnd_hash(r)}};
        const std::uint64_t first = built.frontier();
        const BlockTxEvent ev = block(h, first, id_of(h), outs, k, cb);
        checkf(built.on_block_connected(ev) && node.on_block_connected(ev), "PART C: connect %llu",
               (unsigned long long)h);
        kis.insert(kis.end(), k.begin(), k.end());
    }
    compare_sets(built, node, kis, r, "PART C overlay");
    for (std::uint64_t h = H + 6; h > H + 2; --h) {
        BlockTxEvent ev; ev.kind = BlockTxEvent::Kind::Disconnected; ev.height = h;
        checkf(built.on_block_disconnected(ev) && node.on_block_disconnected(ev),
               "PART C: disconnect %llu", (unsigned long long)h);
    }
    compare_sets(built, node, kis, r, "PART C after reorg");
    for (std::size_t i = 0; i < 1000; ++i)
        checkf(node.is_spent(kis[i]), "PART C: snapshot key image %zu still spent after reorg", i);
    {
        auto back = ChainOutputSet::deserialize(node.serialize());
        checkf(back != nullptr, "PART C: seeded+overlay set serializes");
        if (back) compare_sets(built, *back, kis, r, "PART C serialize round-trip");
    }

    // PART D: fail-closed.
    auto rejects = [&](const std::string& p, const AnchorBundle& b, const char* what) {
        ChainOutputSet s(0);
        (void)s.reset_base(b.rct_output_count);
        std::string w;
        const bool okk = seed_like_node(s, p, b, w);
        checkf(!okk && !w.empty(), "PART D: %s is refused with a reason", what);
        std::vector<OutputRecord> got;
        checkf(!s.resolve(0, {BASE}, got) && !s.is_spent(kis[0]),
               "PART D: %s leaves the set unresolved", what);
    };
    rejects(path + ".missing", bnd, "a missing file");
    {
        const std::string tp = path + ".trunc";
        checkf(write_file(tp, snap.substr(0, snap.size() - 1)), "write truncated");
        rejects(tp, bnd, "a truncated snapshot");
        checkf(write_file(tp, snap + "x"), "write padded");
        rejects(tp, bnd, "a padded snapshot");
        checkf(write_file(tp, std::string()), "write empty");
        rejects(tp, bnd, "an empty snapshot");
        std::remove(tp.c_str());
    }
    { AnchorBundle b = bnd; b.output_set_root[0] ^= 1; rejects(path, b, "a flipped output root"); }
    { AnchorBundle b = bnd; b.spent_set_root[5] ^= 1;  rejects(path, b, "a flipped spent root"); }
    { AnchorBundle b = bnd; b.rct_output_count += 1;   rejects(path, b, "a wrong rct_output_count"); }
    {
        std::string w;
        checkf(!seed_like_node(node, path, bnd, w), "PART D: a seeded set refuses a second seed");
        checkf(!node.reset_base(0), "PART D: a seeded set refuses a base reset");
    }
    std::remove(path.c_str());

    std::printf("xmr_output_set_mmap_kat: %d checks, %d failed\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Measurement modes.
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

static bool seed_timed(ChainOutputSet& s, const std::string& snap, const AnchorBundle& b) {
    print_mem("before-seed");
    const auto t0 = std::chrono::steady_clock::now();
    (void)s.reset_base(b.rct_output_count);
    std::string why;
    const bool ok = seed_like_node(s, snap, b, why);
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::printf("[load] ok=%d secs=%.1f base=%llu frontier=%llu outputs=%zu spent=%zu why=%s\n", ok ? 1 : 0,
                secs, (unsigned long long)s.first_output_index(), (unsigned long long)s.frontier(),
                s.output_count(), s.spent_count(), why.c_str());
    print_mem("after-seed");
    return ok;
}

// Independent streaming reader of the serialize() form (no ChainOutputSet code).
struct RefReader {
    std::ifstream f;
    std::uint64_t base = 0, n = 0, ns = 0;
    std::streamoff out_off = 0, ki_off = 0;
    static std::uint64_t le(const unsigned char* p) {
        std::uint64_t x = 0;
        for (int i = 7; i >= 0; --i) x = (x << 8) | p[i];
        return x;
    }
    bool u64_at(std::streamoff off, std::uint64_t& x) {
        unsigned char b[8];
        f.seekg(off);
        if (!f.read(reinterpret_cast<char*>(b), 8)) return false;
        x = le(b);
        return true;
    }
    bool open(const std::string& p) {
        f.open(p, std::ios::binary);
        if (!f) return false;
        std::uint64_t th = 0, nol = 0, nkl = 0;
        if (!u64_at(1, base) || !u64_at(9, th) || !u64_at(49, n)) return false;
        out_off = 57;
        std::streamoff o = out_off + std::streamoff(n * 80);
        if (!u64_at(o, nol)) return false;
        o += 8 + std::streamoff(nol * 40);
        if (!u64_at(o, nkl)) return false;
        o += 8 + std::streamoff(nkl * 32);
        if (!u64_at(o, ns)) return false;
        ki_off = o + 8;
        return true;
    }
    OutputRecord row(std::uint64_t i) {
        unsigned char b[80];
        f.clear();
        f.seekg(out_off + std::streamoff(i * 80));
        f.read(reinterpret_cast<char*>(b), 80);
        OutputRecord o;
        std::memcpy(o.pubkey.data(), b, 32);
        std::memcpy(o.commitment.data(), b + 32, 32);
        o.unlock_time = le(b + 64);
        o.height      = le(b + 72);
        return o;
    }
    Hash ki(std::uint64_t i) {
        Hash h{};
        f.clear();
        f.seekg(ki_off + std::streamoff(i * 32));
        f.read(reinterpret_cast<char*>(h.data()), 32);
        return h;
    }
};

static int run_equiv(const std::string& snap, const std::string& anc, std::uint64_t n_out,
                     std::uint64_t n_ki, std::uint64_t seed, const std::string& out_path) {
    AnchorBundle b;
    if (!load_anchor_file(anc, b)) return 2;
    ChainOutputSet s(0);
    if (!seed_timed(s, snap, b)) return 2;
    RefReader ref;
    if (!ref.open(snap)) { std::fprintf(stderr, "reference reader cannot parse %s\n", snap.c_str()); return 2; }
    std::ofstream ans(out_path, std::ios::binary | std::ios::trunc);
    std::mt19937_64 r(seed);
    const std::uint64_t base = ref.base, fr = ref.base + ref.n;
    const auto t0 = std::chrono::steady_clock::now();
    std::uint64_t mism_out = 0, mism_ring = 0, mism_ki = 0, spent_true = 0;
    // Single indices: 98% inside the snapshot, 2% at/after the frontier or below base.
    for (std::uint64_t t = 0; t < n_out; ++t) {
        std::uint64_t gi;
        const std::uint64_t sel = r() % 100;
        if (sel < 98 || ref.n == 0) gi = base + (ref.n ? r() % ref.n : 0);
        else if (sel == 98) gi = fr + (r() % 1000);
        else gi = base ? r() % base : fr + 1000 + (r() % 1000);
        std::vector<OutputRecord> got;
        const bool ok = s.resolve(0, {gi}, got);
        const bool rin = gi >= base && gi < fr;
        bool eq = ok == rin;
        OutputRecord rr{};
        if (rin) { rr = ref.row(gi - base); eq = eq && got.size() == 1 && same(got[0], rr); }
        if (!eq) ++mism_out;
        ans.put(ok ? 1 : 0);
        if (ok) for (const auto& o : got) {
            ans.write(reinterpret_cast<const char*>(o.pubkey.data()), 32);
            ans.write(reinterpret_cast<const char*>(o.commitment.data()), 32);
            ans.write(reinterpret_cast<const char*>(&o.unlock_time), 8);
            ans.write(reinterpret_cast<const char*>(&o.height), 8);
        }
    }
    // Rings of 16 (one in eight reaches past the frontier).
    for (std::uint64_t t = 0; t < n_out / 100; ++t) {
        std::vector<std::uint64_t> ring;
        for (int k = 0; k < 16; ++k) ring.push_back(base + (ref.n ? r() % ref.n : 0));
        if ((r() & 7) == 0) ring.push_back(fr + (r() % 3));
        std::sort(ring.begin(), ring.end());
        std::vector<OutputRecord> got;
        const bool ok = s.resolve(0, ring, got);
        bool rin = true;
        for (auto gi : ring) rin = rin && gi >= base && gi < fr;
        bool eq = ok == rin && (!ok || got.size() == ring.size());
        for (std::size_t k = 0; eq && ok && k < ring.size(); ++k) eq = same(got[k], ref.row(ring[k] - base));
        if (!eq) ++mism_ring;
        ans.put(ok ? 1 : 0);
    }
    // Key images: half snapshot rows (spent by definition), half misses (random
    // and 8-byte-prefix twins of snapshot rows) whose truth the reference
    // establishes by one streaming pass over the whole spent table.
    std::vector<Hash> known, unknown;
    for (std::uint64_t t = 0; t < n_ki / 2 && ref.ns; ++t) known.push_back(ref.ki(r() % ref.ns));
    for (std::uint64_t t = 0; t < n_ki - n_ki / 2; ++t) {
        if ((t & 1) && ref.ns) { Hash h = ref.ki(r() % ref.ns); h[31] ^= 0x01; unknown.push_back(h); }
        else unknown.push_back(rnd_hash(r));
    }
    std::unordered_set<Hash, HashHasher> uq(unknown.begin(), unknown.end()), uq_hit;
    {
        ref.f.clear();
        ref.f.seekg(ref.ki_off);
        std::vector<char> buf(32 * 65536);
        std::uint64_t left = ref.ns;
        while (left) {
            const std::uint64_t c = std::min<std::uint64_t>(left, 65536);
            ref.f.read(buf.data(), std::streamsize(c * 32));
            for (std::uint64_t i = 0; i < c; ++i) {
                Hash h; std::memcpy(h.data(), buf.data() + i * 32, 32);
                if (uq.count(h)) uq_hit.insert(h);
            }
            left -= c;
        }
    }
    for (const Hash& k : known) {
        const bool sp = s.is_spent(k);
        spent_true += sp;
        if (!sp) ++mism_ki;
        ans.put(sp ? 1 : 0);
    }
    for (const Hash& k : unknown) {
        const bool sp = s.is_spent(k);
        spent_true += sp;
        if (sp != (uq_hit.count(k) != 0)) ++mism_ki;
        ans.put(sp ? 1 : 0);
    }
    ans.close();
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::printf("[equiv] outputs=%llu rings=%llu key_images=%llu (known=%zu unknown=%zu, unknown-in-table=%zu) "
                "spent_true=%llu | mismatches: outputs=%llu rings=%llu key_images=%llu | %.1fs\n",
                (unsigned long long)n_out, (unsigned long long)(n_out / 100), (unsigned long long)n_ki,
                known.size(), unknown.size(), uq_hit.size(), (unsigned long long)spent_true,
                (unsigned long long)mism_out, (unsigned long long)mism_ring, (unsigned long long)mism_ki, secs);
    print_mem("after-equiv");
    return (mism_out || mism_ring || mism_ki) ? 1 : 0;
}

int main(int argc, char** argv) {
    if (argc >= 4 && std::strcmp(argv[1], "--load") == 0) {
        AnchorBundle b;
        if (!load_anchor_file(argv[3], b)) return 2;
        ChainOutputSet s(0);
        if (!seed_timed(s, argv[2], b)) return 2;
        const int hold = argc >= 5 ? std::atoi(argv[4]) : 0;
        for (int i = 0; i < hold; ++i) std::this_thread::sleep_for(std::chrono::seconds(1));
        print_mem("end");
        return 0;
    }
    if (argc >= 8 && std::strcmp(argv[1], "--equiv") == 0)
        return run_equiv(argv[2], argv[3], std::strtoull(argv[4], nullptr, 10),
                         std::strtoull(argv[5], nullptr, 10), std::strtoull(argv[6], nullptr, 10), argv[7]);
    return run_kat();
}
