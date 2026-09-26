// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_rx_seed_switch_kat.cpp   (RX-SEED-SWITCH)
//
// Stagenet capstone attempt 3: from Monero height 2216001 (the first block
// keyed by seed block 2215936) node C's stratum rejected EVERY share as
// "Low diff share". The served jobs carry no next_seed_hash (the settlement
// template provider sets it to nullopt; get_miner_data has none), so the
// switch reached the verifier as prefetch_epoch(S_new, nullopt): the victim
// was the slot holding S_old -- the slot the light VM was bound to -- and it
// was re-keyed IN PLACE (same randomx_cache*). LightVerifier's bind memo was
// pointer-only, so randomx_vm_set_cache() was never called again and the JIT
// light VM kept hashing with the OLD epoch's compiled superscalar programs over
// the NEW epoch's cache memory. It also evicted S_old, the seed every job
// issued before the switch was mined on.
//
// Real RandomX, light mode, JIT (randomx_get_flags() carries RANDOMX_FLAG_JIT
// on x86-64 whatever VerifierOptions::use_jit says). Ground truth for
// every (seed, blob) is a FRESH cache + FRESH VM built for that seed alone,
// plus the X8 vector (Monero mainnet block 3,000,000 PoW) for seed A.
//   (1) LightVerifier: the live un-announced switch A -> B, then B -> C, then
//       an announced C -> D; every hash byte-equal to the fresh reference; the
//       previous epoch stays resident for in-flight jobs; two caches max.
//   (2) O2RandomXVerifier through the MERGED XmrStratumServer: a job issued
//       on seed A, the template switches to seed B (no next_seed_hash), shares
//       on the new job AND on the pre-switch job submitted after the switch
//       are all accepted; network gate Accept on the post-switch job.
// RED on the pre-fix LightVerifier, GREEN on the fix. HEAVY (2 x 256 MiB
// light caches + one 256 MiB reference cache at a time); built only under
// XMR_BUILD_RANDOMX. Nonzero exit on any failure.
// ===========================================================================
#include <cstdio>
#include <cstring>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/xmr_o2_randomx_verify.hpp"

using namespace c2pool::v37n::xmr::o2;
using ::c2pool::xmr::LightVerifier;
using ::c2pool::xmr::SeedHash;
using ::c2pool::xmr::VerifierOptions;

namespace {

int fails = 0;
void check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++fails;
}

bool hex_to_bytes(const char* hex, std::vector<uint8_t>& out) {
    out.clear();
    const size_t n = std::strlen(hex);
    if (n % 2) return false;
    for (size_t i = 0; i < n; i += 2) {
        uint8_t b;
        if (!strat::StratumDialect::from_hex_byte(hex[i], hex[i + 1], b)) return false;
        out.push_back(b);
    }
    return true;
}

long rss_kib() {
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line))
        if (line.rfind("VmRSS:", 0) == 0) return std::atol(line.c_str() + 6);
    return -1;
}

// X8 vector (Monero mainnet block 3,000,000): seed A, blob, PoW.
const char* kSeedAHex = "3c512c1a6e8210e985b47e855eaf93af952abb61b9bd032872a376910ba7d448";
const char* kBlobHex =
    "1010dea6caa906cc64d29f62794dbb5309732f74447d88389198cfbf86a499bd"
    "5b4b5347bc43ae2b8000313cc88694451e92299e5283b2c51985e5c0d31b8d91"
    "0f53d9a8b167a24e7bdf0626";
const char* kPowAHex = "309e84a7d1175490a14cf722f8f3862b3adda4fff904a5d72175ec0100000000";
constexpr size_t kNonceOff = 39;

SeedHash seed_fill(uint8_t v) { SeedHash s; for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(v + 7 * i); return s; }

void set_nonce(std::vector<uint8_t>& blob, uint32_t n) {
    for (size_t i = 0; i < 4; ++i) blob[kNonceOff + i] = static_cast<uint8_t>(n >> (8 * i));
}

// Fresh-cache + fresh-VM ground truth for one seed (one 256 MiB cache at a time).
struct Reference {
    randomx_cache* cache = nullptr;
    randomx_vm*    vm    = nullptr;
    explicit Reference(const SeedHash& seed, bool jit = true) {
        VerifierOptions o; o.use_jit = jit;
        cache = randomx_alloc_cache(::c2pool::xmr::cache_flags(o));
        if (!cache) return;
        randomx_init_cache(cache, seed.data(), seed.size());
        vm = randomx_create_vm(::c2pool::xmr::vm_flags(o), cache, nullptr);
    }
    ~Reference() { if (vm) randomx_destroy_vm(vm); if (cache) randomx_release_cache(cache); }
    bool ok() const { return vm != nullptr; }
    Hash32 hash(const std::vector<uint8_t>& blob) {
        Hash32 h{}; randomx_calculate_hash(vm, blob.data(), blob.size(), h.data()); return h;
    }
};

} // namespace

namespace {

// ---------------------------------------------------------------------------
// Suite 1 -- LightVerifier across switches.
// ---------------------------------------------------------------------------
void suite_verifier(bool jit, const std::vector<uint8_t>& blob, const SeedHash& A,
                    const Hash32& powA) {
    std::printf("== (1) LightVerifier across seed switches (%s) ==\n", jit ? "jit" : "interpreter");
    const SeedHash B = seed_fill(0x11), C = seed_fill(0x22), D = seed_fill(0x33);
    Hash32 refA{}, refB{}, refC{}, refD{};
    {
        Reference r(A, jit); check(r.ok(), "reference A: fresh cache + VM"); refA = r.hash(blob);
    }
    { Reference r(B, jit); refB = r.hash(blob); }
    { Reference r(C, jit); refC = r.hash(blob); }
    { Reference r(D, jit); refD = r.hash(blob); }
    check(refA == powA, "reference A == X8 vector PoW (mainnet block 3,000,000)");
    check(refA != refB && refB != refC && refC != refD, "references differ per seed");

    LightVerifier v;
    VerifierOptions o; o.use_jit = jit;
    check(v.init(o), "init: two light caches + one light VM");
    const long rss0 = rss_kib();
    Hash32 h{};

    // Epoch A, never announced as `next` (as the live template path serves it).
    v.prefetch_epoch(A, std::nullopt);
    check(v.hash(blob.data(), blob.size(), A, h.data()) && h == refA, "epoch A: hash == reference (VM bound to A's slot)");
    const long rss_a = rss_kib();

    // UN-ANNOUNCED switch A -> B (node C at 2216001).
    v.prefetch_epoch(B, std::nullopt);
    const long rss_b = rss_kib();
    const bool gotB = v.hash(blob.data(), blob.size(), B, h.data());
    check(gotB && h == refB, "switch A->B (no next_seed): hash on B == fresh reference B (VM re-keyed with the cache)");
    check(v.seed_resident(A), "switch A->B: A still resident for jobs issued before the switch");
    check(v.hash(blob.data(), blob.size(), A, h.data()) && h == refA, "switch A->B: in-flight job on A still hashes == reference A");
    check(v.hash(blob.data(), blob.size(), B, h.data()) && h == refB, "switch A->B: back on B after A == reference B");

    // Second un-announced switch B -> C: the older epoch (A) goes, B stays.
    v.prefetch_epoch(C, std::nullopt);
    check(v.hash(blob.data(), blob.size(), C, h.data()) && h == refC, "switch B->C: hash on C == reference C");
    check(v.seed_resident(B) && !v.seed_resident(A), "switch B->C: B (previous) kept, A (older) evicted");
    check(v.hash(blob.data(), blob.size(), B, h.data()) && h == refB, "switch B->C: in-flight job on B == reference B");

    // Announced path (monerod templates): C current, D next, then switch to D.
    v.hash(blob.data(), blob.size(), C, h.data());
    v.prefetch_epoch(C, D);
    check(v.seed_resident(C) && v.seed_resident(D), "announced C,D: both resident");
    check(v.hash(blob.data(), blob.size(), D, h.data()) && h == refD, "announced switch C->D: hash on D == reference D");
    check(v.hash(blob.data(), blob.size(), C, h.data()) && h == refC, "announced switch C->D: in-flight job on C == reference C");
    const long rss_end = rss_kib();
    std::printf("  RSS KiB: after init=%ld epochA=%ld after-switch-prefetch=%ld end=%ld (two light caches max)\n",
                rss0, rss_a, rss_b, rss_end);
    check(rss_end > 0 && rss_end - rss0 < 3L * 256 * 1024, "RSS growth across four epochs < 3 x 256 MiB (<= two caches live)");
}

} // namespace

namespace {

// ---------------------------------------------------------------------------
// Suite 2 -- O2RandomXVerifier through the MERGED XmrStratumServer.
// Template 1 = epoch A (height kH-1), template 2 = epoch B (height kH, the
// first height keyed by the new seed). Neither carries next_seed_hash.
// ---------------------------------------------------------------------------
constexpr uint64_t kH = 2216001;          // capstone attempt 3 switch height
constexpr uint64_t kShareDiff = 16;

struct SwitchTemplates final : strat::ITemplateSource {
    std::vector<uint8_t> blob1, blob2;   // nonce zeroed
    Seed32 seed1{}, seed2{};
    uint32_t current = 1;
    bool get_job(uint32_t en, strat::TemplateJob& out) override { return rebuild_blob(current, en, out); }
    bool rebuild_blob(uint32_t id, uint32_t, strat::TemplateJob& out) override {
        if (id != 1 && id != 2) return false;
        out.blob = (id == 1) ? blob1 : blob2;
        out.nonce_offset = kNonceOff; out.template_id = id;
        out.height = (id == 1) ? kH - 1 : kH;
        out.mainchain_target = 0xFFFFFFFFFFFFFFFFULL / kShareDiff;   // every valid share is a "block"
        out.lane_target = 0xFFFFFFFFFFFFFFFFULL / kShareDiff;
        out.seed_hash = (id == 1) ? seed1 : seed2;
        out.next_seed_hash = std::nullopt;                         // as the settlement provider serves it
        out.monero_major_version = 16;
        return true;
    }
    uint32_t max_extra_nonces() const override { return 1; }
};

struct GateSink final : strat::IShareSink {
    O2RandomXVerifier& v; SwitchTemplates& t;
    int accepted = 0, net_accept = 0, net_other = 0;
    GateSink(O2RandomXVerifier& v_, SwitchTemplates& t_) : v(v_), t(t_) {}
    void on_accepted_share(const strat::AcceptedShare&) override { ++accepted; }
    void submit_network_block(uint32_t id, uint32_t nonce, uint32_t en) override {
        strat::TemplateJob tj;
        if (!t.rebuild_blob(id, en, tj)) { ++net_other; return; }
        for (size_t i = 0; i < 4; ++i) tj.blob[tj.nonce_offset + i] = static_cast<uint8_t>(nonce >> (8 * i));
        Hash32 pow{};
        const auto nv = v.verify_network_block(tj.blob.data(), tj.blob.size(), tj.seed_hash,
                                               NetworkDifficulty{kShareDiff, 0}, pow);
        (nv == NetworkVerdict::Accept ? net_accept : net_other)++;
    }
};

struct Lines final : strat::ITransport {
    std::vector<std::string> lines;
    bool send_line(uint64_t, std::string_view l) override { lines.emplace_back(l); return true; }
    void close(uint64_t) override {}
};

// Grind `want` nonces whose FRESH-reference hash meets kShareDiff.
std::vector<uint32_t> grind(const std::vector<uint8_t>& blob0, const Seed32& seed, int want, uint32_t start) {
    Reference r(seed);
    std::vector<uint32_t> out;
    std::vector<uint8_t> b = blob0;
    const uint64_t target = 0xFFFFFFFFFFFFFFFFULL / kShareDiff;
    for (uint32_t n = start; out.size() < static_cast<size_t>(want) && n < start + 20000; ++n) {
        set_nonce(b, n);
        const Hash32 h = r.hash(b);
        uint64_t top = 0;
        for (int i = 0; i < 8; ++i) top |= static_cast<uint64_t>(h[24 + i]) << (8 * i);
        if (top <= target) out.push_back(n);
    }
    return out;
}

std::string nonce_hex(uint32_t n) {
    uint8_t b[4]; for (int i = 0; i < 4; ++i) b[i] = static_cast<uint8_t>(n >> (8 * i));
    return strat::StratumDialect::to_hex(b, 4);
}

struct Tally { int ok = 0, lowdiff = 0, other = 0; };
void tally(const Lines& tr, Tally& t) {
    const std::string& l = tr.lines.back();
    if (l.find("\"status\":\"OK\"") != std::string::npos) ++t.ok;
    else if (l.find("Low diff share") != std::string::npos) ++t.lowdiff;
    else ++t.other;
}

void suite_stratum(const std::vector<uint8_t>& blob, const Seed32& A) {
    std::printf("== (2) O2RandomXVerifier x XmrStratumServer across the switch ==\n");
    const Seed32 B = seed_fill(0x11);
    SwitchTemplates t;
    t.blob1 = blob; set_nonce(t.blob1, 0);
    t.blob2 = blob; t.blob2[1] ^= 0x5a; set_nonce(t.blob2, 0);   // a different header for the new tip
    t.seed1 = A; t.seed2 = B;
    const auto n1 = grind(t.blob1, A, 6, 1);
    const auto n2 = grind(t.blob2, B, 4, 1);
    check(n1.size() == 6 && n2.size() == 4, "grind: 6 valid nonces on job A, 4 on job B (fresh reference VM)");
    const std::string res(64, '0');

    O2RandomXVerifier v; RandomXPolicy p; p.enabled = true;
    check(v.init(p), "init (jit)");
    std::printf("  %s\n", v.describe().c_str());
    GateSink sink(v, t); Lines tr;
    strat::XmrStratumServer srv(t, v, sink, tr);
    strat::XmrStratumSession s(1);

    // Pre-switch: template 1 on seed A.
    v.post_seeds(A, std::nullopt); v.drain_pending();
    check(srv.handle_login(s, 1, "4xxx.rig"), "login -> job 1 (template 1, seed A)");
    Tally pre;
    for (int i = 0; i < 3; ++i) {
        strat::SubmitFields f{"", "1", nonce_hex(n1[i]), res};
        srv.handle_submit(s, 10 + i, f); tally(tr, pre);
    }
    std::printf("  pre-switch job A: ok=%d lowdiff=%d other=%d\n", pre.ok, pre.lowdiff, pre.other);
    check(pre.ok == 3, "pre-switch: 3/3 valid shares on job A accepted");

    // THE SWITCH: tip moves to kH, template 2 on seed B, no next_seed_hash.
    const long rss_before = rss_kib();
    t.current = 2;
    v.post_seeds(B, std::nullopt); v.drain_pending();
    srv.broadcast_job(s);                                 // job 2 (template 2, seed B)
    const long rss_after = rss_kib();
    check(tr.lines.back().find("\"job_id\":\"") != std::string::npos, "broadcast: job 2 pushed");

    Tally postB, postA;
    for (int i = 0; i < 4; ++i) {                         // new job, new seed
        strat::SubmitFields f{"", "2", nonce_hex(n2[i]), res};
        srv.handle_submit(s, 20 + i, f); tally(tr, postB);
    }
    for (int i = 3; i < 6; ++i) {                         // job issued BEFORE the switch, submitted AFTER
        strat::SubmitFields f{"", "1", nonce_hex(n1[i]), res};
        srv.handle_submit(s, 30 + i, f); tally(tr, postA);
    }
    std::printf("  post-switch job B: ok=%d lowdiff=%d other=%d | pre-switch job A submitted after: ok=%d lowdiff=%d other=%d\n",
                postB.ok, postB.lowdiff, postB.other, postA.ok, postA.lowdiff, postA.other);
    std::printf("  network gate: accept=%d other=%d | RSS KiB before switch=%ld after=%ld\n",
                sink.net_accept, sink.net_other, rss_before, rss_after);
    std::printf("  %s\n", v.describe().c_str());
    check(postB.ok == 4 && postB.lowdiff == 0, "post-switch: 4/4 valid shares on job B accepted, 0 'Low diff share'");
    check(postA.ok == 3 && postA.lowdiff == 0 && postA.other == 0,
          "straddle: 3/3 shares on the pre-switch job (seed A) submitted after the switch accepted");
    check(sink.accepted == 10, "sink: 10 accepted shares total");
    check(sink.net_accept == 10 && sink.net_other == 0, "exact network gate Accept for every share (blocks across the switch)");
}

} // namespace

int main() {
    std::vector<uint8_t> blob, sv, pv;
    if (!hex_to_bytes(kBlobHex, blob) || !hex_to_bytes(kSeedAHex, sv) || !hex_to_bytes(kPowAHex, pv)
        || sv.size() != 32 || pv.size() != 32) { std::printf("bad vector hex\n"); return 2; }
    SeedHash A; std::memcpy(A.data(), sv.data(), 32);
    Hash32 powA; std::memcpy(powA.data(), pv.data(), 32);
    std::printf("== v37_xmr_rx_seed_switch_kat ==\n");
    suite_verifier(true, blob, A, powA);
    suite_stratum(blob, A);
    std::printf("== %s (%d failures) ==\n", fails ? "FAIL" : "OK", fails);
    return fails ? 1 : 0;
}
