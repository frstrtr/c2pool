// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_o2_randomx_kat.cpp   (X9 O-2, wire 2)
//
// The runtime RandomX IPowVerifier (xmr/xmr_o2_randomx_verify.hpp:
// O2RandomXVerifier over the production LightVerifier + librandomx) against the
// X8 KAT vector — Monero mainnet block 3,000,000 (seed = block id at 2,998,272,
// difficulty 308739704685, PoW 309e84a7…) — in two suites:
//   (A) the verifier alone: fail-closed disabled/compiled-out modes, JIT ->
//       interpreter init, the STRICT no-Argon2d-on-submit invariant (I2), the
//       main-thread -> listener seed mailbox, randomx_hash == the KAT PoW, the
//       u64 seam rule, the EXACT 128-bit network gate (Accept / BelowTarget at
//       8x / BelowTarget at 2^64 / Malformed) with the byte-identical hash memo,
//       and the opt-in lazy policy;
//   (B) the verifier plugged into the MERGED X5 XmrStratumServer through
//       handle_login / handle_submit with fake template/sink/transport seams:
//       "Couldn't check PoW" before the template hook, the O-2 flow (hook ->
//       prefetch -> login -> winning submit -> submit_network_block -> exact
//       gate Accept, 1 hash total), a wrong nonce = lane share only, and the
//       disabled verifier never reaching the sink.
// HEAVY: 2 x 256 MiB light caches per verifier instance (light mode only,
// never the 2 GiB dataset). Built only under XMR_BUILD_RANDOMX (the
// non-sanitizer CI leg). Nonzero exit on any failure.
// ===========================================================================
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/xmr_o2_randomx_verify.hpp"

using namespace c2pool::v37n::xmr::o2;

namespace {

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

int fails = 0;
void check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++fails;
}

// The X8 KAT suite-C vector (Monero mainnet block 3,000,000).
const char* kSeedHex = "3c512c1a6e8210e985b47e855eaf93af952abb61b9bd032872a376910ba7d448";
const char* kBlobHex =
    "1010dea6caa906cc64d29f62794dbb5309732f74447d88389198cfbf86a499bd"
    "5b4b5347bc43ae2b8000313cc88694451e92299e5283b2c51985e5c0d31b8d91"
    "0f53d9a8b167a24e7bdf0626";
const char* kPowHex = "309e84a7d1175490a14cf722f8f3862b3adda4fff904a5d72175ec0100000000";
const uint64_t kDifficulty = 308739704685ULL;
const uint64_t kHeight = 3000000;

struct Vector {
    std::vector<uint8_t> blob;
    Seed32 seed{};
    Hash32 want{};
};

bool load_vector(Vector& v) {
    std::vector<uint8_t> seedv, powv;
    if (!hex_to_bytes(kSeedHex, seedv) || !hex_to_bytes(kBlobHex, v.blob) || !hex_to_bytes(kPowHex, powv))
        return false;
    if (seedv.size() != 32 || powv.size() != 32) return false;
    std::memcpy(v.seed.data(), seedv.data(), 32);
    std::memcpy(v.want.data(), powv.data(), 32);
    return true;
}

// ---------------------------------------------------------------------------
// Suite A — the verifier alone.
// ---------------------------------------------------------------------------
void suite_a(const Vector& kat) {
    const std::vector<uint8_t>& blob = kat.blob;
    const Seed32& seed = kat.seed;
    const Hash32& want = kat.want;
    const uint64_t difficulty = kDifficulty;
    const uint64_t height = kHeight;

    std::printf("== (A) O2RandomXVerifier ==\n");

    // (0) disabled policy: fail-closed everywhere
    {
        O2RandomXVerifier v;
        RandomXPolicy p; p.enabled = false;
        const bool r = v.init(p);
        Hash32 h{};
        check(!r && !v.ready() && !v.network_blocks_allowed(), "disabled: init false, not ready, network blocks refused");
        check(!v.randomx_hash(blob.data(), blob.size(), height, seed, h), "disabled: randomx_hash -> false (CouldNotCheck)");
        const auto nv = v.verify_network_block(blob.data(), blob.size(), seed, NetworkDifficulty{difficulty, 0}, h);
#if defined(V37_XMR_O2_WITH_RANDOMX)
        check(nv == NetworkVerdict::VerifyUnavailable, "disabled: verify_network_block -> VerifyUnavailable");
        check(v.mode() == O2RandomXVerifier::Mode::Disabled, "disabled: mode == Disabled");
#else
        check(nv == NetworkVerdict::VerifyUnavailable, "compiled-out: verify_network_block -> VerifyUnavailable");
        check(v.mode() == O2RandomXVerifier::Mode::CompiledOut, "compiled-out: mode == CompiledOut");
        check(!O2RandomXVerifier::meets_network_difficulty(want, NetworkDifficulty{1, 0}), "compiled-out: meets_network_difficulty fail-closed");
#endif
        std::printf("  %s\n", v.describe().c_str());
    }

#if defined(V37_XMR_O2_WITH_RANDOMX)
    // (1) enabled: init (JIT, interpreter fallback)
    O2RandomXVerifier v;
    RandomXPolicy p; p.enabled = true;
    check(v.init(p), "enabled: init ok");
    std::printf("  %s\n", v.describe().c_str());
    check(v.ready() && v.network_blocks_allowed(), "enabled: ready + network blocks allowed");

    // (2) strict I2: seed not resident -> refuse, no cache init
    Hash32 h{};
    check(!v.randomx_hash(blob.data(), blob.size(), height, seed, h), "I2 strict: non-resident seed -> false");
    check(v.stats().seed_misses == 1 && v.stats().prefetches == 0, "I2 strict: seed_misses=1, prefetches=0");
    check(v.verify_network_block(blob.data(), blob.size(), seed, NetworkDifficulty{difficulty, 0}, h) == NetworkVerdict::SeedNotResident,
          "I2 strict: verify_network_block -> SeedNotResident");

    // (3) main-thread post_seeds -> listener drain_pending (prefetch)
    v.post_seeds(seed, std::nullopt);
    check(v.drain_pending(), "mailbox: drain_pending applied a pair");
    check(!v.drain_pending(), "mailbox: second drain is a no-op");
    check(v.seed_resident(seed), "prefetch: seed resident");
    check(v.stats().prefetches == 1, "prefetch: counted once");
    check(v.ensure_seeds(seed, std::nullopt) && v.stats().prefetches == 1, "ensure_seeds: resident pair is a no-op (no re-key)");

    // (4) IPowVerifier::randomx_hash reproduces the mainnet PoW
    check(v.randomx_hash(blob.data(), blob.size(), height, seed, h), "randomx_hash: ok");
    check(h == want, "randomx_hash: == block 3,000,000 PoW (X8 KAT vector)");
    const uint64_t target = 0xFFFFFFFFFFFFFFFFULL / difficulty;
    check(v.meets_target(h, target), "meets_target: block clears its own network target (u64 rule)");
    check(!v.meets_target(h, target / 4), "meets_target: fails a 4x harder target");

    // (5) exact network gate: memo reuse + meets_difficulty_128
    Hash32 h2{};
    auto nv = v.verify_network_block(blob.data(), blob.size(), seed, NetworkDifficulty{difficulty, 0}, h2);
    check(nv == NetworkVerdict::Accept, "verify_network_block: Accept at the block's difficulty");
    check(h2 == want, "verify_network_block: returns the PoW hash");
    check(v.stats().memo_hits == 1 && v.stats().hashes == 1, "verify_network_block: reused the submit's hash (memo hit, no re-hash)");
    nv = v.verify_network_block(blob.data(), blob.size(), seed, NetworkDifficulty{difficulty * 8, 0}, h2);
    check(nv == NetworkVerdict::BelowTarget, "verify_network_block: BelowTarget at 8x difficulty");
    nv = v.verify_network_block(blob.data(), blob.size(), seed, NetworkDifficulty{0, 1}, h2);
    check(nv == NetworkVerdict::BelowTarget, "verify_network_block: BelowTarget at difficulty 2^64 (128-bit path)");
    std::vector<uint8_t> blob2 = blob; blob2[39] ^= 0x01;
    const auto before = v.stats();
    nv = v.verify_network_block(blob2.data(), blob2.size(), seed, NetworkDifficulty{1, 0}, h2);
    check(nv == NetworkVerdict::Accept, "verify_network_block: nonce+1 at difficulty 1 -> Accept (any hash meets diff 1)");
    check(v.stats().hashes == before.hashes + 1 && v.stats().memo_hits == before.memo_hits, "verify_network_block: changed bytes re-hashed (no memo hit)");
    check(h2 != want, "verify_network_block: changed bytes -> different PoW");
    check(v.verify_network_block(blob.data(), blob.size(), seed, NetworkDifficulty{0, 0}, h2) == NetworkVerdict::Malformed, "verify_network_block: zero difficulty -> Malformed");
    check(v.verify_network_block(nullptr, 0, seed, NetworkDifficulty{1, 0}, h2) == NetworkVerdict::Malformed, "verify_network_block: empty blob -> Malformed");
    check(O2RandomXVerifier::meets_network_difficulty(want, NetworkDifficulty{difficulty, 0}), "meets_network_difficulty: exact rule on the KAT hash");

    // (6) lazy policy: miss -> prefetch inside the submit
    {
        O2RandomXVerifier lz;
        RandomXPolicy lp; lp.enabled = true; lp.lazy_prefetch_on_miss = true;
        check(lz.init(lp), "lazy: init ok");
        Hash32 lh{};
        check(lz.randomx_hash(blob.data(), blob.size(), height, seed, lh) && lh == want, "lazy: non-resident seed prefetched inside randomx_hash, PoW matches");
        check(lz.stats().prefetches == 1 && lz.stats().seed_misses == 0, "lazy: prefetches=1, seed_misses=0");
    }
    std::printf("  %s\n", v.describe().c_str());
#endif
}

// ---------------------------------------------------------------------------
// Suite B — the verifier through the MERGED XmrStratumServer.
// ---------------------------------------------------------------------------
struct FakeTemplates final : strat::ITemplateSource {
    std::vector<uint8_t> blob;   // hashing blob with nonce ZEROED (served to miners)
    Seed32 seed{};
    uint64_t difficulty = 0;
    bool get_job(uint32_t, strat::TemplateJob& out) override { return rebuild_blob(7, 0, out); }
    bool rebuild_blob(uint32_t template_id, uint32_t, strat::TemplateJob& out) override {
        if (template_id != 7) return false;
        out.blob = blob; out.nonce_offset = 39; out.template_id = 7; out.height = kHeight;
        out.mainchain_target = 0xFFFFFFFFFFFFFFFFULL / difficulty;
        out.lane_target = 0xFFFFFFFFFFFFFFFFULL;           // lane diff 1
        out.seed_hash = seed; out.next_seed_hash = std::nullopt; out.monero_major_version = 16;
        return true;
    }
    uint32_t max_extra_nonces() const override { return 1; }
};

struct FakeSink final : strat::IShareSink {
    O2RandomXVerifier& v; FakeTemplates& t;
    int submits = 0, accepted = 0; bool last_net_flag = false;
    NetworkVerdict verdict = NetworkVerdict::Malformed; Hash32 pow{};
    FakeSink(O2RandomXVerifier& v_, FakeTemplates& t_) : v(v_), t(t_) {}
    void on_accepted_share(const strat::AcceptedShare& s) override { ++accepted; last_net_flag = s.is_network_block; }
    // The O-2 share-sink pattern: rebuild + patch nonce + EXACT gate.
    void submit_network_block(uint32_t template_id, uint32_t nonce, uint32_t extra_nonce) override {
        ++submits;
        strat::TemplateJob tj;
        if (!t.rebuild_blob(template_id, extra_nonce, tj)) { verdict = NetworkVerdict::Malformed; return; }
        for (size_t i = 0; i < 4; ++i) tj.blob[tj.nonce_offset + i] = static_cast<uint8_t>(nonce >> (8 * i));
        if (!v.network_blocks_allowed()) { verdict = NetworkVerdict::VerifyUnavailable; return; }
        verdict = v.verify_network_block(tj.blob.data(), tj.blob.size(), tj.seed_hash,
                                         NetworkDifficulty{t.difficulty, 0}, pow);
        // only NetworkVerdict::Accept would patch the FULL blob and submit_block here
    }
};

struct FakeTransport final : strat::ITransport {
    std::vector<std::string> lines; int closed = 0;
    bool send_line(uint64_t, std::string_view l) override { lines.emplace_back(l); return true; }
    void close(uint64_t) override { ++closed; }
};

void suite_b(const Vector& kat) {
    std::printf("== (B) O2RandomXVerifier x XmrStratumServer ==\n");
#if defined(V37_XMR_O2_WITH_RANDOMX)
    const std::vector<uint8_t>& blob = kat.blob;
    const Seed32& seed = kat.seed;
    const Hash32& want = kat.want;
    const std::string nonce_hex = strat::StratumDialect::to_hex(blob.data() + 39, 4);   // winning nonce, LE bytes verbatim

    FakeTemplates t; t.blob = blob; t.seed = seed; t.difficulty = kDifficulty;
    for (size_t i = 0; i < 4; ++i) t.blob[39 + i] = 0;    // served job carries a zero nonce

    // strict I2 before any template hook: submit -> Couldn't check PoW
    {
        O2RandomXVerifier v; RandomXPolicy p; p.enabled = true; check(v.init(p), "init");
        FakeSink sink(v, t); FakeTransport tr;
        strat::XmrStratumServer srv(t, v, sink, tr);
        strat::XmrStratumSession s(1);
        check(srv.handle_login(s, 1, "4xxx.rig"), "login ok (no prefetch yet)");
        strat::SubmitFields f{"", "1", nonce_hex, kPowHex};
        check(srv.handle_submit(s, 2, f), "submit handled (connection kept)");
        check(tr.lines.back().find("Couldn't check PoW") != std::string::npos, "no seed resident -> \"Couldn't check PoW\" (fail-closed, no cache init on submit)");
        check(sink.submits == 0 && sink.accepted == 0, "no submit_network_block, no accepted share");
        std::printf("  %s\n", v.describe().c_str());
    }

    // the O-2 flow: template hook -> prefetch -> login -> submit
    {
        O2RandomXVerifier v; RandomXPolicy p; p.enabled = true; check(v.init(p), "init");
        FakeSink sink(v, t); FakeTransport tr;
        strat::XmrStratumServer srv(t, v, sink, tr);

        strat::TemplateJob tj; t.get_job(0, tj);
        v.post_seeds(tj.seed_hash, tj.next_seed_hash);
        check(v.drain_pending() && v.seed_resident(seed), "template hook: seeds prefetched on the listener side");

        strat::XmrStratumSession s(2);
        check(srv.handle_login(s, 1, "4xxx+1.rig"), "login ok");
        check(tr.lines.back().find("\"algo\":\"rx/0\"") != std::string::npos, "login reply carries algo rx/0");

        strat::SubmitFields f{"", "1", nonce_hex, kPowHex};
        check(srv.handle_submit(s, 2, f), "submit handled");
        check(tr.lines.back().find("\"status\":\"OK\"") != std::string::npos, "submit reply OK");
        check(sink.submits == 1, "server called submit_network_block once");
        check(sink.verdict == NetworkVerdict::Accept, "sink exact gate: Accept (hash*difficulty < 2^256)");
        check(sink.pow == want, "sink saw the block 3,000,000 PoW");
        check(sink.accepted == 1 && sink.last_net_flag, "accepted share flagged is_network_block");
        check(v.stats().memo_hits == 1 && v.stats().hashes == 1, "exact gate reused the submit hash (1 hash total)");

        // wrong nonce -> not a network block; lane diff 1 -> still an accepted share
        std::string bad = nonce_hex; bad[0] = (bad[0] == '0') ? '1' : '0';
        strat::SubmitFields g{"", "1", bad, kPowHex};
        check(srv.handle_submit(s, 3, g), "submit(wrong nonce) handled");
        check(sink.submits == 1, "wrong nonce: no network submit");
        check(sink.accepted == 2 && !sink.last_net_flag, "wrong nonce: accepted as lane share (diff 1), not network");
        check(tr.lines.back().find("\"status\":\"OK\"") != std::string::npos, "wrong nonce: reply OK (lane share)");
        std::printf("  %s\n", v.describe().c_str());
    }

    // disabled verifier: every submit is CouldNotCheck, sink refuses
    {
        O2RandomXVerifier v; RandomXPolicy p; p.enabled = false; v.init(p);
        FakeSink sink(v, t); FakeTransport tr;
        strat::XmrStratumServer srv(t, v, sink, tr);
        strat::XmrStratumSession s(3);
        srv.handle_login(s, 1, "4xxx");
        strat::SubmitFields f{"", "1", nonce_hex, kPowHex};
        srv.handle_submit(s, 2, f);
        check(tr.lines.back().find("Couldn't check PoW") != std::string::npos, "disabled: submit -> Couldn't check PoW");
        check(sink.submits == 0, "disabled: never reaches submit_network_block");
    }
#else
    (void)kat;
    std::printf("  (skipped: RandomX compiled out)\n");
#endif
}

} // namespace

int main() {
    Vector kat;
    if (!load_vector(kat)) {
        std::printf("bad KAT vector hex\n");
        return 2;
    }
    std::printf("== v37_xmr_o2_randomx_kat (X8 vector: mainnet block %llu) ==\n",
                static_cast<unsigned long long>(kHeight));
    suite_a(kat);
    suite_b(kat);
    std::printf("== %s (%d failures) ==\n", fails ? "FAIL" : "OK", fails);
    return fails ? 1 : 0;
}
