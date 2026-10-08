// SPDX-License-Identifier: AGPL-3.0-or-later
//
// xmr_cpu_miner_kat.cpp — known-answer / property tests for the in-process
// RandomX CPU miner (src/impl/xmr/pow/xmr_cpu_miner.hpp).
//
// THE CLAIM UNDER TEST, in one sentence: the miner produces nothing the node
// does not already validate. Concretely:
//
//   K1  topology/pinning helpers are sane and never fatal;
//   K2  a LIGHT-mode miner finds a hit at an easy lane target, and EVERY hash
//       it reports is reproduced BIT-FOR-BIT by the production LightVerifier
//       (randomx_verify.hpp) over the same blob with the reported nonce
//       patched in — i.e. the miner is a client of librandomx, not a second
//       implementation of it;
//   K3  the reported achieved_target is exactly the top 64-bit LE word of the
//       hash, the same number xmr_stratum.cpp computes for a submit;
//   K4  no false positives: an impossible network target yields zero block
//       hits over thousands of hashes, while the easy lane target keeps
//       firing (so the negative is a real negative, not a dead miner);
//   K5  huge pages degrade gracefully: large_pages=true starts and mines on a
//       host with no hugepages configured, and says so;
//   K6  a new job takes over the workers, and — the invariant the node really
//       depends on — EVERY hit verifies against the blob of the template it
//       NAMES. (A hit for the previous template may still land after set_job()
//       returns: a worker notices the switch only every 64 hashes and then
//       closes its pipeline with one last hash. That is real work on a template
//       the provider still retains, not staleness to be suppressed.);
//   K7  SELF-CONTAINED FIND: at a *network* target a regtest node would set,
//       the miner produces `network`-flagged hits, and each one passes the
//       node's own exact 128-bit acceptance rule (meets_difficulty_128 from
//       randomx_verify.hpp) when re-hashed by the verifier. This is the
//       in-process, no-daemon, no-external-miner shape of the find proof;
//   K8  REGRESSION: a verifier re-key (prefetch_epoch, listener thread) racing
//       a miner re-key (set_job, main thread) does not crash. Before
//       randomx_init_lock.hpp this pair died with SIGFPE inside
//       randomx_reciprocal() on a live regtest run.
//
// Heavy: it allocates one 256 MiB Argon2d cache for the miner and two for the
// verifier. Gated behind XMR_BUILD_RANDOMX with the other RandomX targets.

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "randomx_verify.hpp"
#include "xmr_cpu_miner.hpp"

namespace mn = c2pool::xmr::miner;

static int g_fail = 0;
static void check(bool ok, const char* name, const std::string& detail = {}) {
    std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name,
                detail.empty() ? "" : " — ", detail.c_str());
    if (!ok) ++g_fail;
}

static std::uint64_t target_from_diff(std::uint64_t d) {
    return d ? (0xFFFFFFFFFFFFFFFFULL / d) : 0xFFFFFFFFFFFFFFFFULL;
}
static std::uint64_t top_word_le(const mn::HashBytes& h) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<std::uint64_t>(h[mn::kHashSize - 8 + i]) << (8 * i);
    return v;
}

// A stand-in Monero v16 hashing blob: 76 bytes, nonce at offset 39. The exact
// bytes are irrelevant to RandomX (it hashes whatever it is given); what
// matters is that the miner and the verifier hash the SAME bytes.
static constexpr std::size_t kNonceOffset = 39;
static std::vector<std::uint8_t> make_blob() {
    std::vector<std::uint8_t> b(76, 0);
    for (std::size_t i = 0; i < b.size(); ++i)
        b[i] = static_cast<std::uint8_t>(0x10 + (i * 7) % 0xE0);
    b[0] = 16;  // major_version
    b[1] = 16;  // minor_version
    for (std::size_t i = 0; i < 4; ++i) b[kNonceOffset + i] = 0;
    return b;
}

static mn::SeedBytes make_seed(std::uint8_t tag) {
    mn::SeedBytes s{};
    for (std::size_t i = 0; i < s.size(); ++i)
        s[i] = static_cast<std::uint8_t>((i * 11 + tag) & 0xFF);
    return s;
}

static c2pool::xmr::SeedHash to_vseed(const mn::SeedBytes& s) {
    c2pool::xmr::SeedHash v{};
    std::memcpy(v.data(), s.data(), s.size());
    return v;
}

// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    bool quick = false;
    for (int i = 1; i < argc; ++i)
        if (std::string(argv[i]) == "--quick") quick = true;

    std::printf("== xmr_cpu_miner_kat ==\n");

    // ---- K1: topology + pinning helpers ----------------------------------
    {
        const std::vector<int> order = mn::detail::preferred_cpu_order();
        const std::set<int> uniq(order.begin(), order.end());
        check(!order.empty(), "K1.a preferred_cpu_order is non-empty",
              "n=" + std::to_string(order.size()));
        check(uniq.size() == order.size(), "K1.b preferred_cpu_order has no duplicates");
        bool in_range = true;
        for (int c : order) if (c < 0) in_range = false;
        check(in_range, "K1.c every cpu id is non-negative");
        // Pinning must never throw or abort; it may legitimately refuse.
        const bool pinned = mn::detail::pin_this_thread(order.front());
        check(true, "K1.d pin_this_thread is non-fatal",
              pinned ? "pinned cpu " + std::to_string(order.front())
                     : "refused (cpuset/container) — fallback path exercised");
        std::printf("       hugepages_total=%ld\n", mn::detail::hugepages_total());
        // Undo the pin: the rest of the KAT must be free to use every core.
        for (int c : order) (void)mn::detail::pin_this_thread(c);
    }

    // ---- shared setup: one verifier, one seed -----------------------------
    c2pool::xmr::LightVerifier verifier;
    c2pool::xmr::VerifierOptions vo;   // light, JIT on, no large pages
    if (!verifier.init(vo)) {
        std::printf("  [FAIL] verifier init (OOM?) — cannot check the miner's hashes\n");
        return 1;
    }
    const mn::SeedBytes seed = make_seed(0x5A);
    const c2pool::xmr::SeedHash vseed = to_vseed(seed);
    verifier.prefetch_epoch(vseed, std::nullopt);
    if (!verifier.seed_resident(vseed)) {
        std::printf("  [FAIL] verifier seed not resident after prefetch\n");
        return 1;
    }

    // ---- K2/K3/K4/K5/K6/K7: mine in LIGHT mode ----------------------------
    {
        mn::MinerOptions o;
        o.threads     = 2;            // keep CI memory and CPU modest
        o.fast_mode   = false;        // LIGHT is the default and what CI runs
        o.large_pages = true;         // K5: ask for them; must degrade, not die
        o.pin_threads = true;
        mn::CpuMiner miner(o);

        mn::MinerJob job;
        job.blob           = make_blob();
        job.nonce_offset   = kNonceOffset;
        job.template_id    = 0x1111;
        job.extra_nonce    = 0x2222;
        job.height         = 123456;
        job.seed_hash      = seed;
        job.lane_target    = target_from_diff(64);              // ~64 hashes per hit
        job.network_target = target_from_diff(1ULL << 40);      // effectively never

        std::string why;
        const auto t0 = std::chrono::steady_clock::now();
        const bool ok = miner.set_job(job, &why);
        check(ok, "K5.a miner starts with large_pages requested", ok ? miner.large_pages_note() : why);
        if (!ok) return 1;

        const int want_hits = quick ? 2 : 4;
        std::vector<mn::MinerHit> hits;
        const auto deadline = t0 + std::chrono::seconds(180);
        while (static_cast<int>(hits.size()) < want_hits &&
               std::chrono::steady_clock::now() < deadline) {
            mn::MinerHit h;
            while (miner.pop_hit(h)) hits.push_back(h);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        const double secs = std::chrono::duration<double>(
                                std::chrono::steady_clock::now() - t0).count();
        const mn::MinerStats st = miner.stats();
        std::printf("       %s\n", miner.describe().c_str());
        std::printf("       LIGHT-mode: %llu hashes in %.1fs over %u threads => %.1f H/s "
                    "(%.1f H/s/thread)\n",
                    static_cast<unsigned long long>(st.hashes), secs, st.threads,
                    secs > 0 ? st.hashes / secs : 0.0,
                    (secs > 0 && st.threads) ? st.hashes / secs / st.threads : 0.0);
        std::printf("       %s\n", miner.pinning_note().c_str());

        check(static_cast<int>(hits.size()) >= want_hits,
              "K2.a miner finds lane-target hits",
              "got " + std::to_string(hits.size()) + "/" + std::to_string(want_hits));

        // K2.b/K3: every reported hash is a REAL RandomX hash of the exact blob
        // with the reported nonce, and achieved_target is its top LE word.
        int rehash_ok = 0, target_ok = 0, lane_ok = 0, wrong_tid = 0;
        for (const mn::MinerHit& h : hits) {
            std::vector<std::uint8_t> blob = job.blob;
            for (std::size_t i = 0; i < 4; ++i)
                blob[kNonceOffset + i] = static_cast<std::uint8_t>(h.nonce >> (8 * i));
            std::uint8_t ref[32];
            if (!verifier.hash(blob.data(), blob.size(), vseed, ref)) continue;
            if (std::memcmp(ref, h.pow_hash.data(), 32) == 0) ++rehash_ok;
            if (h.achieved_target == top_word_le(h.pow_hash)) ++target_ok;
            if (h.achieved_target <= job.lane_target) ++lane_ok;
            if (h.template_id != job.template_id || h.extra_nonce != job.extra_nonce)
                ++wrong_tid;
        }
        check(!hits.empty() && rehash_ok == static_cast<int>(hits.size()),
              "K2.b every mined hash re-computes byte-identically in LightVerifier",
              std::to_string(rehash_ok) + "/" + std::to_string(hits.size()));
        check(!hits.empty() && target_ok == static_cast<int>(hits.size()),
              "K3.a achieved_target == top 64-bit LE word of the hash");
        check(!hits.empty() && lane_ok == static_cast<int>(hits.size()),
              "K3.b every reported hit actually clears the lane target");
        check(wrong_tid == 0, "K3.c hits carry the job's (template_id, extra_nonce)");

        check(st.blocks == 0, "K4.a no false network-block hits at difficulty 2^40",
              "blocks=" + std::to_string(st.blocks) + " over " +
                  std::to_string(st.hashes) + " hashes");
        bool any_net = false;
        for (const mn::MinerHit& h : hits) if (h.network) any_net = true;
        check(!any_net, "K4.b no hit is flagged `network` at an impossible target");
        check(st.hashes > 0, "K4.c the negative is not a dead miner (hashes > 0)");

        // ---- K6: a new job displaces the old one --------------------------
        //
        // NOTE ON WHAT IS *NOT* ASSERTED HERE. A worker checks for a job change
        // every 64 hashes and then closes its RandomX pipeline with one final
        // hash of the nonce already loaded, so a hit for the PREVIOUS template
        // can legitimately land in the queue after set_job() returned. That is
        // not staleness to be suppressed: it is real work, it names the
        // template it was done on, and the provider keeps a 6-deep template ring
        // precisely so the node can still submit it. The invariant the node
        // actually depends on — and the one asserted below — is stronger and
        // simpler: EVERY hit verifies against the blob of the template it
        // NAMES, and the new template does take over.
        std::map<std::uint32_t, mn::MinerJob> issued;
        issued[job.template_id] = job;

        mn::MinerJob job2 = job;
        job2.template_id = 0x3333;
        job2.extra_nonce = 0x4444;
        job2.blob[8] ^= 0xFF;   // different work, same seed => no re-key
        std::string why2;
        const bool ok2 = miner.set_job(job2, &why2);
        check(ok2, "K6.a set_job replaces the work in place", ok2 ? "" : why2);
        issued[job2.template_id] = job2;
        { mn::MinerHit h; while (miner.pop_hit(h)) {} }   // drain what job 1 queued

        std::vector<mn::MinerHit> hits2;
        int new_tid = 0;
        const auto d2 = std::chrono::steady_clock::now() + std::chrono::seconds(120);
        while (new_tid < 2 && std::chrono::steady_clock::now() < d2) {
            mn::MinerHit h;
            while (miner.pop_hit(h)) {
                hits2.push_back(h);
                if (h.template_id == job2.template_id) ++new_tid;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        check(new_tid >= 2, "K6.b the new template takes over the workers",
              "new-template hits=" + std::to_string(new_tid) + " of " +
                  std::to_string(hits2.size()) + " total");

        int rehash2 = 0, unknown_tid = 0;
        for (const mn::MinerHit& h : hits2) {
            auto it = issued.find(h.template_id);
            if (it == issued.end()) { ++unknown_tid; continue; }
            std::vector<std::uint8_t> blob = it->second.blob;
            for (std::size_t i = 0; i < 4; ++i)
                blob[kNonceOffset + i] = static_cast<std::uint8_t>(h.nonce >> (8 * i));
            std::uint8_t ref[32];
            if (verifier.hash(blob.data(), blob.size(), vseed, ref) &&
                std::memcmp(ref, h.pow_hash.data(), 32) == 0)
                ++rehash2;
        }
        check(unknown_tid == 0, "K6.c no hit names a template that was never issued");
        check(!hits2.empty() && rehash2 == static_cast<int>(hits2.size()),
              "K6.d every hit verifies against the blob of the template it NAMES",
              std::to_string(rehash2) + "/" + std::to_string(hits2.size()));

        // ---- K7: SELF-CONTAINED FIND at a regtest network difficulty -------
        // The node's exact acceptance rule is meets_difficulty_128(hash, lo, hi)
        // — the SAME predicate O2RandomXVerifier::verify_network_block applies
        // before a block is published. Here the miner's cheap u64 pre-filter
        // proposes, and the node's exact rule disposes, entirely in-process.
        {
            const std::uint64_t regtest_diff = 500;     // monerod --fixed-difficulty class
            mn::MinerJob job3 = job2;
            job3.template_id    = 0x5555;
            job3.extra_nonce    = 0x6666;
            job3.blob[9] ^= 0x5A;
            job3.network_target = target_from_diff(regtest_diff);
            job3.lane_target    = 0;                    // solo: block hits only
            std::string why3;
            check(miner.set_job(job3, &why3), "K7.a miner takes a regtest network job",
                  why3);
            { mn::MinerHit h; while (miner.pop_hit(h)) {} }

            // Only hits that NAME job 3 are this test's subject; a trailing
            // job-2 share may still arrive (see the K6 note) and is ignored.
            std::vector<mn::MinerHit> found;
            const auto d3 = std::chrono::steady_clock::now() + std::chrono::seconds(240);
            while (found.empty() && std::chrono::steady_clock::now() < d3) {
                mn::MinerHit h;
                while (miner.pop_hit(h))
                    if (h.template_id == job3.template_id) found.push_back(h);
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            check(!found.empty(), "K7.b miner finds a NETWORK-target hit",
                  "difficulty=" + std::to_string(regtest_diff) +
                      " n=" + std::to_string(found.size()));
            int net_flag = 0, exact_ok = 0, rehash3 = 0;
            for (const mn::MinerHit& h : found) {
                if (h.network) ++net_flag;
                std::vector<std::uint8_t> blob = job3.blob;
                for (std::size_t i = 0; i < 4; ++i)
                    blob[kNonceOffset + i] = static_cast<std::uint8_t>(h.nonce >> (8 * i));
                std::uint8_t ref[32];
                if (!verifier.hash(blob.data(), blob.size(), vseed, ref)) continue;
                if (std::memcmp(ref, h.pow_hash.data(), 32) == 0) ++rehash3;
                // the node's exact 128-bit gate, difficulty = (lo=regtest_diff, hi=0)
                if (c2pool::xmr::meets_difficulty_128(ref, regtest_diff, 0)) ++exact_ok;
            }
            check(!found.empty() && net_flag == static_cast<int>(found.size()),
                  "K7.c every job-3 hit is flagged `network`");
            check(!found.empty() && rehash3 == static_cast<int>(found.size()),
                  "K7.d the found hash re-computes byte-identically in LightVerifier",
                  std::to_string(rehash3) + "/" + std::to_string(found.size()));
            check(!found.empty() && exact_ok == static_cast<int>(found.size()),
                  "K7.e the found hash passes the node's EXACT 128-bit gate",
                  std::to_string(exact_ok) + "/" + std::to_string(found.size()));
        }

        miner.stop();
        check(!miner.running(), "K6.e stop() joins every worker");
    }

    // ---- K8: verifier re-key racing a miner re-key (SIGFPE regression) -----
    // The crash this reproduces needs both randomx_init_cache() calls to be in
    // flight at once. Both sides now take randomx_init_mutex(), so the loop
    // below simply has to survive; if the lock is removed it dies with SIGFPE
    // inside randomx_reciprocal() (observed 2026-09-17 on a regtest node).
    {
        mn::MinerOptions o;
        o.threads     = 1;
        o.large_pages = false;
        o.pin_threads = false;
        mn::CpuMiner miner(o);

        std::atomic<bool> go{false}, die{false};
        std::atomic<int>  rekeys{0};
        std::thread verifier_thread([&] {
            c2pool::xmr::LightVerifier lv;
            c2pool::xmr::VerifierOptions v2;
            if (!lv.init(v2)) return;
            while (!go.load()) std::this_thread::yield();
            for (int i = 0; i < 4 && !die.load(); ++i) {
                lv.prefetch_epoch(to_vseed(make_seed(static_cast<std::uint8_t>(0x80 + i))),
                                  std::nullopt);
                rekeys.fetch_add(1);
            }
        });

        mn::MinerJob j;
        j.blob         = make_blob();
        j.nonce_offset = kNonceOffset;
        j.template_id  = 0x7777;
        j.lane_target  = target_from_diff(1ULL << 30);   // never fires; we want the re-keys
        bool all_ok = true;
        go.store(true);
        for (int i = 0; i < 4; ++i) {
            j.seed_hash   = make_seed(static_cast<std::uint8_t>(0xC0 + i));
            j.template_id = static_cast<std::uint32_t>(0x7777 + i);
            std::string w;
            if (!miner.set_job(j, &w)) { all_ok = false; std::printf("       set_job: %s\n", w.c_str()); }
        }
        die.store(true);
        verifier_thread.join();
        miner.stop();
        check(all_ok, "K8.a 4 miner re-keys succeed while a verifier re-keys concurrently");
        check(rekeys.load() > 0, "K8.b the verifier side really ran",
              "prefetch_epoch x" + std::to_string(rekeys.load()));
        check(true, "K8.c no SIGFPE — randomx_init_mutex() held the two apart");
    }

    std::printf("== %s ==\n", g_fail ? "FAIL" : "OK");
    return g_fail ? 1 : 0;
}
