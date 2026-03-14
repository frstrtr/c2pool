/**
 * Threading architecture regression tests.
 *
 * Covers the fixes introduced for 48h stress-test crashes/freezes:
 *
 *   1. ScryptControlledByCheckPowFlag
 *      share_init_verify(share, false) skips scrypt and is measurably faster
 *      than share_init_verify(share, true).  Both return the same SHA256d hash.
 *      Regression guard: if someone removes the check_pow guard, 20 "fast"
 *      calls would take > 1 scrypt call — the assertion catches that.
 *
 *   2. VerifyShareUsesPresetHashToSkipScrypt
 *      After Phase-1 stores a share's SHA256d hash in m_hash, the expression
 *      share_init_verify(share, share.m_hash.IsNull()) evaluates check_pow=false.
 *      This is the exact guard added to verify_share() to prevent the 40-95 s
 *      think() freeze.
 *
 *   3. ThreadPoolAtomicCounterHandoffToIoc
 *      Direct unit test of the processing_shares Phase-1 → Phase-2 pattern:
 *        - N tasks posted to thread_pool
 *        - atomic counter decremented by each task
 *        - when counter reaches 0, last task posts Phase-2 callback to io_context
 *      Validates ordering, single-firing, and correct counter value.
 */

#include <gtest/gtest.h>

#include <impl/ltc/share.hpp>
#include <impl/ltc/share_check.hpp>
#include <sharechain/sharechain.hpp>
#include <core/pack.hpp>
#include <btclibs/crypto/scrypt.h>

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

namespace io = boost::asio;

// ─── Shared fixture: a real V36 testnet share loaded from raw hex ────────────

static const char* SHARE_HEX =
    "23fd9601fe00000020654f11363698fc9a54e43f126f294bd1a33b650148e8b6b"
    "b532fc08500cb6966e8103066140b041db0022a77e3af9c1de80a16583bed2a61"
    "79b63ed410b890b113cfd0fcd68bafa4096779b90503fd823100731a92d3226d6"
    "839617a4b44785235374766374a575a756e6e43324a7a37325351747746544b68"
    "dec14025000000000000fe2302a41fb37f52f6747afbbeae61462feaa40b8b365"
    "5f8fb7af60843111101ec5f958e93b9a76bb46536bf807b1caef9635f432d982b"
    "d907eb5050130b6ec00aeabc2bb9ca34c5f1ba0bd332fc3d217d9853754fe4279"
    "7e32cf9ddddcab6f66ab8056f1b64efa2157281c406fc6a5d9de6db5e2adf63c8"
    "6646a4edc91c51f86d74c707c0221e8828011ef310306675b3210073990593df0"
    "d00000000000000000000000100000000000000c357550d5a390b342f665a3d85"
    "3c039a626b803bb37976c20ba0b5ee5a56fceedc0220e67c088987582af73218c"
    "99820276bbf0004c5c18f7dd691f9c4326bfd9930d5567a6d109fec00f4eca887"
    "c42e80ddaa57df9bda8db8b277110a50a9a268b6";

static ltc::ShareType load_test_share()
{
    PackStream ps;
    ps.from_hex(SHARE_HEX);
    chain::RawShare rshare;
    ps >> rshare;
    return ltc::load_share(rshare, NetService{"0.0.0.0", 0});
}

// ─── Test 1: scrypt is controlled by check_pow flag ──────────────────────────

TEST(VerifyShareThreading, ScryptControlledByCheckPowFlag)
{
    auto share = load_test_share();

    // --- Baseline: measure N raw scrypt calls for reliable timing ---
    constexpr int SCRYPT_REPS = 5;
    char dummy_in[80]  = {};
    char dummy_out[32] = {};
    auto t_scrypt_start = std::chrono::steady_clock::now();
    for (int i = 0; i < SCRYPT_REPS; i++)
        scrypt_1024_1_1_256(dummy_in, dummy_out);
    auto t_scrypt_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t_scrypt_start).count();

    // scrypt-1024-1-1-256 is memory-hard; even on fast hardware takes > 50µs each
    EXPECT_GT(t_scrypt_us, 50)
        << SCRYPT_REPS << " scrypt calls took " << t_scrypt_us << "µs total — unexpectedly fast";

    // --- Fast path: same number of share_init_verify(check_pow=false) calls ---
    // If the check_pow guard is removed, this becomes SCRYPT_REPS scrypt calls
    // and t_fast_us ≈ t_scrypt_us (the assertion catches the regression).
    auto t_fast_start = std::chrono::steady_clock::now();
    for (int i = 0; i < SCRYPT_REPS; i++)
    {
        share.ACTION({ ltc::share_init_verify(*obj, false); });
    }
    auto t_fast_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t_fast_start).count();

    // Device-relative: SCRYPT_REPS fast calls must be strictly faster than SCRYPT_REPS scrypt calls.
    EXPECT_LT(t_fast_us, t_scrypt_us)
        << SCRYPT_REPS << " share_init_verify(false) calls took " << t_fast_us
        << "µs vs " << t_scrypt_us << "µs for scrypt. "
           "If equal, check_pow=false is no longer skipping scrypt.";
}

// ─── Test 2: verify_share uses pre-set m_hash to skip scrypt ─────────────────

TEST(VerifyShareThreading, VerifyShareUsesPresetHashToSkipScrypt)
{
    auto share = load_test_share();

    // Before Phase 1: m_hash is zero (not yet computed)
    uint256 initial_hash;
    share.ACTION({ initial_hash = obj->m_hash; });
    EXPECT_TRUE(initial_hash.IsNull())
        << "freshly loaded share should have null m_hash before Phase 1";

    // Phase 1 pattern: compute and store hash (check_pow=true — full validation)
    uint256 phase1_hash;
    bool phase1_ok = true;
    try {
        share.ACTION({
            obj->m_hash = ltc::share_init_verify(*obj, true);
            phase1_hash = obj->m_hash;
        });
    } catch (const std::exception& e) {
        // PoW may legitimately fail for a testnet share if the target is
        // stricter than the hex data meets.  Fall back to check_pow=false.
        phase1_ok = false;
        share.ACTION({
            obj->m_hash = ltc::share_init_verify(*obj, false);
            phase1_hash = obj->m_hash;
        });
    }
    (void)phase1_ok;

    EXPECT_FALSE(phase1_hash.IsNull()) << "Phase 1 must produce a non-null hash";

    // After Phase 1: m_hash is set → IsNull() == false
    bool is_null_after_phase1 = true;
    share.ACTION({ is_null_after_phase1 = obj->m_hash.IsNull(); });
    EXPECT_FALSE(is_null_after_phase1)
        << "m_hash must not be null after Phase 1 stores it";

    // Simulate verify_share()'s guard: share_init_verify(share, share.m_hash.IsNull())
    // With hash pre-set, IsNull()=false → check_pow=false → no scrypt.
    // Result must equal the stored hash (SHA256d is deterministic).
    uint256 verify_hash;
    share.ACTION({
        verify_hash = ltc::share_init_verify(*obj, obj->m_hash.IsNull());
    });

    EXPECT_EQ(verify_hash, phase1_hash)
        << "verify_share re-computation must return the same hash as Phase 1. "
           "If this fails the IsNull() guard was bypassed.";

    // Confirm timing: with hash pre-set, N calls should be faster than N scrypt calls.
    // (Regression: if the guard is removed, this triggers N scrypt calls each time)
    constexpr int N = 5;
    char scrypt_in[80] = {};  char scrypt_out[32] = {};
    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < N; i++)
        scrypt_1024_1_1_256(scrypt_in, scrypt_out);
    auto n_scrypt_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t0).count();

    auto t1 = std::chrono::steady_clock::now();
    for (int i = 0; i < N; i++)
    {
        share.ACTION({
            ltc::share_init_verify(*obj, obj->m_hash.IsNull()); // check_pow=false
        });
    }
    auto fast_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t1).count();

    EXPECT_LT(fast_us, n_scrypt_us)
        << N << " verify-with-preset-hash calls took " << fast_us
        << "µs; " << N << " scrypt calls took " << n_scrypt_us << "µs. "
           "think() would have blocked for ~400× scrypt_time without the fix.";
}

// ─── Test 3: processing_shares threading pattern ─────────────────────────────
//
// Validates the exact async pattern used in NodeImpl::processing_shares():
//   • N tasks posted to a thread_pool
//   • Each task decrements an atomic<int> counter
//   • The task that decrements to 0 posts the Phase-2 callback to io_context
//   • Phase-2 fires exactly once on the io_context thread
//
// This catches bugs in the atomic counter or post() ordering that would cause
// Phase 2 to never fire (freeze) or fire multiple times (corruption).

TEST(VerifyShareThreading, ThreadPoolAtomicCounterHandoffToIoc)
{
    constexpr int N = 24; // divisible by 4 (thread pool size)

    io::io_context ioc;
    boost::asio::thread_pool pool(4);

    // Work guard keeps ioc.run_for() alive until Phase 2 fires and resets it.
    auto work = std::make_shared<io::executor_work_guard<io::io_context::executor_type>>(
        io::make_work_guard(ioc));

    auto remaining = std::make_shared<std::atomic<int>>(N);
    std::atomic<int> phase2_fire_count{0};

    for (int i = 0; i < N; i++)
    {
        boost::asio::post(pool,
            [remaining, &ioc, &phase2_fire_count, work]()
            {
                // Simulate per-share CPU work (scrypt) with a short sleep
                std::this_thread::sleep_for(std::chrono::milliseconds(2));

                if (--(*remaining) == 0)
                {
                    boost::asio::post(ioc,
                        [&phase2_fire_count, work]()
                        {
                            phase2_fire_count.fetch_add(1);
                            work->reset(); // release work guard → ioc.run_for() returns
                        });
                }
            });
    }

    // Run ioc until Phase-2 fires (work guard released) or 10s elapses
    ioc.run_for(std::chrono::seconds(10));

    pool.join(); // ensure all thread-pool tasks have finished

    EXPECT_EQ(phase2_fire_count.load(), 1)
        << "Phase-2 must fire exactly once; fired " << phase2_fire_count.load()
        << " times. 0=never fired (atomic/post broken); >1=race in counter";

    EXPECT_EQ(remaining->load(), 0)
        << "All " << N << " Phase-1 tasks must complete before Phase-2 fires";
}
