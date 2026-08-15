// #1133 — dash teardown-order guard: the NodeImpl compute pools (m_verify_pool
// X11 verify + m_think_pool run_think/clean) must be JOINED before the members
// their tasks touch — m_tracker_mutex, the m_think_running / m_clean_running /
// m_rethink_pending atomics, the tracker + snapshot — are destroyed, AND before
// the main_dash-owned objects (web_server / oracle_shadow / stratum_server) a
// task's callback can reach are unwound.
//
// On master the pools are declared BEFORE m_tracker_mutex (node.hpp), so
// reverse-order member destruction tears the mutex down while ~thread_pool is
// still joining a lock-holding think task — destroying a std::shared_mutex
// another thread may lock is UB. And ~Node (p2p_node declared first in
// main_dash) runs LAST, after web_server/oracle_shadow already died.
//
// The fix: NodeImpl::join_compute_pools() (stop()+join() both pools) called
// explicitly right after ioc.run() returns in main_dash, and again from the
// ~NodeImpl BODY (which runs before ANY member is destroyed) as a
// declaration-order-independent belt-and-suspenders.
//
// Two lenses, both fold into the EXISTING allowlisted test_dash_node target:
//   1. RUNTIME — construct a real NodeImpl, post in-flight verify+think tasks
//      that hammer the exclusive m_tracker_mutex, then drive the shutdown join
//      and let the object destruct. Proves the join drains in-flight tasks and
//      the destructor is safe. Under ASan/TSAN the master ordering faults here.
//   2. SOURCE-STRUCTURAL — a true UB repro is nondeterministic, so (mirroring
//      the dgb RACE913 guard) parse the shipped node.hpp + main_dash.cpp and
//      assert the join sites are present in the right places. Revert the fix ->
//      RED; restore -> GREEN.

#include <gtest/gtest.h>

#include <impl/dash/node.hpp>

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>

using namespace std::chrono_literals;

namespace {

// Test-only subclass exposing the protected compute pools + think atomics so the
// KAT can post the exact task shape a real think()/verify cycle runs, then drive
// the public shutdown entrypoint. tracker_mutex() is already public on NodeImpl.
class ShutdownProbeNode : public dash::NodeImpl
{
public:
    using dash::NodeImpl::NodeImpl;  // rig-free default ctor
    boost::asio::thread_pool& verify_pool() { return m_verify_pool; }
    boost::asio::thread_pool& think_pool()  { return m_think_pool; }
    // Touch the same atomics the real run_think()/clean cycle mutates under the
    // exclusive lock — they are declared AFTER the pools too, so they share the
    // teardown hazard the join closes.
    void touch_think_atomics()
    {
        m_think_running.store(true, std::memory_order_relaxed);
        m_rethink_pending.store(false, std::memory_order_relaxed);
        m_clean_running.store(false, std::memory_order_relaxed);
        m_think_running.store(false, std::memory_order_relaxed);
    }
};

} // namespace

// ── Lens 1: runtime shutdown with in-flight tasks ───────────────────────────

// join_compute_pools() must drain a think task that is actively holding the
// exclusive tracker mutex, so that when the object destructs nothing touches the
// (about-to-be-destroyed) mutex/atomics. Deadlock/crash => the pipeline is
// broken; clean return + destruct => the join contract holds.
TEST(DashShutdownOrder, JoinDrainsInflightTrackerTask)
{
    std::atomic<int> think_iters{0};
    std::atomic<int> verify_iters{0};
    std::atomic<bool> keep_going{true};

    {
        ShutdownProbeNode node;

        // A think-cycle stand-in: repeatedly take the EXCLUSIVE tracker lock and
        // touch the think atomics, exactly the members destroyed before the pool
        // join on master. It sleeps briefly WITHOUT the lock so the verify
        // readers below get windows too (glibc's shared_mutex can starve an
        // exclusive writer under a continuous reader flood — a fairness quirk we
        // deliberately avoid so the KAT exercises SHUTDOWN, not lock fairness).
        boost::asio::post(node.think_pool(), [&]() {
            while (keep_going.load(std::memory_order_acquire)) {
                {
                    std::unique_lock<std::shared_mutex> lk(node.tracker_mutex());
                    node.touch_think_atomics();
                    think_iters.fetch_add(1, std::memory_order_relaxed);
                }
                std::this_thread::sleep_for(1ms);
            }
        });

        // Verify-pool stand-ins: shared try-locks like attempt_verify's IO-side
        // helpers, momentary hold, then a gap without the lock (leaves room for
        // the exclusive writer above), on the 4 verify threads.
        for (int i = 0; i < 4; ++i) {
            boost::asio::post(node.verify_pool(), [&]() {
                while (keep_going.load(std::memory_order_acquire)) {
                    {
                        std::shared_lock<std::shared_mutex> lk(node.tracker_mutex(),
                                                               std::try_to_lock);
                        verify_iters.fetch_add(1, std::memory_order_relaxed);
                    }
                    std::this_thread::sleep_for(2ms);
                }
            });
        }

        // Deterministically wait (bounded) until BOTH task classes are provably
        // in flight before we begin teardown — no fixed sleep to race.
        const auto deadline = std::chrono::steady_clock::now() + 3s;
        while ((think_iters.load() == 0 || verify_iters.load() == 0)
               && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(1ms);
        }
        EXPECT_GT(think_iters.load(), 0) << "think task never ran";
        EXPECT_GT(verify_iters.load(), 0) << "verify tasks never ran";

        // Begin shutdown: signal the loops to end, then DRAIN via the fix's
        // entrypoint. After this returns, no pool thread is running.
        keep_going.store(false, std::memory_order_release);
        node.join_compute_pools();

        // Idempotency: the main_dash explicit call + the ~NodeImpl body call must
        // both be able to run. A second join is a safe no-op on joined pools.
        node.join_compute_pools();

        // node destructs HERE: ~NodeImpl joins once more (no-op) BEFORE
        // m_tracker_mutex / the atomics are destroyed. No task is in flight, so
        // the teardown touches nothing live-then-dead.
    }

    SUCCEED();
}

// ── Lens 2: source-structural guards (deterministic red/green) ──────────────

#ifndef DASH_NODE_HPP_SRC
#error "DASH_NODE_HPP_SRC must be defined by CMake to src/impl/dash/node.hpp"
#endif
#ifndef DASH_MAIN_SRC
#error "DASH_MAIN_SRC must be defined by CMake to src/c2pool/main_dash.cpp"
#endif

namespace {

std::string slurp(const char* path)
{
    std::ifstream in(path);
    EXPECT_TRUE(in.good()) << "cannot open " << path;
    std::stringstream ss; ss << in.rdbuf();
    return ss.str();
}

} // namespace

// node.hpp must declare an explicit ~NodeImpl that joins the pools first, and a
// join_compute_pools() that stops+joins BOTH pools.
TEST(DashShutdownOrder, NodeHppDeclaresJoinFirstDestructor)
{
    const std::string src = slurp(DASH_NODE_HPP_SRC);

    ASSERT_NE(src.find("void join_compute_pools()"), std::string::npos)
        << "join_compute_pools() shutdown entrypoint missing from node.hpp";

    const auto jstart = src.find("void join_compute_pools()");
    const auto jend = src.find('}', jstart);
    ASSERT_NE(jend, std::string::npos);
    const std::string jbody = src.substr(jstart, jend - jstart);
    EXPECT_NE(jbody.find("m_verify_pool.join()"), std::string::npos)
        << "join_compute_pools() must join m_verify_pool";
    EXPECT_NE(jbody.find("m_think_pool.join()"), std::string::npos)
        << "join_compute_pools() must join m_think_pool";

    // Explicit destructor whose body joins the pools before any member dies.
    const auto dstart = src.find("~NodeImpl()");
    ASSERT_NE(dstart, std::string::npos)
        << "explicit ~NodeImpl() missing — member reverse-destruction would tear "
           "down m_tracker_mutex while ~thread_pool still joins m_think_pool";
    const auto dend = src.find('}', dstart);
    ASSERT_NE(dend, std::string::npos);
    EXPECT_NE(src.substr(dstart, dend - dstart).find("join_compute_pools()"),
              std::string::npos)
        << "~NodeImpl() must join the compute pools in its body (runs before any "
           "member is destroyed)";
}

// main_dash must join the node's pools after ioc.run() returns and BEFORE the
// objects a verify/think task can reach (stratum_server/oracle_shadow/web_server)
// are torn down.
TEST(DashShutdownOrder, MainDashJoinsNodePoolsBeforeExternalTeardown)
{
    const std::string src = slurp(DASH_MAIN_SRC);

    const auto join_at = src.find("p2p_node.join_compute_pools()");
    ASSERT_NE(join_at, std::string::npos)
        << "main_dash must explicitly join the node compute pools after ioc.run()";

    // Ordering: the join must sit after the run loop and before the external
    // objects unwind.
    const auto run_at = src.rfind("ioc.run()", join_at);
    ASSERT_NE(run_at, std::string::npos);
    EXPECT_LT(run_at, join_at) << "join must come AFTER ioc.run() returns";

    for (const char* later : {"stratum_server.reset()",
                              "oracle_shadow.reset()",
                              "web_server.reset()",
                              "shutdown_persistence()"}) {
        const auto pos = src.find(later, join_at);
        EXPECT_NE(pos, std::string::npos)
            << "expected teardown of '" << later << "' to follow the pool join";
        EXPECT_LT(join_at, pos)
            << "node pools must be joined BEFORE '" << later
            << "' unwinds (a task's callback can still reach it)";
    }
}
