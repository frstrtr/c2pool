// Boost header-integrity + version gate.
//
// Compiles ONE TU that exercises the four exact subsystems whose torn-header
// signatures surfaced the Boost 1.90.0 / GCC-13 CI flakes, and static_asserts
// the resolved Boost is 1.90.0 (catches a stray apt Boost 1.83 filling holes
// via include-path fallback). Green here == intact single-version tree, right
// version resolved, compiled archives link. See ci-boost-stream.md ss.D.
//
// FORWARD-TRIPWIRE GUARD (ci-steward 2026-07-31): the full body below is a
// forward gate for the pending fleet Boost 1.90.0 bump. Its newer includes
// (boost/asio/cancel_after.hpp, added in Boost 1.86) and its static_assert
// require Boost >= 1.90.0. The live fleet/prod toolchain is Boost 1.83, so
// compiling the full body hard-reds EVERY build PR Linux-x86_64 leg regardless
// of the diff. Until the operator-gated fleet Boost>=1.90 bump lands (a
// prod-touch: VM110 links libsecp256k1 .so.1), the sentinel stays DORMANT on
// <1.90 hosts and auto-arms the instant the tree reaches 1.90.0.
#include <boost/version.hpp>
#include <cstdio>

#if BOOST_VERSION >= 109000
static_assert(BOOST_VERSION == 109000, "wrong Boost tree resolved: expected 1.90.0");

#include <boost/asio/cancel_after.hpp>   // pulls detail/timed_cancel_op.hpp (stage-1 casualty)
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/severity_logger.hpp>  // A.1 site (BOOST_PP expansion)
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/console.hpp>

#include <boost/signals2/signal.hpp>               // A.2 site (slot_template.hpp)

#include <boost/fusion/adapted/std_pair.hpp>
#include <boost/spirit/home/x3.hpp>                // A.3 site (operator/detail/sequence.hpp)

#include <chrono>
#include <memory>
#include <string>
#include <utility>

int main()
{
    // asio: timed cancellation machinery
    boost::asio::io_context io;
    boost::asio::steady_timer timer(io, std::chrono::milliseconds(100));
    bool aborted = false;
    timer.async_wait(boost::asio::cancel_after(
        std::chrono::milliseconds(10),
        [&](boost::system::error_code ec) { aborted = (ec == boost::asio::error::operation_aborted); }));
    io.run();
    if (!aborted) { std::puts("FAIL asio"); return 1; }

    // log: severity_logger (header) + libboost_log / log_setup (link check)
    boost::log::add_console_log();
    boost::log::sources::severity_logger<boost::log::trivial::severity_level> lg;
    BOOST_LOG_SEV(lg, boost::log::trivial::info) << "sentinel: log ok";

    // signals2: std::shared_ptr tracking -> the exact foreign_void_weak_ptr push_back path
    using sig_t = boost::signals2::signal<int(int)>;
    sig_t sig;
    auto tracked = std::make_shared<int>(1);
    sig.connect(sig_t::slot_type([&](int x) { return x + *tracked; }).track_foreign(tracked));
    if (sig(41).value_or(0) != 42) { std::puts("FAIL signals2"); return 1; }

    // spirit.x3: sequence operator -> partition_attribute static_asserts
    namespace x3 = boost::spirit::x3;
    std::pair<int, int> out{};
    std::string const in = "12,34";
    auto it = in.begin();
    if (!x3::parse(it, in.end(), x3::int_ >> ',' >> x3::int_, out)
        || it != in.end() || out.first != 12 || out.second != 34) {
        std::puts("FAIL spirit.x3"); return 1;
    }

    std::puts("boost_sentinel: asio+log+signals2+spirit.x3 OK");
    return 0;
}
#else
int main()
{
    // Fleet Boost < 1.90.0: forward tripwire inactive. Compiles green with no
    // newer-Boost headers or link deps so the required Linux-x86_64 leg passes
    // on the current 1.83 toolchain. Auto-arms once the fleet reaches 1.90.0.
    std::printf("boost_sentinel: DORMANT (Boost %d < 1.90.0 target) -- "
                "forward tripwire inactive until fleet Boost>=1.90 bump lands\n",
                BOOST_VERSION);
    return 0;
}
#endif
