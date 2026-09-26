// v37_xmr_boost_origin_kat -- build-hygiene KAT: every C++ TU sees the pinned
// (conan) Boost, never a host/system Boost, and never "no Boost" by accident.
//
// The top-level CMakeLists.txt force-includes core/boost_asio_compat.hpp into
// every C++ TU, and that shim starts with #include <boost/version.hpp>. THIS TU
// deliberately belongs to a target that links NO Boost (like the vendored
// randomx and xmr_node's monero_rpc.cpp), so the only way it can see
// <boost/version.hpp> is through the include dir the top level pairs with the
// force-include. It compares three Boost versions:
//   A  BOOST_VERSION as seen HERE (no Boost link; forced include only)
//   B  BOOST_VERSION as seen by a TU that links conan's Boost::headers
//      (v37_xmr_boost_origin_probe.cpp, an OBJECT library)
//   C  the Boost version CMake's find_package(Boost) resolved (conan's)
// A == B == C, and the compat shim must be active here exactly as it is in
// the Boost-linked TUs.
//
// Before the fix: on a host with NO system Boost this TU does not compile
// ("boost/version.hpp: No such file or directory"); on a host WITH a system
// Boost (vm905: apt 1.83 next to conan 1.90) A = 1.83 != B = C = 1.90 and the
// run fails. No sockets, no daemon, no RandomX, no consensus code.
#include <cstdio>
#include <cstring>
#include <string>

#ifndef C2POOL_EXPECT_BOOST_VERSION_STRING
#error "C2POOL_EXPECT_BOOST_VERSION_STRING must be set by CMake"
#endif

#if !defined(BOOST_VERSION)
#define V37_XMR_BOOST_ORIGIN_A 0L
#else
#define V37_XMR_BOOST_ORIGIN_A static_cast<long>(BOOST_VERSION)
#endif

long v37_xmr_boost_origin_probe_version();   // B (Boost::headers TU)
int  v37_xmr_boost_origin_probe_shim();      // shim active in the B TU

static std::string fmt(long v)
{
    char b[32];
    std::snprintf(b, sizeof b, "%ld.%ld.%ld", v / 100000, v / 100 % 1000, v % 100);
    return b;
}

static int shim_here()
{
#if defined(BOOST_ASIO_DETAIL_HANDLER_INVOKE_HELPERS_HPP) && defined(BOOST_VERSION) && BOOST_VERSION >= 108400
    // Exercise the shim's hook-free invoke: copy the function, call the copy.
    int hits = 0;
    auto f = [&hits] { ++hits; };
    int ctx = 0;
    boost_asio_handler_invoke_helpers::invoke(f, ctx);
    return hits == 1 ? 1 : -1;
#else
    return 0;
#endif
}

int main()
{
    const long a = V37_XMR_BOOST_ORIGIN_A;
    const long b = v37_xmr_boost_origin_probe_version();
    const std::string c = C2POOL_EXPECT_BOOST_VERSION_STRING;
    const int sa = shim_here();
    const int sb = v37_xmr_boost_origin_probe_shim();

    std::printf("A no-Boost-link TU     BOOST_VERSION=%ld (%s)\n", a, fmt(a).c_str());
    std::printf("B Boost::headers TU    BOOST_VERSION=%ld (%s)\n", b, fmt(b).c_str());
    std::printf("C find_package(Boost)  version=%s\n", c.c_str());
    std::printf("shim active: A=%d B=%d\n", sa, sb);

    int fails = 0;
    if (a == 0)            { std::printf("FAIL: no-Boost-link TU saw no Boost at all\n"); ++fails; }
    if (a != b)            { std::printf("FAIL: MIXED BOOST: no-Boost-link TU %s != Boost::headers TU %s\n", fmt(a).c_str(), fmt(b).c_str()); ++fails; }
    if (fmt(b) != c)       { std::printf("FAIL: Boost::headers TU %s != find_package(Boost) %s\n", fmt(b).c_str(), c.c_str()); ++fails; }
    if (sa != sb || sa < 0){ std::printf("FAIL: compat shim differs: A=%d B=%d\n", sa, sb); ++fails; }

    std::printf("%s (%d failure%s)\n", fails ? "v37_xmr_boost_origin_kat FAILED" : "v37_xmr_boost_origin_kat PASSED",
                fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
