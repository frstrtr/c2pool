// Probe TU for v37_xmr_boost_origin_kat: compiled in an OBJECT library that
// links conan's Boost::headers, i.e. exactly like every Boost-using c2pool TU.
#include <boost/version.hpp>

long v37_xmr_boost_origin_probe_version() { return static_cast<long>(BOOST_VERSION); }

int v37_xmr_boost_origin_probe_shim()
{
#if defined(BOOST_ASIO_DETAIL_HANDLER_INVOKE_HELPERS_HPP) && BOOST_VERSION >= 108400
    int hits = 0;
    auto f = [&hits] { ++hits; };
    int ctx = 0;
    boost_asio_handler_invoke_helpers::invoke(f, ctx);
    return hits == 1 ? 1 : -1;
#else
    return 0;
#endif
}
