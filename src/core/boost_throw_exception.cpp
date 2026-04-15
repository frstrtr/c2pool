// Provide boost::throw_exception for Boost 1.90+ on MSVC.
//
// Boost 1.90's throw_exception.hpp declares non-template overloads
// when BOOST_NO_EXCEPTIONS is defined, but provides only template
// overloads otherwise. MSVC's Conan-built Boost libraries reference
// the non-template symbols, creating unresolved externals.
//
// This is NOT a band-aid — Boost's exception component is header-only
// in Conan and provides no compiled library. This file IS the compiled
// implementation, equivalent to what a hypothetical libboost_exception
// would contain.

#include <boost/version.hpp>
#if BOOST_VERSION >= 109000

#include <boost/config.hpp>
#include <boost/throw_exception.hpp>

namespace boost {

BOOST_NORETURN void throw_exception(std::exception const& e) {
    throw e;
}

BOOST_NORETURN void throw_exception(std::exception const& e,
                                     boost::source_location const&) {
    throw e;
}

} // namespace boost

#endif // BOOST_VERSION >= 109000
