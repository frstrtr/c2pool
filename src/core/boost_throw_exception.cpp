// Compiled implementation of boost::throw_exception for Boost 1.90+.
//
// Boost's throw_exception.hpp declares non-template overloads:
//   void throw_exception(std::exception const&);
//   void throw_exception(std::exception const&, source_location const&);
// but no Boost compiled library provides the definition — not even
// libboost_exception (which only has clone_current_exception).
// The user is expected to provide these when not using BOOST_NO_EXCEPTIONS
// in header-only mode. On GCC/Clang, the template overloads in the header
// satisfy all call sites. On MSVC, the non-template symbols are referenced
// by pre-compiled Boost libraries (log, thread, filesystem), requiring
// this compiled definition.

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

#endif
