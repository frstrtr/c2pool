// Provide boost::throw_exception implementation for Boost 1.90+ on MSVC.
// Boost 1.90 declares throw_exception in a header but the compiled library
// may not be available in all package manager configurations (Conan/vcpkg).
// This shim ensures the symbol is always resolvable.
#include <boost/version.hpp>
#if BOOST_VERSION >= 109000
#include <boost/config.hpp>
#include <boost/throw_exception.hpp>
#include <boost/exception/exception.hpp>

#if !defined(BOOST_NO_EXCEPTIONS)
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
#endif
