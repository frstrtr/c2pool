#pragma once
//
// core/boost_asio_compat.hpp
//
// Build-only compatibility shim for Boost.Asio's removed
// boost_asio_handler_invoke_helpers namespace. This is NOT a behaviour change.
//
// c2pool pins Boost via conan (currently 1.90), which deleted
// boost/asio/detail/handler_invoke_helpers.hpp together with the
// boost_asio_handler_invoke_helpers namespace (the asio_handler_invoke hooks
// were deprecated in Boost 1.79 and dropped thereafter). On build hosts that
// also carry a legacy *system* Boost (e.g. libboost-dev 1.83 under
// /usr/include), that older tree's boost/asio/impl/system_executor.hpp can
// leak onto the include path and still calls
//     boost_asio_handler_invoke_helpers::invoke(f, f);
// yielding "'boost_asio_handler_invoke_helpers' has not been declared" when
// the conan (>= 1.90) headers no longer provide it.
//
// This header supplies that namespace's historical *default* (hook-free)
// invoke so the leaked impl resolves. The body mirrors Boost's own
// BOOST_ASIO_HAS_HANDLER_HOOKS-disabled path (copy the function, then call
// it), which is identical to how Boost >= 1.90 dispatches internally. c2pool
// defines no asio_handler_invoke overloads, so behaviour is unchanged.
//
// It is force-included ahead of every C++ translation unit (see the top-level
// CMakeLists.txt) so all five coins keep building regardless of ccache
// eviction. Guarded so it stays inert on any Boost that still ships the
// namespace itself.
//
#include <boost/version.hpp>

#if BOOST_VERSION >= 108400
// Claim Boost's own include guard so that, if the real (legacy) header is
// reached later in the same TU, it becomes a no-op instead of a redefinition.
#ifndef BOOST_ASIO_DETAIL_HANDLER_INVOKE_HELPERS_HPP
#define BOOST_ASIO_DETAIL_HANDLER_INVOKE_HELPERS_HPP

namespace boost_asio_handler_invoke_helpers {

template <typename Function, typename Context>
inline void invoke(Function& function, Context& /*context*/)
{
  Function tmp(function);
  tmp();
}

template <typename Function, typename Context>
inline void invoke(const Function& function, Context& /*context*/)
{
  Function tmp(function);
  tmp();
}

} // namespace boost_asio_handler_invoke_helpers

#endif // BOOST_ASIO_DETAIL_HANDLER_INVOKE_HELPERS_HPP
#endif // BOOST_VERSION >= 108400
