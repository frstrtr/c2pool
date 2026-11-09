// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// One binary, one BLS mode. bls_verify.hpp and bls_canonical.hpp define
/// inline functions whose bodies depend on C2POOL_DASH_BLS (the dashbls
/// backend or a fail-closed stub), and so does everything inlined over them
/// (protx_core_refusal, build_embedded_workdata, ...). A binary whose
/// translation units disagree on the macro holds two definitions of each:
/// an ODR violation, and the linker keeps either one (a stub that refuses
/// every version-3 provider payload, on some toolchains). The build gives
/// every DASH target the macro through dash_bls_verify's PUBLIC usage
/// requirements (src/impl/dash/CMakeLists.txt); this guard makes a mixed
/// binary visible at run time: every translation unit that includes these
/// headers records its mode during static initialisation, and
/// bls_mode_mixed() reports a binary that saw both. c2pool-dash refuses to
/// start with a mixed binary; KATs assert the mode of their own binaries.

#include <atomic>

namespace dash {
namespace coin {
namespace vendor {

inline constexpr unsigned kBlsModeStub = 1u;
inline constexpr unsigned kBlsModeBackend = 2u;

inline std::atomic<unsigned>& bls_modes_seen()
{
    static std::atomic<unsigned> seen{0};
    return seen;
}
inline bool bls_mode_note(unsigned mode)
{
    bls_modes_seen().fetch_or(mode);
    return true;
}
/// Both modes were compiled into this binary.
inline bool bls_mode_mixed()
{
    return bls_modes_seen().load() == (kBlsModeStub | kBlsModeBackend);
}
/// The modes this binary's translation units were compiled with.
inline unsigned bls_modes() { return bls_modes_seen().load(); }

} // namespace vendor
} // namespace coin
} // namespace dash

namespace {
#ifdef C2POOL_DASH_BLS
[[maybe_unused]] const bool c2pool_dash_bls_mode_noted =
    ::dash::coin::vendor::bls_mode_note(::dash::coin::vendor::kBlsModeBackend);
#else
[[maybe_unused]] const bool c2pool_dash_bls_mode_noted =
    ::dash::coin::vendor::bls_mode_note(::dash::coin::vendor::kBlsModeStub);
#endif
}  // namespace
