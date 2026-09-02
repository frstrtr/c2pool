// SPDX-License-Identifier: MIT
// Shared export marker for the pure-C entry points of the HIDDEN-VISIBILITY
// dash_scriptcheck shared object. Included by BOTH c2pool_scriptcheck.h (the
// extern "C" DECLARATIONS) and c2pool_scriptcheck.cpp (the DEFINITIONS) so the
// declaration and the definition carry IDENTICAL linkage. MSVC emits C2375
// ("redefinition; different linkage") when a dllexport definition was declared
// without the same dllexport; GCC/Clang tolerate an attribute on the def alone,
// but decl+def agreement is required for MSVC and harmless everywhere.
//
// On GCC/Clang the marker is __attribute__((visibility("default"))): the
// dash_scriptcheck library builds with -fvisibility=hidden so every
// bitcoin-derived symbol is hidden (never ODR-collides with c2pool's own
// btclibs at the final c2pool-dash link), and this attribute re-exports exactly
// the c2pool_dash_* entry points. On MSVC the equivalent is __declspec(
// dllexport) on those same entry points. Neither token is defined on Linux, so
// this reduces to the visibility attribute there — byte-identical to before.
#ifndef C2POOL_DASH_SCRIPT_EXPORT_H
#define C2POOL_DASH_SCRIPT_EXPORT_H

#if defined(_MSC_VER)
#  define C2POOL_DASH_SCRIPT_EXPORT __declspec(dllexport)
#else
#  define C2POOL_DASH_SCRIPT_EXPORT __attribute__((visibility("default")))
#endif

#endif // C2POOL_DASH_SCRIPT_EXPORT_H
