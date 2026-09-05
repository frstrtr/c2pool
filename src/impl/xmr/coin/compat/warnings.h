// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// compat/warnings.h  --  boost-free stand-in for monero-project's
// contrib/epee/include/warnings.h
//
// AUTHORED for c2pool (not ported). The vendored monero crypto C files
// (crypto-ops.c, hash-ops.h) #include "warnings.h" for compiler-diagnostic
// macros. Upstream's epee header pulls <boost/preprocessor/stringize.hpp> just
// to build the -W pragma string; the vendored primitives otherwise need no
// boost. This shim supplies the same macro surface with no boost dependency:
// PUSH/POP emit real GCC/Clang diagnostic pragmas; the per-warning suppressors
// are no-ops (the vendored code compiles warning-clean on modern GCC/Clang, so
// suppressing nothing is safe). Placed on the include path via -Icompat so the
// vendored files are used byte-for-byte, unmodified.
// ---------------------------------------------------------------------------
#pragma once

#if defined(__GNUC__) || defined(__clang__)
#  define PUSH_WARNINGS _Pragma("GCC diagnostic push")
#  define POP_WARNINGS  _Pragma("GCC diagnostic pop")
#else
#  define PUSH_WARNINGS
#  define POP_WARNINGS
#endif

// MSVC-only suppressors: nothing to do off MSVC.
#define DISABLE_VS_WARNINGS(w)

// Per-compiler warning suppressors. No-ops here (see header note). If a future
// vendored file needs a specific -W silenced, replace the relevant macro with a
// _Pragma using standard preprocessor stringizing (no boost required).
#define DISABLE_GCC_AND_CLANG_WARNING(w)
#if defined(__clang__)
#  define DISABLE_GCC_WARNING(w)
#  define DISABLE_CLANG_WARNING(w)
#else
#  define DISABLE_GCC_WARNING(w)
#  define DISABLE_CLANG_WARNING(w)
#endif
