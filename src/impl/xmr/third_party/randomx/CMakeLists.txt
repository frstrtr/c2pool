# SPDX-License-Identifier: AGPL-3.0-or-later
# ─────────────────────────────────────────────────────────────────────────────
# c2pool XMR-lane build wiring for the VENDORED tevador/RandomX source.
#
# This file is c2pool's OWN authored CMake (AGPL). It builds a single static
# archive `randomx` from the byte-identical upstream sources under ./src/
# (tevador/RandomX @ 12f2c2ff — the Monero mainnet rx/0 consensus pin; see
# PROVENANCE.txt). It contains NO upstream build code: the source LIST below is
# the set of translation units RandomX needs, but the CMake logic here is ours.
#
# LIGHT MODE — what "light" means and why the full source list is still built:
#   RandomX "light" vs "fast" is a RUNTIME choice, not a compile-time one. Fast
#   mode allocates the 2 GiB dataset (randomx_alloc_dataset); light mode keeps
#   ONLY the 256 MiB Argon2d cache and the light VM recomputes each dataset item
#   on demand from that cache (src/vm_*_light.cpp -> src/dataset.cpp
#   initDatasetItem). So dataset.cpp/superscalar.cpp MUST be compiled even for
#   light verify. c2pool's wrapper (pow/randomx_verify.hpp) NEVER sets
#   RANDOMX_FLAG_FULL_MEM and NEVER calls randomx_alloc_dataset — that, not a
#   build switch, is what makes the per-node cost 256 MiB (+256 MiB across an
#   epoch rollover) + a 2 MiB scratchpad per VM. There is intentionally no
#   dataset/FULL_MEM target here.
#
#   JIT is OPTIONAL. On x86-64 the JIT compiler TUs are built and the wrapper
#   may pass RANDOMX_FLAG_JIT (fast light execution). On any arch, or if the
#   caller clears RANDOMX_FLAG_JIT, RandomX falls back to the portable
#   interpreter (src/vm_interpreted_light.cpp via jit_compiler_fallback.hpp).
#   Correctness (the hash) is identical either way — JIT only changes speed.
# ─────────────────────────────────────────────────────────────────────────────

cmake_minimum_required(VERSION 3.10)

# Portable translation units — compiled on every architecture. This is the
# light-verify surface: Argon2d cache fill (argon2_*, blake2b), the SuperscalarHash
# dataset generator (superscalar/dataset), the interpreted light VM, and the C API.
set(randomx_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/aes_hash.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/argon2_ref.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/argon2_ssse3.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/argon2_avx2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bytecode_machine.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cpu.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dataset.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/soft_aes.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/virtual_memory.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vm_interpreted.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/allocator.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/assembly_generator_x86.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/instruction.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/randomx.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/superscalar.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vm_compiled.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vm_interpreted_light.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/argon2_core.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/blake2_generator.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/instructions_portable.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/reciprocal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/virtual_machine.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vm_compiled_light.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/blake2/blake2b.c)

# Resolve the target architecture id (host build on CI; no cross-compile here).
if(NOT ARCH_ID)
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "")
        set(CMAKE_SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
    endif()
    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" ARCH_ID)
endif()

include(CheckCCompilerFlag)

# Enable a compiler flag on a single source file only if the toolchain accepts it.
function(c2pool_rx_srcflag src flag var)
    check_c_compiler_flag(${flag} ${var})
    if(${var})
        set_source_files_properties(${src} PROPERTIES COMPILE_FLAGS ${flag})
    endif()
endfunction()

set(RANDOMX_HAVE_JIT OFF)

# x86-64: build the JIT compiler + its static machine-code blob, and enable the
# AES / SSSE3 / AVX2 codepaths that RandomX selects at runtime.
if((CMAKE_SIZEOF_VOID_P EQUAL 8) AND
   (ARCH_ID STREQUAL "x86_64" OR ARCH_ID STREQUAL "x86-64" OR ARCH_ID STREQUAL "amd64"))
    list(APPEND randomx_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/jit_compiler_x86.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/jit_compiler_x86_static.S)
    # .S carries C-preprocessor directives; compile it through the C frontend.
    set_property(SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/jit_compiler_x86_static.S
                 PROPERTY LANGUAGE C)
    check_c_compiler_flag(-maes C2POOL_RX_HAVE_MAES)
    if(C2POOL_RX_HAVE_MAES)
        add_compile_options(-maes)
    endif()
    c2pool_rx_srcflag(${CMAKE_CURRENT_SOURCE_DIR}/src/argon2_ssse3.c -mssse3 C2POOL_RX_HAVE_SSSE3)
    c2pool_rx_srcflag(${CMAKE_CURRENT_SOURCE_DIR}/src/argon2_avx2.c  -mavx2  C2POOL_RX_HAVE_AVX2)
    set(RANDOMX_HAVE_JIT ON)
# ARMv8: JIT + crypto AES. Falls back to interpreter cleanly if unavailable.
elseif(ARCH_ID STREQUAL "aarch64" OR ARCH_ID STREQUAL "arm64" OR ARCH_ID STREQUAL "armv8-a")
    list(APPEND randomx_sources
        ${CMAKE_CURRENT_SOURCE_DIR}/src/jit_compiler_a64.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/jit_compiler_a64_static.S)
    set_property(SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/jit_compiler_a64_static.S
                 PROPERTY LANGUAGE C)
    check_c_compiler_flag("-march=armv8-a+crypto" C2POOL_RX_HAVE_ARMCRYPTO)
    if(C2POOL_RX_HAVE_ARMCRYPTO)
        add_compile_options(-march=armv8-a+crypto)
    endif()
    include(CheckIncludeFile)
    check_include_file(asm/hwcap.h C2POOL_RX_HAVE_HWCAP)
    if(C2POOL_RX_HAVE_HWCAP)
        add_definitions(-DHAVE_HWCAP)
    endif()
    set(RANDOMX_HAVE_JIT ON)
endif()
# Any other arch: no JIT TU is added; randomx.cpp uses jit_compiler_fallback.hpp
# and the interpreter. Light verify still works (just slower). No action needed.

add_library(randomx STATIC ${randomx_sources})

# Consumers that link `randomx` get the vendored src/ on their include path,
# so `#include "randomx.h"` resolves to src/randomx.h (byte-identical to the
# root API copy documented in PROVENANCE.txt).
target_include_directories(randomx PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

set_property(TARGET randomx PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property(TARGET randomx PROPERTY C_STANDARD 99)
set_property(TARGET randomx PROPERTY CXX_STANDARD 11)
set_property(TARGET randomx PROPERTY CXX_STANDARD_REQUIRED ON)

if(NOT RANDOMX_HAVE_JIT)
    message(STATUS "c2pool/randomx: no JIT for arch '${ARCH_ID}' — interpreter light VM (correct, slower)")
endif()
