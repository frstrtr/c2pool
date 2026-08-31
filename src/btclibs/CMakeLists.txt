file(GLOB crypto_sources "crypto/*.h" "crypto/*.cpp")

# Blake3 (portable-only build for MWEB header hashing)
set(blake3_sources
    crypto/blake3/blake3.c
    crypto/blake3/blake3.h
    crypto/blake3/blake3_impl.h
    crypto/blake3/blake3_dispatch.c
    crypto/blake3/blake3_portable.c
)


set(sources
        uint256.h
        uint256.cpp
        tinyformat.h
        attributes.h
#        arith_uint256.h
#        arith_uint256.cpp
        hash.h
        hash.cpp
        util/str.h
        util/str.cpp
        util/strencodings.h
        util/strencodings.cpp
        util/spanparsing.cpp
        util/spanparsing.h
        compat/byteswap.h
        compat/endian.h
        compat/cpuid.h
        script/script.h
        script/script.cpp
        span.h
        base58.h
        base58.cpp
        serialize.h
        prevector.h
        core_read.cpp
        core_io.h
        streams.h streams.cpp
        ${crypto_sources}
        ${blake3_sources}
        )

add_library(btclibs STATIC ${sources}) #${SOURCE} ${HEADER})

# ---------------------------------------------------------------------------
# Runtime-dispatched SIMD SHA256 (Bitcoin Core crypto/sha256.cpp).
#
# btclibs vendors the full CPUID-dispatched SHA256 family (sse4 single-block,
# sse4.1 4-way + avx2 8-way TransformD64, and the SHA-NI transform), but every
# optimized translation unit is wrapped in ifdef ENABLE_*/USE_ASM and stays
# EMPTY unless the macro is defined, and SHA256AutoDetect was never called at
# all -- so the whole binary ran the scalar C sha256::Transform. Define the
# gates and give each optimized TU its -march flag so the code compiles;
# SHA256AutoDetect() (called once at process start) then probes CPUID and
# installs the fastest transform the running CPU proves correct via
# CSHA256::SelfTest. Output is BYTE-IDENTICAL to the scalar path by
# construction; a CPU lacking a feature never selects that path, so the binary
# stays portable across the fleet.
#
# Reward-safety: the DASH daemonless replay fold recomputes the full
# merkleRootMNList / merkleRootQuorums every block and byte-compares them to the
# committed cbTx roots (poison fail-closed on mismatch). That self-check is
# UNCHANGED and stays the authority -- a miscompiled SIMD transform can only
# make a root mismatch and hard-stop, never silently mis-fold. This swaps only
# the primitive underneath ~70% of fold-thread CPU (its scalar form).
# GCC/Clang only: the optimized TUs use GNU-syntax __attribute__((always_inline))
# and GCC-style -msse4.1/-mavx2/-msha flags. MSVC ignores those flags (warning
# D9002) but still opens the ENABLE_* #ifdef gates, then fails to compile the
# GNU attribute (C2182). Leave the ENABLE_* macros undefined on MSVC so the three
# SIMD TUs compile to empty (their bodies are fully #ifdef-wrapped) and
# SHA256AutoDetect falls back to the scalar transform -- the proven pre-SIMD path,
# self-checked by CSHA256::SelfTest and the fold merkle byte-compare. No behavior
# change on the fleet's Linux build hosts.
# Arch gate: -msse4.1/-mavx2/-msha and the Intel <immintrin.h> intrinsics are
# x86-ONLY. clang rejects them for arm64-apple-darwin ("unsupported option
# '-mavx2' for target 'arm64-...'"), which broke the macOS arm64 CI build. Emit
# the SIMD definitions + flags only for an x86 (Intel/AMD) target. On any other
# target (Apple Silicon arm64, aarch64, or a universal slice that includes
# arm64) none of USE_ASM/ENABLE_SSE41/ENABLE_AVX2/ENABLE_SHANI is defined, so
# every optimized TU compiles to empty (its body is fully #ifdef-wrapped) and
# SHA256AutoDetect() -- itself gated on HAVE_GETCPUID, which compat/cpuid.h only
# defines on x86 -- returns the scalar sha256::Transform. The scalar path is
# self-checked by CSHA256::SelfTest and, on the DASH fold, by the merkle
# byte-compare, so arm64 stays correct while x86_64 is byte-identical and keeps
# the SIMD fold path unchanged.
#
# On Apple the effective target arch is CMAKE_OSX_ARCHITECTURES (which can be a
# ";"-separated universal list), not CMAKE_SYSTEM_PROCESSOR -- consult it first.
# A universal build that names arm64 must not receive x86-only flags (a single
# COMPILE_OPTIONS cannot be made per-slice), so such builds fall back to scalar.
set(_btclibs_target_arch "${CMAKE_SYSTEM_PROCESSOR}")
if(CMAKE_OSX_ARCHITECTURES)
    set(_btclibs_target_arch "${CMAKE_OSX_ARCHITECTURES}")
endif()
set(_btclibs_x86_target FALSE)
if(_btclibs_target_arch MATCHES "(^|;)(x86_64|amd64|AMD64|x64|i[3-6]86)($|;)")
    set(_btclibs_x86_target TRUE)
endif()
if(_btclibs_target_arch MATCHES "arm64|aarch64|arm")
    # arm64 present (incl. a universal slice) -> never emit x86-only flags.
    set(_btclibs_x86_target FALSE)
endif()

if(NOT MSVC AND _btclibs_x86_target)
    # Belt-and-suspenders: enable each optimized TU only if the compiler truly
    # accepts its flag, so an old x86 toolchain missing one extension drops just
    # that TU (never a macro without its flag). A normal x86 clang/gcc accepts
    # all three, so the x86_64 build is unchanged from before this gate.
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-msse4.1" BTCLIBS_HAVE_MSSE41)
    check_cxx_compiler_flag("-mavx2"   BTCLIBS_HAVE_MAVX2)
    check_cxx_compiler_flag("-msha"    BTCLIBS_HAVE_MSHA)

    target_compile_definitions(btclibs PRIVATE USE_ASM)
    if(BTCLIBS_HAVE_MSSE41)
        target_compile_definitions(btclibs PRIVATE ENABLE_SSE41)
        set_source_files_properties(crypto/sha256_sse41.cpp PROPERTIES COMPILE_OPTIONS "-msse4.1")
    endif()
    if(BTCLIBS_HAVE_MAVX2)
        target_compile_definitions(btclibs PRIVATE ENABLE_AVX2)
        set_source_files_properties(crypto/sha256_avx2.cpp  PROPERTIES COMPILE_OPTIONS "-mavx2")
    endif()
    if(BTCLIBS_HAVE_MSHA)
        target_compile_definitions(btclibs PRIVATE ENABLE_SHANI)
        set_source_files_properties(crypto/sha256_shani.cpp PROPERTIES COMPILE_OPTIONS "-msse4;-msha")
    endif()
endif()
# ---------------------------------------------------------------------------
target_include_directories(btclibs PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} util crypto compat)

target_link_libraries(btclibs Boost::headers nlohmann_json::nlohmann_json)