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
target_compile_definitions(btclibs PRIVATE USE_ASM ENABLE_SSE41 ENABLE_AVX2 ENABLE_SHANI)
set_source_files_properties(crypto/sha256_sse41.cpp PROPERTIES COMPILE_OPTIONS "-msse4.1")
set_source_files_properties(crypto/sha256_avx2.cpp  PROPERTIES COMPILE_OPTIONS "-mavx2")
set_source_files_properties(crypto/sha256_shani.cpp PROPERTIES COMPILE_OPTIONS "-msse4;-msha")
# ---------------------------------------------------------------------------
target_include_directories(btclibs PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} util crypto compat)

target_link_libraries(btclibs Boost::headers nlohmann_json::nlohmann_json)