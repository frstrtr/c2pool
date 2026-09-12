cmake_minimum_required(VERSION 3.21)

# ═══════════════════════════════════════════════════════════════════════════
# c2wallet-qt — Family A (Bitcoin-script) AIR-GAP TRANSFER ARTIFACTS, phase
# M5-A (#193). Design docs/design/c2wallet-qt.md §5.4 "Transfer format & the
# c2pool validation seam" (Family A part).
#
# This module MARSHALS bytes across the air gap — it does NOT sign (that is the
# M3-A/M4-A signer core). It provides:
#   * UnsignedContainer — a PSBT-like, raw-hex-superset container (online ->
#     offline) carrying the unsigned tx + per-input metadata + coin/network +
#     sighash-algebra selector + optional c2pool pre-flight verdict;
#   * SignedContainer   — the c2pool loader format VERBATIM (offline -> online):
#     one raw signed tx hex per line (--pin-local-tx-hex /
#     --embedded-tx-inject-hex);
#   * QrTransport       — multi-frame animated-QR codec (seq/total/per-frame
#     sha256), bounded by the 100 kB oversize ceiling;
#   * ValidateSeam      — the transport-agnostic validate/submit contract + the
#     validate_inject dry-run + the online node's named verdict vocabulary +
#     the clearly-named UNWIRED cross-lane seam.
#
# DELIBERATELY Qt-FREE and NETWORK-FREE (inherits the M0 network-incapable
# property), so its KATs build and run without the Qt app. It REUSES, never
# re-implements (design §2.4 reuse table): the vendored btclibs CSHA256 for the
# sha256 / sha256d digests. No secp256k1 (no signing here).
#
# Standalone use (what CI / a developer runs for just this target):
#   cmake -S ui/c2wallet-qt/src/family/bitcoin/artifact -B build-artifact \
#         -DC2WALLET_QT_BUILD_TESTS=ON
#   cmake --build build-artifact --target c2wallet-artifact-test
#   ctest --test-dir build-artifact --output-on-failure
# ═══════════════════════════════════════════════════════════════════════════

if(NOT DEFINED PROJECT_NAME)
    project(c2wallet_artifact LANGUAGES C CXX)
    set(_artifact_standalone ON)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Repo root: artifact -> bitcoin -> family -> src -> c2wallet-qt -> ui -> <root>
get_filename_component(C2POOL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../.." ABSOLUTE)
set(C2POOL_SRC "${C2POOL_ROOT}/src")

# ── Reused c2pool sources (leaf closure only): the vendored SHA-256. ─────────
set(REUSED_SOURCES
    ${C2POOL_SRC}/btclibs/crypto/sha256.cpp
)

set(ARTIFACT_SOURCES
    Digest.cpp
    TransferContainer.cpp
    QrTransport.cpp
    ValidateSeam.cpp
)

add_library(c2wallet-artifact STATIC ${ARTIFACT_SOURCES} ${REUSED_SOURCES})

target_include_directories(c2wallet-artifact PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${C2POOL_SRC}
    ${C2POOL_SRC}/btclibs
    ${C2POOL_SRC}/btclibs/crypto
    ${C2POOL_SRC}/btclibs/compat
    ${C2POOL_SRC}/btclibs/util
)

# Keep the portable SHA256 path (no USE_ASM) so this tiny module never needs
# per-file -march juggling; correctness is byte-identical.

option(C2WALLET_QT_BUILD_TESTS "Build the artifact KAT test" OFF)
if(C2WALLET_QT_BUILD_TESTS OR _artifact_standalone)
    enable_testing()
    add_executable(c2wallet-artifact-test tests/test_artifact.cpp)
    target_link_libraries(c2wallet-artifact-test PRIVATE c2wallet-artifact)
    add_test(NAME artifact_kats COMMAND c2wallet-artifact-test)
endif()
