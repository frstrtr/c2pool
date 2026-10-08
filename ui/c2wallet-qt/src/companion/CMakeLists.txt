cmake_minimum_required(VERSION 3.21)

# ═══════════════════════════════════════════════════════════════════════════
# c2wallet-qt — the ONLINE, KEY-FREE COMPANION (#193). Design
# docs/design/c2wallet-qt.md §5.2 "companion" + §5.4 "the validation seam".
#
# This is the OPPOSITE side of the network-incapable signer: the ONLINE binary
# that pulls funding data from c2pool, MARSHALS the M5-A air-gap artifacts, and
# submits the offline-signed bytes to the node. It NEVER holds a private key.
# It provides:
#   * FundingData   — public funding intake (JSON/CLI) + the legacy unsigned-tx
#                     serializer (no keys);
#   * Produce       — build the M5-A UnsignedContainer (online -> offline);
#   * Submit        — parse the signed artifact + write the PROVEN
#                     --pin-local-tx-hex / --embedded-tx-inject-hex FILE the
#                     c2pool loader consumes (primary seam), + the op=submit
#                     request;
#   * ValidateClient — the §5.4 validate_inject DRY-RUN client (request side) +
#                     digest cross-check; the online node endpoint is a named
#                     transport seam (Unwired default; loopback-HTTP stub);
#   * QrReassembly  — online-side animated-QR reassembly of the signed artifact
#                     (reuses M5-A QrTransport);
#   * MoneroSeam    — the Family-B (v37 XMR) online leg as a named cross-lane
#                     stub.
#
# KEY-FREE by construction: it links ONLY the M5-A c2wallet-artifact library
# (which links only the vendored btclibs SHA-256) — NOT the key-bearing signer
# core. The ci/check_key_free.sh guard is the mechanical proof (registered as a
# ctest, the analog of the signer's network-incapable link-guard). This library
# is Qt-free and network-free so its KATs build/run without the Qt app.
#
# Standalone (what a developer / CI runs for just this target):
#   cmake -S ui/c2wallet-qt/src/companion -B build-companion \
#         -DC2WALLET_QT_BUILD_TESTS=ON
#   cmake --build build-companion --target c2wallet-companion-test
#   ctest --test-dir build-companion --output-on-failure
# ═══════════════════════════════════════════════════════════════════════════

if(NOT DEFINED PROJECT_NAME)
    project(c2wallet_companion LANGUAGES C CXX)
    set(_companion_standalone ON)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Reuse the M5-A artifact library (UnsignedContainer / SignedContainer /
# QrTransport / ValidateSeam / Digest). Its PUBLIC includes propagate, so the
# companion sources include the artifact headers by bare name. When built as a
# subdirectory of ui/c2wallet-qt/CMakeLists.txt the target already exists;
# standalone, pull it in from the sibling artifact directory.
if(NOT TARGET c2wallet-artifact)
    add_subdirectory(
        ${CMAKE_CURRENT_SOURCE_DIR}/../family/bitcoin/artifact
        ${CMAKE_CURRENT_BINARY_DIR}/artifact)
endif()

set(COMPANION_SOURCES
    FundingData.cpp
    Produce.cpp
    Submit.cpp
    ValidateClient.cpp
    QrReassembly.cpp
)

add_library(c2wallet-companion STATIC ${COMPANION_SOURCES})

target_include_directories(c2wallet-companion PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Link ONLY the key-free artifact library. Deliberately NOT the signer core —
# that is what keeps the companion key-free (proven by ci/check_key_free.sh).
target_link_libraries(c2wallet-companion PUBLIC c2wallet-artifact)

option(C2WALLET_QT_BUILD_TESTS "Build the companion KAT test + key-free guard" OFF)
if(C2WALLET_QT_BUILD_TESTS OR _companion_standalone)
    enable_testing()
    add_executable(c2wallet-companion-test tests/test_companion.cpp)
    target_link_libraries(c2wallet-companion-test PRIVATE c2wallet-companion)
    add_test(NAME companion_kats COMMAND c2wallet-companion-test)

    # Mechanical key-free proof over the companion objects (the analog of the
    # signer's network-incapable link-guard). Runs nm/grep over the built
    # static library and asserts NO private-key / signing symbols.
    add_test(
        NAME companion_key_free_guard
        COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/../../ci/check_key_free.sh"
                "$<TARGET_FILE:c2wallet-companion>"
    )
endif()
