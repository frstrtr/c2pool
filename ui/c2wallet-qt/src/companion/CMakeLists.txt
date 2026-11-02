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
#                     stub;
#   * sched/        — the inject scheduler core: queue file, triggers (maturity,
#                     height, time, parents), the per-item state machine, the
#                     submit outcome map, consented auto-arm and the 0600
#                     token-file reader. Qt-free; the node is reached only
#                     through the sched::NodeApi seam.
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

# The inject scheduler core (sched/) parses queue files, manifests and node
# replies with nlohmann::json, the node's own wire library (header-only). It is
# a dependency of the companion ONLY: the signer target never links it, and a
# signer-only build (-DC2WALLET_QT_BUILD_COMPANION=OFF) never reaches this file.
find_package(nlohmann_json 3.9 QUIET)
if(NOT nlohmann_json_FOUND)
    message(FATAL_ERROR
        "c2wallet-qt companion: nlohmann_json >= 3.9 not found (Debian/Ubuntu: "
        "apt install nlohmann-json3-dev). For a signer-only build configure "
        "ui/c2wallet-qt with -DC2WALLET_QT_BUILD_COMPANION=OFF.")
endif()

set(COMPANION_SOURCES
    FundingData.cpp
    Produce.cpp
    Submit.cpp
    ValidateClient.cpp
    QrReassembly.cpp
    # Inject scheduler core (Qt-free, no network I/O of its own: it talks to the
    # node only through the sched::NodeApi seam). Design: the c2wallet-qt
    # inject scheduler, slice S1.
    sched/InjectQueue.cpp
    sched/Triggers.cpp
    sched/SubmitOutcome.cpp
    sched/Scheduler.cpp
    sched/ChainView.cpp
    sched/ArmPolicy.cpp
    sched/TokenFile.cpp
    sched/Config.cpp
    # The runner side of the queue file (merge + locks) and the operator
    # command line of c2wallet-qt-schedd (slice S2), still Qt-free.
    sched/Runner.cpp
    sched/SchedCli.cpp
    # Zeroizing buffer for the control token. One std-only TU with no key
    # symbols (the same file the signer libraries compile).
    ${CMAKE_CURRENT_SOURCE_DIR}/../secure/SecureString.cpp
)

add_library(c2wallet-companion STATIC ${COMPANION_SOURCES})

target_include_directories(c2wallet-companion PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Link ONLY the key-free artifact library. Deliberately NOT the signer core —
# that is what keeps the companion key-free (proven by ci/check_key_free.sh).
# nlohmann::json is private: no public companion header includes it.
target_link_libraries(c2wallet-companion
    PUBLIC c2wallet-artifact
    PRIVATE nlohmann_json::nlohmann_json)

option(C2WALLET_QT_BUILD_TESTS "Build the companion KAT test + key-free guard" OFF)
if(C2WALLET_QT_BUILD_TESTS OR _companion_standalone)
    enable_testing()
    add_executable(c2wallet-companion-test tests/test_companion.cpp)
    target_link_libraries(c2wallet-companion-test PRIVATE c2wallet-companion)
    add_test(NAME companion_kats COMMAND c2wallet-companion-test)

    # Inject scheduler KATs (K1-K27): a scripted fake node + a fake clock drive
    # the Qt-free core end to end; no network, no Qt.
    add_executable(c2wallet-companion-sched-test tests/test_sched.cpp)
    target_link_libraries(c2wallet-companion-sched-test PRIVATE
        c2wallet-companion nlohmann_json::nlohmann_json)
    # The node headers in this tree, for the cause-vocabulary drift check.
    target_compile_definitions(c2wallet-companion-sched-test PRIVATE
        C2POOL_NODE_COIN_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/impl/dash/coin")
    add_test(NAME companion_sched_kats COMMAND c2wallet-companion-sched-test)

    # Mechanical key-free proof over the companion objects (the analog of the
    # signer's network-incapable link-guard). Runs nm/grep over the built
    # static library and asserts NO private-key / signing symbols.
    add_test(
        NAME companion_key_free_guard
        COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/../../ci/check_key_free.sh"
                "$<TARGET_FILE:c2wallet-companion>"
    )
endif()

# ═══════════════════════════════════════════════════════════════════════════
# Slice S2: the Qt Network transport (sched/QtNodeApi) and the headless runner
# c2wallet-qt-schedd. Built whenever Qt6::Network is available: always from
# ui/c2wallet-qt (the parent found it for the companion GUI), and standalone
# when Qt6 Core + Network are installed. The Qt-free library above never links
# Qt: QtNodeApi lives in its own static library that only the companion GUI
# and this binary link. The daemon links Qt6::Core + Qt6::Network only: no
# Gui, no Widgets (ci/check_no_gui_link.sh), and it is key-free like the
# library (ci/check_key_free.sh over the linked binary).
# ═══════════════════════════════════════════════════════════════════════════
if(NOT TARGET Qt6::Network AND _companion_standalone)
    find_package(Qt6 6.2 QUIET COMPONENTS Core Network)
endif()
if(TARGET Qt6::Network)
    add_library(c2wallet-companion-qtnet STATIC sched/QtNodeApi.cpp)
    target_link_libraries(c2wallet-companion-qtnet PUBLIC c2wallet-companion Qt6::Core Qt6::Network)

    add_executable(c2wallet-qt-schedd schedd/main.cpp)
    target_link_libraries(c2wallet-qt-schedd PRIVATE
        c2wallet-companion-qtnet c2wallet-companion Qt6::Core Qt6::Network)

    if(C2WALLET_QT_BUILD_TESTS OR _companion_standalone)
        # QtNodeApi against a local QTcpServer fake node, the scheduler over
        # it, and an end-to-end run of the daemon binary (init, add, consent,
        # run, list, status, single instance, disarm after a node restart).
        add_executable(c2wallet-qt-schedd-test tests/test_schedd_qt.cpp)
        target_link_libraries(c2wallet-qt-schedd-test PRIVATE
            c2wallet-companion-qtnet c2wallet-companion Qt6::Core Qt6::Network)
        target_compile_definitions(c2wallet-qt-schedd-test PRIVATE
            C2WALLET_SCHEDD_BIN="$<TARGET_FILE:c2wallet-qt-schedd>")
        add_dependencies(c2wallet-qt-schedd-test c2wallet-qt-schedd)
        add_test(NAME schedd_qt_kats COMMAND c2wallet-qt-schedd-test)

        add_test(
            NAME schedd_key_free_guard
            COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/../../ci/check_key_free.sh"
                    "$<TARGET_FILE:c2wallet-qt-schedd>")
        add_test(
            NAME schedd_no_gui_link_guard
            COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/../../ci/check_no_gui_link.sh"
                    "$<TARGET_FILE:c2wallet-qt-schedd>")
    endif()
else()
    message(STATUS "c2wallet-qt companion: Qt6 Network not found; c2wallet-qt-schedd is not built")
endif()
