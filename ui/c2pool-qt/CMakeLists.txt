cmake_minimum_required(VERSION 3.21)
project(c2pool_qt LANGUAGES CXX)

# Qt6 6.2 is the hard floor (WebEngine was stabilised at 6.2 per
# frstrtr/the/docs/c2pool-qt-hybrid-architecture.md §7.3). The design
# doc's "best experience" at 6.5+ is aspirational — functional
# correctness only needs 6.2+, and Debian/Ubuntu stable currently
# ships 6.4.2 which works.
#
# WebEngineCore / WebEngineWidgets / WebChannel are required here
# even though step 1 doesn't yet consume them; downstream refactor
# steps land QWebEngineView (PageEmbedded), QWebChannel bridging,
# and the qrc bundle. Declaring them at step 1 makes "the app still
# builds" a meaningful gate as subsequent steps add consumers.
#
# Install on Debian/Ubuntu via:
#   sudo apt install qt6-webengine-dev qt6-webchannel-dev
find_package(Qt6 6.2 REQUIRED COMPONENTS
    Core
    Widgets
    Network
    WebEngineCore
    WebEngineWidgets
    WebChannel
)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Refactor option flags (declarative here; behaviour lands in
# subsequent refactor steps). Documented in
# frstrtr/the/docs/c2pool-qt-hybrid-architecture.md §7.2.
option(C2POOL_QT_USE_KEYCHAIN
    "Store secrets in OS keychain via qtkeychain (fallback to QSettings)"
    ON)

# qtkeychain is a SOFT dependency — the option controls whether we
# try to find it. If enabled but the package isn't installed, fall
# back to QSettings secrets (SettingsStore carries both code paths).
if(C2POOL_QT_USE_KEYCHAIN)
    find_package(Qt6Keychain CONFIG QUIET)
    if(NOT Qt6Keychain_FOUND)
        message(STATUS "Qt6Keychain not found — SettingsStore will use QSettings secrets fallback. "
                       "Install qtkeychain-qt6-dev (or equivalent) to enable OS keychain storage.")
    endif()
endif()
option(C2POOL_QT_DEV_BUNDLE
    "Allow loading the JS bundle from a filesystem path (dev only)"
    OFF)

add_executable(c2pool-qt
    src/main.cpp
    src/ApiClient.cpp
    src/MainWindow.cpp
    src/PageLaunch.cpp
    src/PageOverview.cpp
    src/PageMining.cpp
    src/PageLogs.cpp
    src/PageSettings.cpp
    src/PageEmbedded.cpp
    src/SettingsStore.cpp
    src/bridges/SharechainBridge.cpp
    src/bridges/PplnsBridge.cpp
    src/bridges/SettingsBridge.cpp
    src/bridges/CoinBridge.cpp
)

# Step 2 embedded-web smoke-test resource: qrc:///test/hello.html.
qt_add_resources(c2pool-qt "test_resources"
    PREFIX "/test"
    BASE   "${CMAKE_CURRENT_SOURCE_DIR}/src/resources/test"
    FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/src/resources/test/hello.html"
)

# Step 7 — real Explorer bundle at qrc:///sharechain-explorer/. The
# embed host (dashboard-embed.html) loads the esbuild-produced
# dist/sharechain-explorer.js via an ES-module import; both travel
# together. A later refactor step can switch BASE to a generated
# file list from resources-manifest.json.
set(C2POOL_EXPLORER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../web-static/sharechain-explorer")
qt_add_resources(c2pool-qt "explorer_bundle"
    PREFIX "/sharechain-explorer"
    BASE   "${C2POOL_EXPLORER_DIR}"
    FILES
        "${C2POOL_EXPLORER_DIR}/dashboard-embed.html"
        "${C2POOL_EXPLORER_DIR}/dist/sharechain-explorer.js"
        "${C2POOL_EXPLORER_DIR}/pplns-embed.html"
        "${C2POOL_EXPLORER_DIR}/dist/pplns-view.js"
)

# The panel reads the node's parameter catalog (src/core/param_catalog.*) and the
# per-coin address-encoding registry leaf headers (src/impl/<coin>/
# address_encoding.hpp) so its generated argv + payout-address check can never
# drift from the node. Both are Qt-free leaf headers; expose the node src root.
set(C2POOL_NODE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
target_include_directories(c2pool-qt PRIVATE src "${C2POOL_NODE_SRC}")

target_link_libraries(c2pool-qt PRIVATE
    Qt6::Widgets
    Qt6::Network
    Qt6::WebEngineCore
    Qt6::WebEngineWidgets
    Qt6::WebChannel
)

# Propagate the dev-bundle flag as a compile definition so C++ code in
# subsequent steps can `#ifdef C2POOL_QT_DEV_BUNDLE` to branch between
# the qrc:/// resource path and a filesystem path.
if(C2POOL_QT_DEV_BUNDLE)
    target_compile_definitions(c2pool-qt PRIVATE C2POOL_QT_DEV_BUNDLE=1)
endif()
# C2POOL_QT_USE_KEYCHAIN is defined only when qtkeychain was found,
# so the C++ code can `#ifdef C2POOL_QT_USE_KEYCHAIN` to reach the
# keychain branch without guessing whether the library is linkable.
if(C2POOL_QT_USE_KEYCHAIN AND Qt6Keychain_FOUND)
    target_compile_definitions(c2pool-qt PRIVATE C2POOL_QT_USE_KEYCHAIN=1)
    target_link_libraries(c2pool-qt PRIVATE Qt6Keychain::Qt6Keychain)
endif()

# ── Step 14 leak-regression gate ─────────────────────────────────────
# mount→destroy × 100 of PageEmbedded; asserts no leaked QtWebEngine
# helper processes. Runs under QT_QPA_PLATFORM=offscreen so it doesn't
# need a display. Off by default so a plain c2pool-qt build stays
# minimal; enable with -DC2POOL_QT_BUILD_TESTS=ON.
option(C2POOL_QT_BUILD_TESTS
    "Build c2pool-qt leak-regression + smoke tests"
    OFF)

if(C2POOL_QT_BUILD_TESTS)
    add_executable(c2pool-qt_test_embedded_leak
        test/test_embedded_leak.cpp
        src/PageEmbedded.cpp
    )
    # Reuse the test_resources + explorer_bundle qrc blobs so the
    # harness can load qrc:///test/hello.html without rebuilding the
    # resource tree.
    qt_add_resources(c2pool-qt_test_embedded_leak "test_resources_leak"
        PREFIX "/test"
        BASE   "${CMAKE_CURRENT_SOURCE_DIR}/src/resources/test"
        FILES  "${CMAKE_CURRENT_SOURCE_DIR}/src/resources/test/hello.html"
    )
    target_include_directories(c2pool-qt_test_embedded_leak PRIVATE src)
    target_link_libraries(c2pool-qt_test_embedded_leak PRIVATE
        Qt6::Widgets
        Qt6::Network
        Qt6::WebEngineCore
        Qt6::WebEngineWidgets
        Qt6::WebChannel
    )
    if(C2POOL_QT_DEV_BUNDLE)
        target_compile_definitions(c2pool-qt_test_embedded_leak PRIVATE
            C2POOL_QT_DEV_BUNDLE=1)
    endif()

    # ── ★ Reward-safety gate ─────────────────────────────────────────────
    # Proves the per-coin launch command core: the default DASH command is a
    # bare --run (daemonless) and never emits the dashd/embedded arms
    # (--coin-rpc / --coin-p2p-connect / --embedded-mainnet) unless their
    # explicit opt-ins are set; the author donation is never silently zeroed.
    # Qt-free (LaunchCommand.hpp is std-only) so it runs anywhere.
    enable_testing()
    add_executable(c2pool-qt_test_reward_safe_launch
        test/test_reward_safe_launch.cpp
    )
    target_include_directories(c2pool-qt_test_reward_safe_launch PRIVATE
        src "${C2POOL_NODE_SRC}")
    add_test(NAME reward_safe_launch
             COMMAND c2pool-qt_test_reward_safe_launch)

    # ── QP-B address-flavor gate ─────────────────────────────────────────
    # Proves a wrong-coin base58 payout address (e.g. a DASH 'X…' address in
    # a Litecoin profile) is rejected, while bech32/cashaddr/unknown flavors
    # pass through unjudged. AddressValidator is Qt-Core only (QString +
    # QCryptographicHash), so this links Qt6::Core and runs headless.
    add_executable(c2pool-qt_test_address_validator
        test/test_address_validator.cpp
    )
    target_include_directories(c2pool-qt_test_address_validator PRIVATE
        src "${C2POOL_NODE_SRC}")
    target_link_libraries(c2pool-qt_test_address_validator PRIVATE Qt6::Core)
    add_test(NAME address_validator
             COMMAND c2pool-qt_test_address_validator)

    # ── Teardown leak/crash gate (issue #852) ────────────────────────────
    # The embedded-view host tore itself down via deregisterObject(nullptr),
    # a null-deref inside QWebChannel. This KAT exercises the destroy fence
    # over 100 build/destroy iterations and crashed before the fix. Needs a
    # WebEngine backend; runs offscreen with software GL.
    add_test(NAME embedded_leak
             COMMAND c2pool-qt_test_embedded_leak)
    set_tests_properties(embedded_leak PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        TIMEOUT 90)
endif()
