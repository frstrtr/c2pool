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
    src/PageSharechain.cpp
    src/PageLogs.cpp
    src/PageEmbedded.cpp
    src/bridges/SharechainBridge.cpp
)

# Step 2 embedded-web smoke-test resource: qrc:///test/hello.html.
# Step 7+ adds the real Explorer bundle under qrc:///sharechain-explorer/.
qt_add_resources(c2pool-qt "test_resources"
    PREFIX "/test"
    BASE   "${CMAKE_CURRENT_SOURCE_DIR}/src/resources/test"
    FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/src/resources/test/hello.html"
)

target_include_directories(c2pool-qt PRIVATE src)

target_link_libraries(c2pool-qt PRIVATE
    Qt6::Widgets
    Qt6::Network
    Qt6::WebEngineCore
    Qt6::WebEngineWidgets
    Qt6::WebChannel
)

# Propagate the dev-bundle flag as a compile definition so C++ code in
# subsequent steps can `#ifdef C2POOL_QT_DEV_BUNDLE` to branch between
# the qrc:/// resource path and a filesystem path. The keychain flag
# is consumed when the settings bridge lands.
if(C2POOL_QT_DEV_BUNDLE)
    target_compile_definitions(c2pool-qt PRIVATE C2POOL_QT_DEV_BUNDLE=1)
endif()
if(C2POOL_QT_USE_KEYCHAIN)
    target_compile_definitions(c2pool-qt PRIVATE C2POOL_QT_USE_KEYCHAIN=1)
endif()
