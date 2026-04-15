cmake_minimum_required(VERSION 3.21)
project(c2pool_qt LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets Network Charts)

add_executable(c2pool-qt
    src/main.cpp
    src/ApiClient.cpp
    src/MainWindow.cpp
    src/ProcessLauncher.cpp
    src/ConfigSerializer.cpp
    src/NodeManager.cpp
    src/PageLaunch.cpp
    src/PageSettings.cpp
    src/PageOverview.cpp
    src/PageMining.cpp
    src/PageSharechain.cpp
    src/PageLogs.cpp
    src/PagePeers.cpp
    src/SseClient.cpp
)

target_include_directories(c2pool-qt PRIVATE src)

target_link_libraries(c2pool-qt PRIVATE
    Qt6::Widgets
    Qt6::Network
    Qt6::Charts
)

# ── Platform-specific properties ──────────────────────────────────────────────
if(WIN32)
    set_target_properties(c2pool-qt PROPERTIES WIN32_EXECUTABLE TRUE)
endif()
if(APPLE)
    set_target_properties(c2pool-qt PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_BUNDLE_NAME "c2pool"
        MACOSX_BUNDLE_GUI_IDENTIFIER "org.c2pool.qt"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
    )
endif()

install(TARGETS c2pool-qt DESTINATION bin)
