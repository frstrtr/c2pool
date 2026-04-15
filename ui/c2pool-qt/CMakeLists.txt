cmake_minimum_required(VERSION 3.21)
project(c2pool_qt LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets Network)

add_executable(c2pool-qt
    src/main.cpp
    src/ApiClient.cpp
    src/MainWindow.cpp
    src/PageLaunch.cpp
    src/PageOverview.cpp
    src/PageMining.cpp
    src/PageSharechain.cpp
    src/PageLogs.cpp
)

target_include_directories(c2pool-qt PRIVATE src)

target_link_libraries(c2pool-qt PRIVATE
    Qt6::Widgets
    Qt6::Network
)
