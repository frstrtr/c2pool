# Enhanced C2Pool Components

# Hashrate Tracker Library
add_library(c2pool_hashrate
    hashrate/tracker.cpp
)
target_include_directories(c2pool_hashrate PUBLIC .)
target_link_libraries(c2pool_hashrate 
    btclibs
    core
    nlohmann_json::nlohmann_json
)

# Difficulty Adjustment Engine Library  
add_library(c2pool_difficulty
    difficulty/adjustment_engine.cpp
)
target_include_directories(c2pool_difficulty PUBLIC .)
target_link_libraries(c2pool_difficulty 
    btclibs
    core
    nlohmann_json::nlohmann_json
)

# Storage Manager Library
add_library(c2pool_storage
    storage/sharechain_storage.cpp
)
target_include_directories(c2pool_storage PUBLIC .)
target_link_libraries(c2pool_storage 
    core
    btclibs
)

# Merged Mining Manager Library (integrated mm-adapter)
add_library(c2pool_merged_mining
    merged/merged_mining.cpp
)
target_include_directories(c2pool_merged_mining PUBLIC .)
target_link_libraries(c2pool_merged_mining
    core
    btclibs
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)

# Enhanced Node Library
add_library(c2pool_node_enhanced
    node/enhanced_node.cpp
)
target_include_directories(c2pool_node_enhanced PUBLIC .)
target_link_libraries(c2pool_node_enhanced 
    ltc
    core
    c2pool_hashrate
    c2pool_difficulty
    c2pool_storage
    nlohmann_json::nlohmann_json
)

# Inject version from git at build time
execute_process(
    COMMAND git describe --tags --always
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE C2POOL_GIT_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT C2POOL_GIT_VERSION)
    set(C2POOL_GIT_VERSION "0.1.0-alpha")
endif()
# Strip leading 'v'
string(REGEX REPLACE "^v" "" C2POOL_GIT_VERSION "${C2POOL_GIT_VERSION}")

# Main C2Pool Enhanced Application (refactored with mining_shares/p2p_shares separation)
add_executable(c2pool c2pool_refactored.cpp)
target_compile_definitions(c2pool PRIVATE C2POOL_VERSION="${C2POOL_GIT_VERSION}")
target_link_libraries(c2pool
    c2pool_node_enhanced
    c2pool_payout
    c2pool_merged_mining
    core
    ltc
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)

# Enhanced version with explicit name (for backward compatibility)
add_executable(c2pool_enhanced c2pool_refactored.cpp)
target_link_libraries(c2pool_enhanced
    c2pool_node_enhanced
    c2pool_payout
    c2pool_merged_mining
    core
    ltc
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)

# Windows: Boost.Asio requires Winsock libraries; /bigobj for large translation units
if(WIN32)
    target_link_libraries(c2pool ws2_32 mswsock bcrypt)
    target_link_libraries(c2pool_enhanced ws2_32 mswsock bcrypt)
endif()
if(MSVC)
    target_compile_options(c2pool PRIVATE /bigobj)
    target_compile_options(c2pool_enhanced PRIVATE /bigobj)
endif()

# Test applications
add_executable(test_ltc_node test_ltc_node.cpp)
target_link_libraries(test_ltc_node core btclibs pool ltc)
target_link_libraries(test_ltc_node nlohmann_json::nlohmann_json)

# Legacy applications have been archived to ../../archive/
# - c2pool_legacy.cpp (original c2pool.cpp)
# - c2pool_node_legacy.cpp (original c2pool_node.cpp)
# - c2pool_temp_legacy.cpp (original c2pool_temp.cpp)

add_subdirectory(ltc)
add_subdirectory(payout)

# core's web_server.cpp references symbols from c2pool_payout, c2pool_hashrate,
# and secp256k1, so expose them transitively so any target linking core also
# picks them up (fixes link ordering for test executables).
# NOTE: uses plain signature to match core/CMakeLists.txt's style.
target_link_libraries(core c2pool_payout c2pool_hashrate c2pool_merged_mining ltc ${SECP256K1_LIBRARIES})