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

# Main C2Pool Enhanced Application (refactored with mining_shares/p2p_shares separation)
add_executable(c2pool c2pool_refactored.cpp)
target_link_libraries(c2pool 
    c2pool_node_enhanced
    core
    ltc
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)

# Enhanced version with explicit name (for backward compatibility)
add_executable(c2pool_enhanced c2pool_refactored.cpp)
target_link_libraries(c2pool_enhanced 
    c2pool_node_enhanced
    core
    ltc
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)

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