# C2Pool Payout Management Library
add_library(c2pool_payout
    payout_manager.cpp
)

target_include_directories(c2pool_payout PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
    ${CMAKE_CURRENT_SOURCE_DIR}/../../..
)

target_link_libraries(c2pool_payout
    nlohmann_json::nlohmann_json
)

# Ensure headers are available
target_include_directories(c2pool_payout INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
