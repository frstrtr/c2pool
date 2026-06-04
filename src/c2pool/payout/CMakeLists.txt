# C2Pool Payout Management Library
add_library(c2pool_payout OBJECT
    payout_manager.cpp
)

target_include_directories(c2pool_payout PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
    ${CMAKE_CURRENT_SOURCE_DIR}/../../..
)

target_link_libraries(c2pool_payout
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
    # payout_manager.cpp uses <core/log.hpp> (LOG_* -> Boost.Log trivial). This OBJECT
    # lib deliberately does not link core (SCC break), so it must carry the Boost.Log
    # usage requirement itself via the imported targets. ${Boost_LIBRARIES} alone does
    # not reliably resolve the log component through ld64 static archives on AppleClang
    # arm64 (GCC/MSVC tolerated it); name Boost::log/log_setup explicitly (#22/#39).
    Boost::log
    Boost::log_setup
    btclibs
)

# Ensure headers are available
target_include_directories(c2pool_payout INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
