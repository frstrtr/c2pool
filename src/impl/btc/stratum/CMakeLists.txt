# btc::stratum module — concrete IWorkSource implementation for c2pool-btc.
# Bridges core::StratumServer (coin-agnostic protocol layer) to BTC's
# template_builder + sharechain + B5 submit path. Stage 4 of B4-stratum.

add_library(btc_stratum
    work_source.hpp work_source.cpp
)

target_link_libraries(btc_stratum
    core
    btc_coin
    btclibs
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)

# Include parent so #include <impl/btc/...> resolves
target_include_directories(btc_stratum PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)
