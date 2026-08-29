# bch::stratum module -- concrete IWorkSource implementation for c2pool-bch.
# Bridges core::StratumServer (coin-agnostic protocol layer) to BCH-specific
# work generation (template_builder), share validation, and the dual-path
# won-block broadcaster. Mirrors src/impl/btc/stratum. G2 pool-serve slice-c.

add_library(bch_stratum
    work_source.hpp work_source.cpp
)

target_link_libraries(bch_stratum
    core
    bch_coin
    btclibs
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)

# Include parent so #include <impl/bch/...> resolves
target_include_directories(bch_stratum PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)
