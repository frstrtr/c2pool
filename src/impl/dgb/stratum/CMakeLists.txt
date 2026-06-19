# dgb::stratum module — concrete IWorkSource implementation for c2pool-dgb.
# Bridges core::StratumServer (coin-agnostic protocol layer) to DGB's
# Scrypt template builder + sharechain + the #82 dual-path won-block
# broadcaster. Mirrors src/impl/btc/stratum/CMakeLists.txt. Stage 4a
# skeleton (work-gen/submit stubbed; 4b/4c/4d fill them in).

add_library(dgb_stratum
    work_source.hpp work_source.cpp
)

target_link_libraries(dgb_stratum
    core
    dgb_coin
    btclibs
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)

# Include parent so #include <impl/dgb/...> resolves
target_include_directories(dgb_stratum PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)
