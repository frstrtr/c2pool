# dash::stratum module -- concrete core::stratum::IWorkSource implementation for
# c2pool-dash (DASH X11, V36). Bridges the coin-agnostic core::StratumServer
# (TCP, JSON-RPC, sessions, vardiff, rate monitor) to DASH work generation +
# share validation: the fused get_work() capstone (#698) sources a base template
# off the node-held NodeCoinState (embedded arm) or the RETAINED dashd GBT RPC
# fallback ([GBT-XCHECK], never removed), and the 4d hot path runs the X11 PoW.
#
# OBJECT lib (mirrors src/impl/dash/CMakeLists.txt add_library(dash OBJECT ...)):
# the work-source TU compiles against the header-only coin selector + get_work
# capstone; only c2pool-dash (and the test_dash_stratum_work_source KAT) link the
# objects in, so ltc/btc/doge/dgb build + ctest surfaces stay untouched.
# SAFE-ADDITIVE, per-coin isolation held: src/impl/dash only, dashd RPC fallback
# preserved. Stage 4b: bodies landed (getters + registry + get_work adapter real;
# X11 work-assembly + share-validation held at safe defaults for 4c/4d).
add_library(dash_stratum OBJECT
    work_source.hpp work_source.cpp
)
target_include_directories(dash_stratum PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/btclibs
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(dash_stratum core dash_x11 nlohmann_json::nlohmann_json ${Boost_LIBRARIES})
