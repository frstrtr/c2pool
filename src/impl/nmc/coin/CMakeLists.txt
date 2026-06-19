# NMC coin tree — P0 structural leaf.
# Mirror of src/impl/btc/coin/CMakeLists.txt (header-only interface files +
# a translation unit that forces them to compile). STRUCTURE-only: no node /
# rpc / p2p layers yet.

set(nmc_coin_interface
    transaction.hpp transaction.cpp
    block.hpp
    mempool.hpp
    header_chain.hpp
    rpc_data.hpp
    template_builder.hpp
    coin_smoke.cpp
)

add_library(nmc_coin ${nmc_coin_interface})

target_link_libraries(nmc_coin core nlohmann_json::nlohmann_json)
