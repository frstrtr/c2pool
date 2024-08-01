add_library(ltc_coin_impl 
    p2p.hpp
    rpc.hpp rpc.cpp
)

target_link_libraries(ltc_coin_impl core nlohmann_json::nlohmann_json)