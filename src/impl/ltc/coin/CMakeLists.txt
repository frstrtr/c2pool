
set(ltc_coin_impl 
    rpc_data.hpp
    rpc.hpp rpc.cpp
    p2p_connection.hpp p2p_connection.cpp
    p2p_node.cpp p2p_node.hpp 
    p2p_messages.hpp
    node.hpp
)

set(ltc_coin_interface
    txidcache.hpp
    node_interface.hpp
    block.hpp
    transaction.hpp transaction.cpp
)


add_library(ltc_coin ${ltc_coin_interface} ${ltc_coin_impl})

target_link_libraries(ltc_coin core nlohmann_json::nlohmann_json)