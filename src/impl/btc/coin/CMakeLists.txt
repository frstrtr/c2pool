
set(btc_coin_impl 
    rpc_data.hpp
    rpc.hpp rpc.cpp
    p2p_connection.hpp p2p_connection.cpp
    p2p_node.cpp p2p_node.hpp 
    p2p_messages.hpp
    node.hpp
)

set(btc_coin_interface
    txidcache.hpp
    node_interface.hpp
    block.hpp
    transaction.hpp transaction.cpp
    header_chain.hpp
    mempool.hpp
    template_builder.hpp
)


add_library(btc_coin ${btc_coin_interface} ${btc_coin_impl})

target_link_libraries(btc_coin core nlohmann_json::nlohmann_json)