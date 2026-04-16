
set(ltc_coin_impl
    rpc.hpp rpc.cpp
    p2p_node.cpp p2p_node.hpp
    node.hpp
)

set(ltc_coin_interface
    node_interface.hpp
    # Forwarding headers (real types in bitcoin_family)
    txidcache.hpp
    block.hpp
    transaction.hpp
    rpc_data.hpp
    p2p_connection.hpp
    p2p_messages.hpp
    softfork_check.hpp
)

add_library(ltc_coin ${ltc_coin_interface} ${ltc_coin_impl})

target_link_libraries(ltc_coin core bitcoin_family nlohmann_json::nlohmann_json)
