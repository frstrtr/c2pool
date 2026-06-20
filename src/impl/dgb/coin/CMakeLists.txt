# dgb_coin -- DGB coin-layer library.
# Mirrors src/impl/btc/coin/CMakeLists.txt. Phase A (#82) adds the embedded
# P2P + mempool layer (non-MWEB, btc-shaped; Scrypt PoW lives in header_chain).
# NOT yet referenced by any add_subdirectory(): top-level registration of
# src/impl/dgb follows the ci-steward OBJECT-lib convention (see ../CMakeLists.txt);
# staged here so that wiring is a one-line flip.

set(dgb_coin_impl
    rpc_data.hpp
    rpc.hpp rpc.cpp
    rpc_conf.hpp
    rpc_request.hpp
    softfork_check.hpp
    p2p_connection.hpp p2p_connection.cpp
    p2p_node.cpp p2p_node.hpp
    p2p_messages.hpp
    node.hpp
    coin_node.hpp coin_node.cpp
)

set(dgb_coin_interface
    txidcache.hpp
    node_interface.hpp
    block.hpp
    transaction.hpp transaction.cpp
    compact_blocks.hpp
    header_chain.hpp
    mempool.hpp
    template_builder.hpp
    embedded_coinbase_value.hpp
    embedded_coin_node.hpp
    embedded_tx_select.hpp embedded_tx_select.cpp
)

add_library(dgb_coin ${dgb_coin_interface} ${dgb_coin_impl})

target_link_libraries(dgb_coin core nlohmann_json::nlohmann_json)
