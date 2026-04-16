# bitcoin_family: shared library for Bitcoin-derived coins (LTC, BTC, DOGE, Dash)
# Contains coin-agnostic types: block/tx structures, P2P messages, share types, peer

add_library(bitcoin_family
    coin/transaction.cpp
    coin/p2p_connection.cpp
)

target_include_directories(bitcoin_family PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(bitcoin_family PUBLIC
    core
    btclibs
)
