add_subdirectory(coin)

add_library(btc
    config_coin.hpp config_coin.cpp config_pool.hpp config_pool.cpp config.hpp
    node.hpp node.cpp
    peer.hpp
    protocol_actual.cpp protocol_legacy.cpp
    messages.hpp
    share_types.hpp share.hpp
)

target_link_libraries(btc core pool sharechain btc_coin btclibs c2pool_storage ${SECP256K1_LIBRARIES})

# add_subdirectory(test)  # B0: disabled — share_test.cpp references LTC types, restore in later phase