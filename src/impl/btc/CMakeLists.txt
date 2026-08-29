add_subdirectory(coin)
add_subdirectory(stratum)

add_library(btc
    config_coin.hpp config_coin.cpp config_pool.hpp config_pool.cpp config.hpp
    node.hpp node.cpp
    peer.hpp
    protocol_actual.cpp protocol_legacy.cpp
    messages.hpp
    share_types.hpp share.hpp
)

target_link_libraries(btc core pool sharechain btc_coin btclibs c2pool_storage c2pool_hashrate ${SECP256K1_LIBRARIES})  # OBJECT-lib SCC direct-naming (#22/#39) — vardiff/HashrateTracker link fix

add_subdirectory(test)  # btc_share_test enabled — F11 value-invariance KAT (twin of ltc share_test, uniquely named to avoid CMP0002)