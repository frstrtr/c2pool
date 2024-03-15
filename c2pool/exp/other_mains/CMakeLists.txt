# tests
add_executable(coind_worker coind_worker.cpp)
target_link_libraries(coind_worker libcoind libnet libdevcore networks sharechains libp2ppreset)

add_executable(only_pool_node only_pool_node.cpp)
target_link_libraries(only_pool_node libnet libdevcore networks sharechains libp2ppreset)

add_executable(only_coind_node only_coind_node.cpp)
target_link_libraries(only_coind_node libcoind libnet libdevcore networks sharechains libp2ppreset)

add_executable(only_jsorpc_coind only_jsorpc_coind.cpp)
target_link_libraries(only_jsorpc_coind libcoind libnet libdevcore networks sharechains libp2ppreset)

add_executable(only_stratum only_stratum.cpp)
target_link_libraries(only_stratum libcoind)

add_executable(coind_n_pool coind_n_pool.cpp)
target_link_libraries(coind_n_pool libcoind libnet libdevcore networks sharechains libp2ppreset)