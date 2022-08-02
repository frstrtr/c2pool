add_executable(c2pool_main c2pool.cpp 
                        coind_master.h 
                        node_manager.h node_manager.cpp)

target_link_libraries(c2pool_main Boost::program_options libnet2 libdevcore networks sharechains)

add_executable(coind_worker coind_worker.cpp)
target_link_libraries(coind_worker libcoind libnet2 libdevcore networks sharechains libp2ppreset)

add_executable(only_pool_node only_pool_node.cpp)
target_link_libraries(only_pool_node libnet2 libdevcore networks sharechains libp2ppreset)

add_executable(only_coind_node only_coind_node.cpp)
target_link_libraries(only_coind_node libcoind libnet2 libdevcore networks sharechains libp2ppreset)

add_executable(only_jsorpc_coind only_jsorpc_coind.cpp)
target_link_libraries(only_jsorpc_coind libcoind libnet2 libdevcore networks sharechains libp2ppreset)