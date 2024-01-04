if(${Qt6Widgets_FOUND})
    set(C2POOL_UI c2pool_main_menu.h ui/configure_window.h ui/main_menu.h)
elseif ()
    set(C2POOL_UI "")
endif ()

add_executable(c2pool_main c2pool.cpp
                        coind_master.h c2pool_version.h ${C2POOL_UI}
                        node_manager.h node_manager.cpp)

if(${Qt6Widgets_FOUND})
    target_compile_definitions(c2pool_main PUBLIC C2POOL_UI_USE)
endif()

target_link_libraries(c2pool_main Boost::program_options libnet libdevcore networks sharechains web_interface)
target_link_libraries(c2pool_main Qt6::Core Qt6::Network)

if(${Qt6Widgets_FOUND})
    target_link_libraries(c2pool_main Qt6::Widgets)
endif()

if(${Qt6Gui_FOUND})
    target_link_libraries(c2pool_main Qt6::Gui)
endif()

target_compile_definitions(c2pool_main PRIVATE C2POOL_MAJOR=${ver_major})
target_compile_definitions(c2pool_main PRIVATE C2POOL_MINOR=${ver_minor})
target_compile_definitions(c2pool_main PRIVATE C2POOL_PATCH=${ver_patch})

set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/web)
file(REMOVE_RECURSE ${CMAKE_CURRENT_BINARY_DIR}/web)
file(COPY ${SOURCE_DIR} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

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

#exp
add_executable(net_parser exp/network_parser.cpp)
target_link_libraries(net_parser networks Boost::program_options btclibs)

add_executable(args_parser exp/args_parser.cpp)
target_link_libraries(args_parser networks Boost::program_options btclibs)

add_executable(logs_filter exp/logs_filter.cpp)
target_link_libraries(logs_filter networks Boost::program_options btclibs)

add_executable(logs_filter2 exp/logs_filter2.cpp)
target_link_libraries(logs_filter2 networks Boost::program_options btclibs)