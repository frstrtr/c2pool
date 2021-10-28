add_executable(c2pool_main c2pool.cpp 
                        coind_master.h 
                        node_manager.h node_manager.cpp)

target_link_libraries(c2pool_main Boost::program_options libnet libdevcore networks sharechains)