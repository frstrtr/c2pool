add_executable(c2pool_main c2pool.cpp coind_master.h)
target_link_libraries(c2pool_main Boost::asio Boost::program_options libnet devcore networks sharechains)