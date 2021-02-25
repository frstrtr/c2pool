add_executable(c2pool c2pool.cpp coind_master.h)
target_link_libraries(c2pool Boost::program_options libnet devcore networks)