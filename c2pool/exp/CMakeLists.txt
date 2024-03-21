#exp
add_executable(net_parser exp/network_parser.cpp)
target_link_libraries(net_parser networks Boost::program_options btclibs)

add_executable(args_parser exp/args_parser.cpp)
target_link_libraries(args_parser networks Boost::program_options btclibs)

add_executable(logs_filter exp/logs_filter.cpp)
target_link_libraries(logs_filter networks Boost::program_options btclibs)

add_executable(logs_filter2 exp/logs_filter2.cpp)
target_link_libraries(logs_filter2 networks Boost::program_options btclibs)