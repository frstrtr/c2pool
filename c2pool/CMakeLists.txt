add_executable(c2pool c2pool.cpp config.h config.cpp)
target_link_libraries(c2pool Boost::program_options logging)