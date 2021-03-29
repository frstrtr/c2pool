file(GLOB sources_coind_networks "coind_networks/*.cpp")

add_library(networks network.h network.cpp ${sources_coind_networks})
target_include_directories(networks PUBLIC coind_networks)
target_link_libraries(networks btclibs coind_jsonrpc)