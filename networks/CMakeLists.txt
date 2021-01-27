file(GLOB coind_networks "coind_networks/*.cpp")

add_library(networks network.h network.cpp ${coind_networks})
target_link_libraries(networks btclibs)