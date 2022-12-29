file(GLOB sources_networks "coind_networks/*.cpp" "pool_networks/*.cpp")
set(sources_networks ${sources_networks} coind_networks/dgb/digibyte_subsidy.cpp coind_networks/dgb/scrypt.h coind_networks/dgb/scrypt.c)

add_library(networks network.h network.cpp ${sources_networks})
target_include_directories(networks PUBLIC coind_networks pool_networks)
target_link_libraries(networks btclibs libcoind)