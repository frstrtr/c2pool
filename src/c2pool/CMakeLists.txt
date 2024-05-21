add_executable(c2pool c2pool.cpp)
target_link_libraries(c2pool core btclibs)
target_link_libraries(c2pool nlohmann_json::nlohmann_json)

add_executable(c2pool_temp c2pool_temp.cpp)
target_link_libraries(c2pool_temp core btclibs pool pool_ltc)
target_link_libraries(c2pool_temp nlohmann_json::nlohmann_json)