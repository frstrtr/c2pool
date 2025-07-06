add_executable(c2pool_main c2pool.cpp)
target_link_libraries(c2pool_main core btclibs pool ltc sharechain)
target_link_libraries(c2pool_main nlohmann_json::nlohmann_json)

add_executable(test_ltc_node test_ltc_node.cpp)
target_link_libraries(test_ltc_node core btclibs pool ltc)
target_link_libraries(test_ltc_node nlohmann_json::nlohmann_json)

# add_executable(c2pool_temp c2pool_temp.cpp)
# target_link_libraries(c2pool_temp core btclibs pool ltc)
# target_link_libraries(c2pool_temp nlohmann_json::nlohmann_json)

add_executable(c2pool_node c2pool_node.cpp)
target_link_libraries(c2pool_node core btclibs pool ltc)
target_link_libraries(c2pool_node nlohmann_json::nlohmann_json)

add_subdirectory(ltc)