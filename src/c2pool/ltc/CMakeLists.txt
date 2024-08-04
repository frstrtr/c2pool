add_executable(ltc_pool_test ltc_pool_test.cpp)
target_link_libraries(ltc_pool_test core btclibs ltc)
target_link_libraries(ltc_pool_test nlohmann_json::nlohmann_json)

add_executable(ltc_coin_test ltc_coin_test.cpp)
target_link_libraries(ltc_coin_test core btclibs pool ltc ltc_coin)
target_link_libraries(ltc_coin_test nlohmann_json::nlohmann_json)