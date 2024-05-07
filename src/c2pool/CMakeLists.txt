add_executable(c2pool c2pool.cpp)
target_link_libraries(c2pool a btclibs)
target_link_libraries(c2pool nlohmann_json::nlohmann_json )