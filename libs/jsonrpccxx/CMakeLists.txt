project(jsonrpccxx)
SET(JSONRPCCXX_FILES batchclient.hpp client.hpp common.hpp dispatcher.hpp iclientconnector.hpp server.hpp typemapper.hpp)

add_library(jsonrpccxx INTERFACE ${JSONRPCCXX_FILES})
include_directories(INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(jsonrpccxx INTERFACE nlohmann_json)