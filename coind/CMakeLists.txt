#jsonrpc-coind
set(CURL_LIBRARY "-lcurl")
find_package(CURL REQUIRED)

set(jsonrpc_sources 
        jsonrpc/coind.h 
        jsonrpc/requests.h 
        #jsonrpc/results.h 
        jsonrpc/coind.cpp)

add_library(coind_jsonrpc STATIC ${jsonrpc_sources})
target_link_libraries(coind_jsonrpc univalue btclibs util networks ${CURL_LIBRARIES})
target_include_directories(coind_jsonrpc PRIVATE ${CURL_INCLUDE_DIR})

#coind_tool
set(coind_tool_sources 
        data.h
        data.cpp)

add_library(coind_tool STATIC ${coind_tool_sources})
target_link_libraries(coind_tool btclibs devcore)