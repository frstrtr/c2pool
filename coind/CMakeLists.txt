#jsonrpc-coind
set(CURL_LIBRARY "-lcurl")
find_package(CURL REQUIRED)

set(jsonrpc_sources 
        jsonrpc/coind.h 
        jsonrpc/requests.h 
        jsonrpc/results.h 
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

#coind_p2p
set(coind_p2p_sources
        p2p/converter.h
        p2p/converter.cpp
        p2p/messages.h
        p2p/messages.cpp
        p2p/p2p_protocol.h
        p2p/p2p_protocol.cpp
        p2p/p2p_socket.h
        p2p/p2p_socket.cpp
        p2p/pystruct.h
        p2p/pystruct.cpp)

message("py3_lib in coind::p2p = ${Python3_LIBRARIES} \n
        py3_include = ${Python3_INCLUDE_DIRS}
")
add_library(coind_p2p STATIC ${coind_p2p_sources})
target_link_libraries(coind_p2p ${Python3_LIBRARIES} devcore util btclibs)
target_include_directories(coind_p2p PUBLIC ${Python3_INCLUDE_DIRS})