set(coind_tool_sources 
        data.h
        data.cpp
        transaction.h
        transaction.cpp)

set(jsonrpc_sources 
        jsonrpc/coind.h 
        jsonrpc/requests.h 
        jsonrpc/results.h 
        jsonrpc/coind.cpp
        jsonrpc/stratum.h
        jsonrpc/stratum.cpp)

set(coind_p2p_sources
        p2p/messages.h
        p2p/messages.cpp
        p2p/p2p_protocol.h
        p2p/p2p_protocol.cpp
        p2p/p2p_socket.h
        p2p/p2p_socket.cpp)

set(coind_sources ${coind_tool_sources} ${jsonrpc_sources} ${coind_p2p_sources})

set(CURL_LIBRARY "-lcurl")
find_package(CURL REQUIRED)

add_library(coind STATIC ${coind_sources})
target_link_libraries(coind btclibs devcore networks univalue ${CURL_LIBRARIES})
target_include_directories(coind PRIVATE ${CURL_INCLUDE_DIR})