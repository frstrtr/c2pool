set(coind_tool_sources 
        data.h
        data.cpp
        types.h
        transaction.h
        transaction.cpp
        height_tracker.h
        # jsonrpc/jsonrpc_coind.h
        # jsonrpc/jsonrpc_coind.cpp
        jsonrpc/coindrpc.h jsonrpc/coindrpc.cpp
        jsonrpc/txidcache.h

        jsonrpc/stratum_node.h
        jsonrpc/stratum_node.cpp
        jsonrpc/stratum.h
        jsonrpc/stratum.cpp
        jsonrpc/stratum_protocol.h
        jsonrpc/stratum_protocol.cpp
)

set(jsonrpc_sources
        jsonrpc/requests.h 
        jsonrpc/results.h 
)

set(coind_p2p_sources
        p2p/coind_messages.h
        p2p/coind_socket.h p2p/coind_socket.cpp
        p2p/coind_protocol.h
        p2p/coind_protocol_data.h
)

set(coind_sources ${coind_tool_sources} ${jsonrpc_sources} ${coind_p2p_sources})

#set(CURL_LIBRARY "-lcurl")
#find_package(CURL REQUIRED)

add_library(libcoind STATIC ${coind_sources})
target_link_libraries(libcoind btclibs libdevcore networks univalue libp2p) # ${CURL_LIBRARIES})
#target_include_directories(libcoind PRIVATE ${CURL_INCLUDE_DIR})