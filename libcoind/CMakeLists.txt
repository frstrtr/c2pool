set(coind_tool_sources 
        data.h
        data.cpp
        types.h
        transaction.h
        transaction.cpp
        height_tracker.h
        jsonrpc/jsonrpc_coind.h
        jsonrpc/jsonrpc_coind.cpp
        jsonrpc/txidcache.h

        jsonrpc/stratum.h
        jsonrpc/stratum.cpp
        jsonrpc/stratum_protocol.h
        jsonrpc/stratum_protocol.cpp
        )

set(jsonrpc_sources 
#        jsonrpc/coind.h
        jsonrpc/requests.h 
        jsonrpc/results.h 
#        jsonrpc/coind.cpp
        )

set(coind_p2p_sources
        p2p/coind_messages.h
#        p2p/messages.h
#        p2p/messages.cpp
#        p2p/p2p_protocol.h
#        p2p/p2p_protocol.cpp
#        p2p/p2p_socket.h
#        p2p/p2p_socket.cpp
        )

set(coind_sources ${coind_tool_sources} ${jsonrpc_sources} ${coind_p2p_sources})

#set(CURL_LIBRARY "-lcurl")
#find_package(CURL REQUIRED)

add_library(libcoind STATIC ${coind_sources})
target_link_libraries(libcoind btclibs libdevcore networks univalue jsonrpccxx libp2p) # ${CURL_LIBRARIES})
#target_include_directories(libcoind PRIVATE ${CURL_INCLUDE_DIR})