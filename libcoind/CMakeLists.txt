set(coind_tool_sources 
        data.h
        data.cpp
        types.h
        transaction.h
        transaction.cpp
        height_tracker.h
)

set(jsonrpc_sources
        jsonrpc/results.h
        jsonrpc/coindrpc.h 
        jsonrpc/coindrpc.cpp
        jsonrpc/txidcache.h
)

set(stratum_sources
        stratum/stratum_node.h
        stratum/stratum_node.cpp
        stratum/stratum.h
        stratum/stratum.cpp
        stratum/stratum_protocol.h
        stratum/stratum_protocol.cpp
)

set(coind_sources ${coind_tool_sources} ${jsonrpc_sources} ${stratum_sources})

#set(CURL_LIBRARY "-lcurl")
#find_package(CURL REQUIRED)

add_library(libcoind STATIC ${coind_sources})
target_link_libraries(libcoind btclibs libdevcore networks libp2p) # ${CURL_LIBRARIES})
#target_include_directories(libcoind PRIVATE ${CURL_INCLUDE_DIR})