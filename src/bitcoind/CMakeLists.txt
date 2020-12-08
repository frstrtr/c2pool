project(bitcoind)

include_directories(../univalue)
include_directories(../btclibs)
include_directories(../util)
include_directories(../pylib)

set(CURL_LIBRARY "-lcurl")
find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})

#TODO: MOVE jsonrpc-bitcoind to lib



set(HEADER_FILES data.h 
    jsonrpc-bitcoind/bitcoind.h jsonrpc-bitcoind/requests.h jsonrpc-bitcoind/results.h)
set(SOURCE_FILES data.cpp 
    jsonrpc-bitcoind/bitcoind.cpp)


add_library(bitcoind STATIC ${SOURCE_FILES} ${HEADER_FILES})
target_link_libraries(bitcoind univalue btclibs util pylib ${CURL_LIBRARIES})