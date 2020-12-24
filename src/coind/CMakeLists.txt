project(coind)

include_directories(../univalue)
include_directories(../btclibs)
include_directories(../util)
include_directories(../pylib)

set(CURL_LIBRARY "-lcurl")
find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})

#TODO: MOVE jsonrpc-coind to lib



set(HEADER_FILES data.h 
    jsonrpc-coind/coind.h jsonrpc-coind/requests.h jsonrpc-coind/results.h)
set(SOURCE_FILES data.cpp 
    jsonrpc-coind/coind.cpp)


add_library(coind STATIC ${SOURCE_FILES} ${HEADER_FILES})
target_link_libraries(coind univalue btclibs util pylib ${CURL_LIBRARIES})