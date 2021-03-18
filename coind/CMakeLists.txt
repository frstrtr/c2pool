set(CURL_LIBRARY "-lcurl")
find_package(CURL REQUIRED)
#TODO: MOVE jsonrpc-coind to lib

set(HEADER_FILES data.h 
    jsonrpc-coind/coind.h jsonrpc-coind/requests.h jsonrpc-coind/results.h)
set(SOURCE_FILES data.cpp 
    jsonrpc-coind/coind.cpp)


add_library(coind STATIC ${SOURCE_FILES} ${HEADER_FILES})
target_link_libraries(coind univalue btclibs util devcore ${CURL_LIBRARIES})
target_include_directories(coind PRIVATE ${CURL_INCLUDE_DIR})