project(bitcoind)

include_directories(../btclibs)
include_directories(../util)

set(HEADER_FILES data.h)
set(SOURCE_FILES data.cpp)

add_library(bitcoind STATIC ${SOURCE_FILES} ${HEADER_FILES})
target_link_libraries(bitcoind btclibs util)