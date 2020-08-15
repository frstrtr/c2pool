project(p2p)

include_directories(../other)
include_directories(../networks)
include_directories(../util)

set(HEADER_FILES p2p.h factory.h node.h protocol.h)
set(SOURCE_FILES factory.cpp node.cpp protocol.cpp)

add_library(p2p STATIC ${SOURCE_FILES} ${HEADER_FILES})
target_link_libraries(p2p other networks util)

if(WIN32)
    target_link_libraries(p2p ws2_32) #возник баг, без этого не компилится boost код.
    target_link_libraries(p2p wsock32) #возник баг, без этого не компилится boost код.
endif()
