project(p2p)

include_directories(../other)

set(HEADER_FILES p2p.h factory.h node.h protocol.h)
set(SOURCE_FILES factory.cpp node.cpp protocol.cpp)

add_library(p2p STATIC ${SOURCE_FILES} ${HEADER_FILES})
