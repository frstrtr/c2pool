project(util)

set(HEADER_FILES pack.h)

set(SOURCE_FILES pack.cpp)

add_library(util STATIC ${SOURCE_FILES} ${HEADER_FILES})