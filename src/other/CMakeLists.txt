project(other)

set(HEADER_FILES other.h)
set(SOURCE_FILES log.cpp converter.cpp other.cpp)

add_library(other STATIC ${SOURCE_FILES} ${HEADER_FILES})
