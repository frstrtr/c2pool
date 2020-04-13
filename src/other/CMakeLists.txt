project(other)

#set(HEADER_FILES)
set(SOURCE_FILES log.cpp converter.cpp other.cpp)

add_library(other STATIC ${SOURCE_FILES})
