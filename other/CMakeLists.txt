set(HEADER_FILES other.h)
set(SOURCE_FILES converter.cpp other.cpp)

add_library(other STATIC ${SOURCE_FILES} ${HEADER_FILES})

#target_compile_definitions(other PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\") #?
