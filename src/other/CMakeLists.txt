project(other)

set(HEADER_FILES other.h console.h)
set(SOURCE_FILES log.cpp converter.cpp other.cpp console.cpp)

add_library(other STATIC ${SOURCE_FILES} ${HEADER_FILES})

if(WIN32)
    target_link_libraries(other ws2_32) #возник баг, без этого не компилится boost код.
    target_link_libraries(other wsock32) #возник баг, без этого не компилится boost код.
endif()
