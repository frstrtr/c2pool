project(other)

set(HEADER_FILES other.h)
set(SOURCE_FILES converter.cpp other.cpp)


set(Boost_USE_STATIC_LIBS ON)

add_library(other STATIC ${SOURCE_FILES} ${HEADER_FILES})

target_compile_definitions(other PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")

if(WIN32)
    target_link_libraries(other ws2_32) #возник баг, без этого не компилится boost код.
    target_link_libraries(other wsock32) #возник баг, без этого не компилится boost код.
endif()
