project(util)

set(HEADER_FILES #[[pack.h]] pystruct.h filesys.h messages.h types.h)

set(SOURCE_FILES #[[pack.cpp]] pystruct.cpp filesys.cpp messages.cpp types.cpp)

add_library(util STATIC ${SOURCE_FILES} ${HEADER_FILES})

target_compile_definitions(util PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")
target_include_directories(util PUBLIC ${Python3_INCLUDE_DIRS} ${Python3_INCLUDE_DIR})
target_link_libraries(util ${Python3_LIBRARIES})