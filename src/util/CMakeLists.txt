project(util)

set(HEADER_FILES #[[pack.h]] pystruct.h file.h)

set(SOURCE_FILES #[[pack.cpp]] pystruct.cpp file.cpp )

add_library(util STATIC ${SOURCE_FILES} ${HEADER_FILES})


target_include_directories(util PUBLIC ${Python3_INCLUDE_DIRS} ${Python3_INCLUDE_DIR})
target_link_libraries(util ${Python3_LIBRARIES})