project(util)

include_directories(../other)
include_directories(../univalue)

find_package(Python3 REQUIRED Development) #cmake --help-module FindPython
message("
    Python3_INCLUDE_DIRS=${Python3_INCLUDE_DIRS}
    Python3_LIBRARIES=${Python3_LIBRARIES}
")


set(HEADER_FILES pystruct.h filesys.h messages.h types.h events.h)
set(SOURCE_FILES pystruct.cpp filesys.cpp messages.cpp types.cpp)

add_library(util STATIC ${SOURCE_FILES} ${HEADER_FILES})

target_link_libraries(util other univalue)

target_compile_definitions(util PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")
target_include_directories(util PUBLIC ${Python3_INCLUDE_DIRS})
target_link_libraries(util ${Python3_LIBRARIES})