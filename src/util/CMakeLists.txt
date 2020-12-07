project(util)

include_directories(../pylib)
include_directories(../other)
include_directories(../univalue)
#include_directories(../sharechain)

set(HEADER_FILES pystruct.h messages.h types.h events.h)
set(SOURCE_FILES pystruct.cpp messages.cpp types.cpp)

find_package(Python3 REQUIRED Development) #cmake --help-module FindPython
message("
    PyLibs:
    Python3_INCLUDE_DIRS=${Python3_INCLUDE_DIRS}
    Python3_LIBRARIES=${Python3_LIBRARIES}
")

add_library(util STATIC ${SOURCE_FILES} ${HEADER_FILES})

target_link_libraries(util pylib other univalue #[[sharechain]])
target_include_directories(util PUBLIC ${Python3_INCLUDE_DIRS})
target_link_libraries(util ${Python3_LIBRARIES})