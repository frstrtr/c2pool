project(pylib)

set(HEADER_FILES py_base.h)
set(SOURCE_FILES py_base.cpp)

find_package(Python3 REQUIRED Development) #cmake --help-module FindPython
message("
    PyLibs:
    Python3_INCLUDE_DIRS=${Python3_INCLUDE_DIRS}
    Python3_LIBRARIES=${Python3_LIBRARIES}
")

add_library(pylib STATIC ${SOURCE_FILES} ${HEADER_FILES})

target_link_libraries(pylib other)
target_include_directories(pylib PUBLIC ${Python3_INCLUDE_DIRS})
target_link_libraries(pylib ${Python3_LIBRARIES})