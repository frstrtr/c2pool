file(GLOB sources "*.h" "*.cpp")

#todo: remove when fix #include <Python3.h>
get_filename_component(full_path_pylib_h ${CMAKE_CURRENT_SOURCE_DIR}/devcode/py_base.h ABSOLUTE)
get_filename_component(full_path_pylib_cpp ${CMAKE_CURRENT_SOURCE_DIR}/devcode/py_base.cpp ABSOLUTE)
message("from sources in devcore removed: ${full_path_pylib_cpp}")
message("from sources in devcore removed: ${full_path_pylib_h}")
list(REMOVE_ITEM sources "${full_path_pylib_h}")
list(REMOVE_ITEM sources "${full_path_pylib_cpp}")
#==============

add_library(devcore ${sources})
target_link_libraries(devcore Boost::log ${Python3_LIBRARIES})

target_compile_definitions(devcore PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")