add_library(pylib STATIC py_base.cpp py_base.h)

target_link_libraries(pylib other ${Python3_LIBRARIES})