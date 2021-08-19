set(HEADER_FILES pystruct.h types.h events.h prefsum.h stream.h stream_types.h math.h)
set(SOURCE_FILES pystruct.cpp types.cpp prefsum.cpp stream.cpp)

add_library(util STATIC ${SOURCE_FILES} ${HEADER_FILES})
message("py3_lib = ${Python3_LIBRARIES}")
target_link_libraries(util devcore univalue ${Python3_LIBRARIES} btclibs)

#copy python script to build folder
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/packtypes.py ${CMAKE_BINARY_DIR}/scripts/packtypes.py COPYONLY)