set(HEADER_FILES pystruct.h types.h events.h)
set(SOURCE_FILES pystruct.cpp types.cpp)

add_library(util STATIC ${SOURCE_FILES} ${HEADER_FILES})
message("py3_lib = ${Python3_LIBRARIES}")
target_link_libraries(util devcore univalue ${Python3_LIBRARIES} #[[sharechain]])