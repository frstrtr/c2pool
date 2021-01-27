set(HEADER_FILES pystruct.h messages.h types.h events.h)
set(SOURCE_FILES pystruct.cpp messages.cpp types.cpp)

add_library(util STATIC ${SOURCE_FILES} ${HEADER_FILES})
target_link_libraries(util pylib other univalue ${Python3_LIBRARIES} #[[sharechain]])