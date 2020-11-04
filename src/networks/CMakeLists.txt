project(networks)

include_directories(../btclibs)


set(HEADER_FILES config.h)
set(SOURCE_FILES config.cpp)

add_library(networks STATIC ${HEADER_FILES} ${SOURCE_FILES})

target_link_libraries(networks btclibs)
