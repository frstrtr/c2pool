project(sharechain)

# include_directories(../other)
# include_directories(../networks)
# include_directories(../util)
# include_directories(../univalue)

set(HEADER_FILES share.h sharechain.h shareTypes.h)
set(SOURCE_FILES share.cpp sharechain.cpp shareTypes.cpp)

add_library(p2p STATIC ${SOURCE_FILES} ${HEADER_FILES})
# target_link_libraries(p2p other networks util univalue)