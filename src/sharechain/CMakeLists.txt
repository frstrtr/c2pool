project(sharechain)

include_directories(../btclibs)

set(HEADER_FILES share.h sharechain.h shareStore.h shareTypes.h shareTracker.h)
set(SOURCE_FILES share.cpp sharechain.cpp shareStore.cpp shareTypes.cpp shareTracker.cpp)

add_library(sharechain STATIC ${SOURCE_FILES} ${HEADER_FILES})
target_link_libraries(sharechain btclibs)