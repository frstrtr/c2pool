# file(GLOB devcore_sources "*.h" "*.cpp")

#from devcore
set(devcore_sources addrStore.h addrStore.cpp common.h common.cpp config.h config.cpp converter.cpp
    filesystem.h filesystem.cpp logger.h logger.cpp random.h random.cpp str.h str.cpp    
)

#from dbshell
set(devcore_sources ${devcore_sources} db.h dbObject.h dbBatch.h db.cpp dbBatch.cpp)

#from util
set(devcore_sources ${devcore_sources} types.h events.h prefsum.h stream.h stream_types.h math.h deferred.h types.cpp prefsum.cpp stream.cpp math.cpp deferred.cpp)
find_library(dl NAMES dl)

add_library(libdevcore ${devcore_sources})
target_link_libraries(libdevcore Boost::coroutine Boost::log Boost::log_setup univalue ${dl})
target_link_libraries(libdevcore btclibs Threads::Threads leveldb)

target_compile_definitions(libdevcore PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")