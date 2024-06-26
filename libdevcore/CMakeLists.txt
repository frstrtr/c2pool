# file(GLOB devcore_sources "*.h" "*.cpp")

#from devcore
set(devcore_sources addr_store.h addr_store.cpp common.h common.cpp config.h config.cpp
    filesystem.h filesystem.cpp logger.h logger.cpp random.h random.cpp str.h str.cpp)

#from dbshell
set(devcore_sources ${devcore_sources} db.h)

#from util
set(devcore_sources ${devcore_sources} types.h disposable.h events.h timer.h stream.h stream_types.h math.h deferred.h types.cpp math.cpp expiring_dict.h)

# find_library(leveldb NAMES leveldb)
# find_path(LEVELDB_INCLUDE_DIR leveldb/db.h /us include)

# hunter_add_package(leveldb)
find_package(leveldb REQUIRED)

add_library(libdevcore STATIC ${devcore_sources})
target_link_libraries(libdevcore Boost::coroutine Boost::log Boost::log_setup)
if (NOT WIN32) # for not windows
    find_library(dl NAMES dl)
    target_link_libraries(libdevcore dl)
endif ()
target_link_libraries(libdevcore btclibs Threads::Threads leveldb)
target_link_libraries(libdevcore nlohmann_json::nlohmann_json)

target_compile_definitions(libdevcore PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")