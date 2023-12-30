add_subdirectory(googletest)


set(LEVELDB_BUILD_BENCHMARKS OFF)
set(LEVELDB_BUILD_TESTS OFF)


add_subdirectory(univalue)
if (WIN32)
    add_subdirectory(leveldb)
endif ()