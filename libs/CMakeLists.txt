add_subdirectory(googletest)


set(LEVELDB_BUILD_BENCHMARKS OFF)
set(LEVELDB_BUILD_TESTS OFF)
add_subdirectory(leveldb)

add_subdirectory(univalue)
add_subdirectory(jsonrpccxx)