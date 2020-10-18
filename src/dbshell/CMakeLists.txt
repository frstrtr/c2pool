project(dbshell)

include_directories(../univalue)
include_directories(../leveldb)

set(HEADER 
    db.h
    dbObject.h
    dbBatch.h
)
set(SOURCE
    db.cpp
    dbObject.cpp
    dbBatch.cpp
)

add_library(dbshell ${HEADER} ${SOURCE})

target_link_libraries(dbshell univalue leveldb)

# target_include_directories(dbshell)