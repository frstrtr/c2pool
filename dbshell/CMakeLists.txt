set(HEADER 
    db.h
    dbObject.h
    dbBatch.h
)
set(SOURCE
    db.cpp
    dbBatch.cpp
)

add_library(dbshell ${HEADER} ${SOURCE})
target_link_libraries(dbshell PUBLIC univalue leveldb devcore)