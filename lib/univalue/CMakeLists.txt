project(univalue)

set(HEADER include/univalue.h)
set(SOURCE 
    lib/univalue.cpp
    lib/univalue_get.cpp
    lib/univalue_read.cpp
    lib/univalue_write.cpp
)

add_library(univalue STATIC ${HEADER} ${SOURCE})

target_include_directories(univalue PUBLIC include PRIVATE lib)