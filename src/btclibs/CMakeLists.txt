project(btclibs)

set(HEADER 
    util/strencodings.h
    util/str.h
    crypto/common.h
    compat/endian.h
    compat/byteswap.h
    uint256.h
    attributes.h
    tinyformat.h
    arith_uint256.h
)
set(SOURCE
    util/strencodings.cpp
    util/str.cpp
    uint256.cpp
    arith_uint256.cpp
)

add_library(btclibs STATIC ${SOURCE} ${HEADER})

target_include_directories(btclibs PRIVATE util crypto compat)

# target_include_directories(bna PUBLIC STATIC)
# target_include_directories(bna PUBLIC include PRIVATE lib)


# project(univalue)

# set(HEADER include/univalue.h)
# set(SOURCE 
#     lib/univalue.cpp
#     lib/univalue_get.cpp
#     lib/univalue_read.cpp
#     lib/univalue_write.cpp
# )

# add_library(univalue ${HEADER} ${SOURCE})

# target_include_directories(univalue PUBLIC include PRIVATE lib)