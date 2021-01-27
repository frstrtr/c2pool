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