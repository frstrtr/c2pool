set(sources 
    uint256.h
    uint256.cpp
    tinyformat.h
    attributes.h
    arith_uint256.h
    arith_uint256.cpp
    util/str.h
    util/str.cpp
    util/strencodings.h
    util/strencodings.cpp
    crypto/common.h
    compat/byteswap.h
    compat/endian.h
    )

add_library(btclibs ${sources}) #${SOURCE} ${HEADER})
target_include_directories(btclibs PUBLIC util crypto compat)