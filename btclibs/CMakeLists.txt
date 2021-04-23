file(GLOB crypto_sources "crypto/*.h" "crypto/*.cpp")

set(sources 
    uint256.h
    uint256.cpp
    tinyformat.h
    attributes.h
    arith_uint256.h
    arith_uint256.cpp
    hash.h
    hash.cpp
    util/str.h
    util/str.cpp
    util/strencodings.h
    util/strencodings.cpp
    compat/byteswap.h
    compat/endian.h
    compat/cpuid.h
    span.h
    ${crypto_sources}
    )

add_library(btclibs ${sources}) #${SOURCE} ${HEADER})
target_include_directories(btclibs PUBLIC util crypto compat)