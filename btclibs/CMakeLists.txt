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
        util/spanparsing.cpp
        util/spanparsing.h
        compat/byteswap.h
        compat/endian.h
        compat/cpuid.h
        script/script.h
        script/script.cpp
        span.h
        base58.h
        base58.cpp
        serialize.h
        prevector.h
        ${crypto_sources}
        )

add_library(btclibs ${sources}) #${SOURCE} ${HEADER})
target_include_directories(btclibs PUBLIC util crypto compat)