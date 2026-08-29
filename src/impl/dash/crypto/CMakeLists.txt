# dash_x11 -- DASH X11 PoW hashing primitive (PR-0 foundation, S2 slice).
#
# Pure sph reference C (dashcore v0.16.1.1): BLAKE->BMW->GROESTL->SKEIN->JH->
# KECCAK->LUFFA->CUBEHASH->SHAVITE->SIMD->ECHO. Self-contained, additive static
# lib. The .c files quote-include their own sph_*.h (same dir); echo.c/groestl.c
# textually include aes_helper.c, so only the listed translation units compile.
# Sole C++ seam is the header-only hash_x11.hpp wrapper (core/uint256.hpp), which
# consumers pull in directly -- nothing links dash_x11 yet (consumed from S3 on).
add_library(dash_x11 STATIC
    x11/aes_helper.c
    x11/blake.c
    x11/bmw.c
    x11/cubehash.c
    x11/echo.c
    x11/groestl.c
    x11/jh.c
    x11/keccak.c
    x11/luffa.c
    x11/shavite.c
    x11/simd.c
    x11/skein.c
)

# hash_x11.hpp resolves <core/uint256.hpp> off the source root; expose it so
# downstream targets that link dash_x11 inherit the wrapper include path.
target_include_directories(dash_x11 PUBLIC ${CMAKE_SOURCE_DIR}/src)
