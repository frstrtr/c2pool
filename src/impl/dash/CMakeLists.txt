# Dash implementation module for c2pool
# X11 PoW + share v16 + masternode payment handling

# X11 crypto: pure C sph reference implementations (from dashcore v0.16.1.1)
set(DASH_X11_SOURCES
    crypto/x11/blake.c
    crypto/x11/bmw.c
    crypto/x11/cubehash.c
    crypto/x11/echo.c
    crypto/x11/groestl.c
    crypto/x11/jh.c
    crypto/x11/keccak.c
    crypto/x11/luffa.c
    crypto/x11/shavite.c
    crypto/x11/simd.c
    crypto/x11/skein.c
)

add_library(dash_x11 ${DASH_X11_SOURCES})
target_include_directories(dash_x11 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto/x11
)
# Pure C — no C++ flags needed
set_target_properties(dash_x11 PROPERTIES LINKER_LANGUAGE C)

# c2pool-dash binary: M3 proof-of-concept
add_executable(c2pool-dash main_dash.cpp)
target_include_directories(c2pool-dash PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)
target_link_libraries(c2pool-dash
    dash_x11
    core
    btclibs
    Boost::system
    Boost::thread
    Boost::log
    Boost::log_setup
)
