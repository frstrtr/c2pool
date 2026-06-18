# DGB module tests. Mirrors src/impl/ltc/test/CMakeLists.txt — links the dgb
# OBJECT lib (pool/share TU) so the share codec + consensus params are build-
# verified into a test executable. Gated on BUILD_TESTING + GTest like the
# sibling coins; registered via gtest_add_tests for the CI --target allowlist.
if (BUILD_TESTING AND GTest_FOUND)
    add_executable(dgb_share_test share_test.cpp)
    target_link_libraries(dgb_share_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
    )
    # OBJECT-lib SCC direct-naming (#22/#39) — mirror the ltc test link set.
    target_link_libraries(dgb_share_test PRIVATE
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    gtest_add_tests(dgb_share_test "" AUTO)

    # --- M3 RPC-transport standalone regression guards ---------------------
    # Header-only guards over the external-daemon RPC coin-layer SSOTs
    # (rpc_request.hpp request-shape + version floor + genesis identity, and
    # softfork_check.hpp softfork-name collection). They link no OBJECT lib —
    # only GTest + nlohmann_json — so they stay buildable even while the
    # transport rpc.cpp wiring is deferred (Option-B scope). Each MUST appear
    # in BOTH this ctest registration AND the build.yml --target allowlist,
    # or it becomes a #143-style NOT_BUILT sentinel that reds master.
    foreach(dgb_guard rpc_request_test softfork_check_test genesis_check_test algo_select_test digishield_walk_test)
        add_executable(${dgb_guard} ${dgb_guard}.cpp)
        target_link_libraries(${dgb_guard} PRIVATE
            GTest::gtest_main GTest::gtest nlohmann_json::nlohmann_json)
        gtest_add_tests(${dgb_guard} "" AUTO)
    endforeach()

    # header_chain_test compiles the btclibs Scrypt PoW TU set DIRECTLY (the
    # same crypto/*.cpp sources btclibs builds, with the same default flags) so
    # the M3 7b digest conversion is exercised against the REAL
    # scrypt_1024_1_1_256 hash, not a synthetic digest. Only the scrypt + SHA256
    # family is pulled in -- NOT the full btclibs archive (its siphash.o needs
    # the removed base_uint<256> symbol) and NOT core/the dgb OBJECT lib. This
    # is linking against an existing scrypt.cpp, no shared source modified: the
    # single DGB smoke gate holds, no shared-base flag owed. Same target name,
    # so it stays in BOTH build.yml --target allowlists unchanged.
    set(_dgb_scrypt_tus
        ${CMAKE_SOURCE_DIR}/src/btclibs/crypto/scrypt.cpp
        ${CMAKE_SOURCE_DIR}/src/btclibs/crypto/sha256.cpp
        ${CMAKE_SOURCE_DIR}/src/btclibs/crypto/sha256_sse4.cpp
        ${CMAKE_SOURCE_DIR}/src/btclibs/crypto/sha256_sse41.cpp
        ${CMAKE_SOURCE_DIR}/src/btclibs/crypto/sha256_avx2.cpp
        ${CMAKE_SOURCE_DIR}/src/btclibs/crypto/sha256_shani.cpp)
    add_executable(header_chain_test header_chain_test.cpp ${_dgb_scrypt_tus})
    target_include_directories(header_chain_test PRIVATE ${CMAKE_SOURCE_DIR}/src/btclibs)
    target_link_libraries(header_chain_test PRIVATE
        GTest::gtest_main GTest::gtest nlohmann_json::nlohmann_json)
    gtest_add_tests(header_chain_test "" AUTO)
endif()
