# V37 MRR roundabout — standalone unit tests.
# Header-only module, stdlib-only: no gtest, no core link needed. The suite
# is its own harness (returns nonzero on failure) so it runs anywhere the
# toolchain exists, including outside the conan/boost dependency tree.
if (BUILD_TESTING)
    add_executable(v37_test v37_test.cpp)
    target_compile_features(v37_test PRIVATE cxx_std_20)
    add_test(NAME v37_test COMMAND v37_test)

    # W1 lane-executor suite: the O1 message-passing wrapper over
    # Lane/Roundabout (differential vs direct, snapshot immutability,
    # surface audit, deterministic replay). Same stdlib-only harness.
    add_executable(v37_executor_test v37_executor_test.cpp)
    target_compile_features(v37_executor_test PRIVATE cxx_std_20)
    add_test(NAME v37_executor_test COMMAND v37_executor_test)

    # Family B (XMR lane) — PayoutDescriptor XMR_STD / XMR_SUB kind extension
    # (v37_descriptor_xmr.hpp, ADD-ONLY over the ratified canon). SHA-256-only,
    # no crypto backend: identity_key goldens for both kinds + fail-closed
    # torsion seam. Compiles against the REAL canon headers (v37_descriptor.hpp,
    # v37_hash.hpp) one directory up. Same stdlib-only harness.
    add_executable(v37_descriptor_xmr_test v37_descriptor_xmr_test.cpp)
    target_include_directories(v37_descriptor_xmr_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
    target_compile_features(v37_descriptor_xmr_test PRIVATE cxx_std_20)
    add_test(NAME v37_descriptor_xmr_test COMMAND v37_descriptor_xmr_test)

    # X3 (W2) torsion / prime-order KAT for the finalized descriptor point check.
    # Compiles the ref10 backend (v37_descriptor_xmr_point_check_ref10.cpp) under
    # -DV37_XMR_HAVE_MONERO_CRYPTO against the X1-vendored Monero crypto-ops (BSD-3,
    # reused NOT re-vendored) and PROVES the [L]P == 𝒪 subgroup test: it ACCEPTS
    # the basepoint / real clamped pubkeys and REJECTS every small-order point AND
    # a runtime-constructed MIXED (prime+torsion) point — the descriptor attack the
    # canon guards. The backend depends ONLY on ge_* (no monero/fcmp_pp — that is
    # FCMP-fenced to X6). STL + vendored C; NO RandomX. Self-contained (compiles
    # the vendored .c directly, order-independent of the xmr_coin target); compat/
    # first so crypto-ops.c's <sodium/crypto_verify_32.h> hits the authored shim.
    add_executable(xmr_torsion_kat
        xmr_torsion_kat.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../v37_descriptor_xmr_point_check_ref10.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor/crypto-ops.c
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor/crypto-ops-data.c)
    target_include_directories(xmr_torsion_kat PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor)
    target_compile_definitions(xmr_torsion_kat PRIVATE V37_XMR_HAVE_MONERO_CRYPTO _GNU_SOURCE)
    target_compile_features(xmr_torsion_kat PRIVATE c_std_11 cxx_std_20)
    add_test(NAME xmr_torsion_kat COMMAND xmr_torsion_kat)
endif()
