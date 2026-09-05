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
endif()
