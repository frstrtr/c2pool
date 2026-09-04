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
endif()
