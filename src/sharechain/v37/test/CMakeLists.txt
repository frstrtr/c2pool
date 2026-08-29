# V37 MRR roundabout — standalone unit tests.
# Header-only module, stdlib-only: no gtest, no core link needed. The suite
# is its own harness (returns nonzero on failure) so it runs anywhere the
# toolchain exists, including outside the conan/boost dependency tree.
if (BUILD_TESTING)
    add_executable(v37_test v37_test.cpp)
    target_compile_features(v37_test PRIVATE cxx_std_20)
    add_test(NAME v37_test COMMAND v37_test)
endif()
