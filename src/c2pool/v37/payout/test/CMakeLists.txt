# V37 payout economics — standalone KATs (src/c2pool/v37/payout/*.hpp).
#
# Stdlib-only, self-contained harness (nonzero exit on failure), the same
# convention as ../../test/ and ../../roundabout/test/. Pulled in from
# src/c2pool/v37/test/CMakeLists.txt (add_subdirectory with an explicit binary
# dir) so src/c2pool/CMakeLists.txt is untouched. HOLLOW-GREEN GUARD: every
# target below is ALSO listed on BOTH build.yml --target lists (Linux x86_64 leg
# + ASan/UBSan leg) so CI compiles AND runs it; the
# tools/ci/check_test_target_allowlist.py src/c2pool/**/test/ glob covers this
# file.
#
#   v37_payout_rule_l_kat   Rule L coinbase payout (P1 FIFO-feasible, reserve,
#                           sub-dust fold, P2/p2x top-ups, genesis P2')
if (BUILD_TESTING)
    # Explicit per-target blocks (no foreach): the allowlist guard resolves
    # literal add_executable names, so every KAT stays visible to it.
    add_executable(v37_payout_rule_l_kat v37_payout_rule_l_kat.cpp)
    target_compile_features(v37_payout_rule_l_kat PRIVATE cxx_std_20)
    target_include_directories(v37_payout_rule_l_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_payout_rule_l_kat Threads::Threads)
    add_test(NAME v37_payout_rule_l_kat COMMAND v37_payout_rule_l_kat)
endif()
