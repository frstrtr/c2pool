# V37 payout economics — CarriageGate + FeeFloorGate standalone KAT
# (src/c2pool/v37/payout/carriage.hpp).
#
# Stdlib-only, self-contained harness (nonzero exit on failure), the same
# convention as ../../../roundabout/test/. Pulled in from
# src/c2pool/v37/test/CMakeLists.txt (add_subdirectory with an explicit binary
# dir) so src/c2pool/CMakeLists.txt is untouched. HOLLOW-GREEN GUARD: the target
# below is ALSO listed on BOTH build.yml --target lists (Linux x86_64 leg +
# ASan/UBSan leg) so CI compiles AND runs it; tools/ci/check_test_target_allowlist.py's
# src/c2pool/**/test/ glob covers this file.
#
#   v37_payout_carriage_kat   capacity-based carriage bonus + h_min_dyn fee floor
if (BUILD_TESTING)
    add_executable(v37_payout_carriage_kat v37_payout_carriage_kat.cpp)
    target_compile_features(v37_payout_carriage_kat PRIVATE cxx_std_20)
    target_include_directories(v37_payout_carriage_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_payout_carriage_kat Threads::Threads)
    add_test(NAME v37_payout_carriage_kat COMMAND v37_payout_carriage_kat)
endif()
