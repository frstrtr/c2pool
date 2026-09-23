# V37 roundabout split S1-S5 — standalone KATs (src/c2pool/v37/roundabout/*.hpp).
#
# Stdlib-only, self-contained harness (nonzero exit on failure), the same
# convention as ../../test/. Pulled in from src/c2pool/v37/test/CMakeLists.txt
# (add_subdirectory with an explicit binary dir) so src/c2pool/CMakeLists.txt is
# untouched. HOLLOW-GREEN GUARD: every target below is ALSO listed on BOTH
# build.yml --target lists (Linux x86_64 leg + ASan/UBSan leg) so CI compiles
# AND runs it; tools/ci/check_test_target_allowlist.py's src/c2pool/**/test/
# glob covers this file.
#
#   v37_rb_stripe_kat      S3 stripe primitives + map-derivation structure
#   v37_rb_map_churn_kat   S3 churn + bounded-load measurement (prints numbers)
#   v37_rb_lane_tag_kat    S1 lane_tag + REJECT_ROUNDABOUT predicate
#   v37_rb_cb_class_kat    S2 cb_class byte budget (+ real W5 assemble)
#   v37_rb_checkpoint_kat  S4 summaries, merkle, CutTokenK, Σ-conservation
#   v37_rb_gate_off_kat    S5 RoundaboutGate default OFF + digest goldens
if (BUILD_TESTING)
    # Explicit per-target blocks (no foreach): the allowlist guard resolves
    # literal add_executable names, so every KAT stays visible to it.
    add_executable(v37_rb_stripe_kat v37_rb_stripe_kat.cpp)
    target_compile_features(v37_rb_stripe_kat PRIVATE cxx_std_20)
    target_include_directories(v37_rb_stripe_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_rb_stripe_kat Threads::Threads)
    add_test(NAME v37_rb_stripe_kat COMMAND v37_rb_stripe_kat)

    add_executable(v37_rb_map_churn_kat v37_rb_map_churn_kat.cpp)
    target_compile_features(v37_rb_map_churn_kat PRIVATE cxx_std_20)
    target_include_directories(v37_rb_map_churn_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_rb_map_churn_kat Threads::Threads)
    add_test(NAME v37_rb_map_churn_kat COMMAND v37_rb_map_churn_kat)

    add_executable(v37_rb_lane_tag_kat v37_rb_lane_tag_kat.cpp)
    target_compile_features(v37_rb_lane_tag_kat PRIVATE cxx_std_20)
    target_include_directories(v37_rb_lane_tag_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_rb_lane_tag_kat Threads::Threads)
    add_test(NAME v37_rb_lane_tag_kat COMMAND v37_rb_lane_tag_kat)

    add_executable(v37_rb_cb_class_kat v37_rb_cb_class_kat.cpp)
    target_compile_features(v37_rb_cb_class_kat PRIVATE cxx_std_20)
    target_include_directories(v37_rb_cb_class_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_rb_cb_class_kat Threads::Threads)
    add_test(NAME v37_rb_cb_class_kat COMMAND v37_rb_cb_class_kat)

    add_executable(v37_rb_checkpoint_kat v37_rb_checkpoint_kat.cpp)
    target_compile_features(v37_rb_checkpoint_kat PRIVATE cxx_std_20)
    target_include_directories(v37_rb_checkpoint_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_rb_checkpoint_kat Threads::Threads)
    add_test(NAME v37_rb_checkpoint_kat COMMAND v37_rb_checkpoint_kat)

    add_executable(v37_rb_gate_off_kat v37_rb_gate_off_kat.cpp)
    target_compile_features(v37_rb_gate_off_kat PRIVATE cxx_std_20)
    target_include_directories(v37_rb_gate_off_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_rb_gate_off_kat Threads::Threads)
    add_test(NAME v37_rb_gate_off_kat COMMAND v37_rb_gate_off_kat)
endif()
