# Boost header-integrity + version sentinel. Gated into every CI lane right
# after conan install + configure, before the main build: a torn/mixed Boost
# tree or an apt-Boost fallback fails HERE (fast, one TU) instead of deep in
# the coin build. Boost::log / Boost::log_setup are found at the root scope.
add_executable(boost_sentinel boost_sentinel.cpp)
target_compile_features(boost_sentinel PRIVATE cxx_std_20)
target_link_libraries(boost_sentinel PRIVATE Boost::log Boost::log_setup)
add_test(NAME boost_sentinel COMMAND boost_sentinel)
