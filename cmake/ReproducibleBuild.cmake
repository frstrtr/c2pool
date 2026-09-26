# Reproducible-build path hygiene (docs/xmr-lane/REPRODUCIBLE-BUILD.md).
#
# A Release binary must not depend on WHERE it was built: the source checkout,
# the build dir and the Conan cache ($CONAN_HOME, i.e. the builder's $HOME) are
# host-specific absolute paths. The compiler bakes them into the output through
# __FILE__ (Boost.Asio / Boost.Multiprecision throw sites record their header
# path in boost::source_location), through debug info when -g is on, and through
# the linker's build RUNPATH. Remapping them to fixed prefixes makes two builds
# of one commit byte-identical wherever they were checked out.
#
# Only the RECORDED path strings change (e.g. "conan-home/p/boost.../asio/..."
# instead of "/home/<user>/.conan2/p/boost.../asio/..."); the code, the
# optimisation flags and every runtime path lookup stay exactly as they were.
# -fmacro-prefix-map (implied by -ffile-prefix-map) only rewrites __FILE__ /
# __BASE_FILE__, never an ordinary string literal or compile definition, so
# tests that locate data through a -D<dir>="${CMAKE_SOURCE_DIR}/..." define are
# unaffected.
#
# Included from the top-level CMakeLists.txt right after project(), before any
# add_subdirectory(), so the options reach every target (vendored RandomX too).
option(C2POOL_REPRODUCIBLE_PATHS
    "Remap source/build/Conan-cache absolute paths in compiled output (reproducible builds)" ON)

if (C2POOL_REPRODUCIBLE_PATHS AND NOT MSVC
    AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-ffile-prefix-map=/c2pool-probe=." C2POOL_HAVE_FILE_PREFIX_MAP)
    if (C2POOL_HAVE_FILE_PREFIX_MAP)
        # Conan 2 cache root(s): every package folder the CMakeToolchain puts on
        # the include/library search path is <CONAN_HOME>/p/[b/]<pkg>/p/{include,lib}.
        # The <pkg> folder name is derived from the reference + package id, so it
        # is the same in every Conan home holding the same package revision.
        set(_c2pool_conan_homes "")
        foreach (_d IN LISTS CMAKE_INCLUDE_PATH CMAKE_LIBRARY_PATH)
            if (_d MATCHES "^(.+)/p/(b/)?[^/]+/p/(include|lib)$")
                list(APPEND _c2pool_conan_homes "${CMAKE_MATCH_1}")
            endif()
        endforeach()
        list(REMOVE_DUPLICATES _c2pool_conan_homes)
        foreach (_h IN LISTS _c2pool_conan_homes)
            add_compile_options("-ffile-prefix-map=${_h}=conan-home")
        endforeach()
        # Source dir first, build dir last: GCC applies the LAST matching map, so
        # a build dir nested inside the source tree still maps to ".".
        add_compile_options("-ffile-prefix-map=${CMAKE_SOURCE_DIR}=."
                            "-ffile-prefix-map=${CMAKE_BINARY_DIR}=.")
        message(STATUS "Reproducible paths: source/build dirs -> '.', "
                       "Conan home(s) [${_c2pool_conan_homes}] -> 'conan-home'")
    endif()
endif()
