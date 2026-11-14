# linux_pkg_normalize_runpath.cmake — drop the build runner's paths from the
# RUNPATH of a staged Linux release package, leaving only the $ORIGIN entries.
#
#   cmake -DPKG_DIR=<c2pool-<coin>-<ver>-linux-x86_64> -P scripts/ci/linux_pkg_normalize_runpath.cmake
#
# Run after strip and before tar (release.yml, linux job, step "Package").
#
# The build tree links c2pool-<coin> with RUNPATH
#   $ORIGIN/lib:<Conan cache>/p/<pkg>/p/lib:...:<build dir>/src/impl/dash
# ($ORIGIN/lib first: cmake/LinuxPackageRunpath.cmake). The build-host entries
# are what the Package step's `ldd` needs to find libdash_scriptcheck.so in the
# build tree, but in the shipped file they only name directories of the runner
# (its user name and runner layout), which every loader lookup then probes on
# the user's host. Rewrite:
#   <PKG_DIR>/c2pool-*       -> $ORIGIN/lib
#   <PKG_DIR>/lib/*.so*      -> $ORIGIN   (only those that carry a RUNPATH at
#                                          all; the system copies ldd bundled
#                                          have none and need only glibc)
# CMake's own ELF editor (the one `cmake --install` uses) rewrites the existing
# DT_RUNPATH string in place, so no patchelf is needed on the runners. It cannot
# ADD a RUNPATH to a file that has none: a binary built without the CMake
# helper therefore fails here, by design, instead of shipping unloadable.
cmake_minimum_required(VERSION 3.21)  # file(RPATH_SET)

if (NOT PKG_DIR OR NOT IS_DIRECTORY "${PKG_DIR}")
    message(FATAL_ERROR "usage: cmake -DPKG_DIR=<staged package dir> -P ${CMAKE_CURRENT_LIST_FILE}")
endif()

function(_c2pool_runpath_of _file _out)
    file(READ_ELF "${_file}" RUNPATH _rp RPATH _rpath CAPTURE_ERROR _err)
    if (_err)
        message(FATAL_ERROR "${_file}: not a readable ELF file (${_err})")
    endif()
    if (NOT _rp)
        set(_rp "${_rpath}")
    endif()
    set(${_out} "${_rp}" PARENT_SCOPE)
endfunction()

file(GLOB _exes LIST_DIRECTORIES false "${PKG_DIR}/c2pool-*")
if (NOT _exes)
    message(FATAL_ERROR "${PKG_DIR}: no c2pool-<coin> executable")
endif()
foreach (_exe IN LISTS _exes)
    _c2pool_runpath_of("${_exe}" _rp)
    # The build must already have put $ORIGIN/lib there; finding it proves the
    # binary came from a tree with cmake/LinuxPackageRunpath.cmake.
    string(REPLACE ":" ";" _entries "${_rp}")
    if (NOT "$ORIGIN/lib" IN_LIST _entries)
        message(FATAL_ERROR "${_exe}: RUNPATH [${_rp}] has no $ORIGIN/lib entry "
                            "(built without cmake/LinuxPackageRunpath.cmake?)")
    endif()
    if (NOT _rp STREQUAL "$ORIGIN/lib")
        file(RPATH_SET FILE "${_exe}" NEW_RPATH "$ORIGIN/lib")
    endif()
endforeach()

file(GLOB _libs LIST_DIRECTORIES false "${PKG_DIR}/lib/*.so*")
foreach (_lib IN LISTS _libs)
    _c2pool_runpath_of("${_lib}" _rp)
    if (_rp AND NOT _rp STREQUAL "$ORIGIN")
        file(RPATH_SET FILE "${_lib}" NEW_RPATH "$ORIGIN")
    endif()
endforeach()
