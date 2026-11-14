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

# <_out> = the file's DT_RUNPATH (else DT_RPATH) as a ;-list, "" if it has none.
# file(READ_ELF) does not touch an output variable whose entry the file lacks,
# and a function body sees its caller's variables, so every output is cleared
# first and named apart from the caller's: otherwise a library without a
# RUNPATH reads back the previous file's (the executable's) and gets rewritten.
function(_c2pool_runpath_of _file _out)
    set(_elf_runpath "")
    set(_elf_rpath "")
    set(_elf_error "")
    file(READ_ELF "${_file}" RUNPATH _elf_runpath RPATH _elf_rpath CAPTURE_ERROR _elf_error)
    if (_elf_error)
        message(FATAL_ERROR "${_file}: not a readable ELF file (${_elf_error})")
    endif()
    if (_elf_runpath STREQUAL "")
        set(_elf_runpath "${_elf_rpath}")
    endif()
    set(${_out} "${_elf_runpath}" PARENT_SCOPE)
endfunction()

file(GLOB _exes LIST_DIRECTORIES false "${PKG_DIR}/c2pool-*")
if (NOT _exes)
    message(FATAL_ERROR "${PKG_DIR}: no c2pool-<coin> executable")
endif()
foreach (_exe IN LISTS _exes)
    _c2pool_runpath_of("${_exe}" _exe_rp)
    # The build must already have put $ORIGIN/lib there; finding it proves the
    # binary came from a tree with cmake/LinuxPackageRunpath.cmake.
    string(REPLACE ":" ";" _entries "${_exe_rp}")
    if (NOT "$ORIGIN/lib" IN_LIST _entries)
        message(FATAL_ERROR "${_exe}: RUNPATH [${_exe_rp}] has no $ORIGIN/lib entry "
                            "(built without cmake/LinuxPackageRunpath.cmake?)")
    endif()
    if (NOT _exe_rp STREQUAL "$ORIGIN/lib")
        file(RPATH_SET FILE "${_exe}" NEW_RPATH "$ORIGIN/lib")
    endif()
endforeach()

# Bundled libraries: only those that carry a RUNPATH/RPATH are rewritten (ours,
# e.g. libdash_scriptcheck.so -> $ORIGIN). The system copies the ldd loop
# bundles (libsecp256k1, libgmp) have none, need only glibc, and are left
# byte-identical.
file(GLOB _libs LIST_DIRECTORIES false "${PKG_DIR}/lib/*.so*")
foreach (_lib IN LISTS _libs)
    _c2pool_runpath_of("${_lib}" _lib_rp)
    if (NOT _lib_rp STREQUAL "" AND NOT _lib_rp STREQUAL "$ORIGIN")
        file(RPATH_SET FILE "${_lib}" NEW_RPATH "$ORIGIN")
    endif()
endforeach()
