# Linux release-package RUNPATH ($ORIGIN-relative library lookup).
#
# The Linux release tarball (.github/workflows/release.yml, linux job, step
# "Package") is laid out as
#
#   c2pool-<coin>-<ver>-linux-x86_64/
#     c2pool-<coin>          the executable, copied from the build tree
#     lib/                   its non-glibc runtime closure (ldd-resolved):
#                            libsecp256k1.so.N for every coin, plus libgmp.so.10
#                            and libdash_scriptcheck.so for DASH
#     start.sh  config/  web-static/  explorer/
#
# Without an $ORIGIN entry the dynamic loader never looks in lib/: the shipped
# binary only starts through start.sh (LD_LIBRARY_PATH=$DIR/lib), and an
# operator running it from a systemd unit or their own script gets
#   error while loading shared libraries: libsecp256k1.so.6
# whenever the host's libsecp256k1 soname differs from the build runner's
# (Ubuntu 24.04 runners link libsecp256k1.so.1, 26.04 runners .so.6). The
# build-tree RUNPATH CMake emits holds only the runner's Conan cache and build
# directories, which do not exist on the user's host.
#
# c2pool_linux_package_runpath(<target> <entry>) puts <entry> FIRST in the
# target's RUNPATH:
#   executables in the package root  -> "$ORIGIN/lib"
#   shared objects shipped in lib/   -> "$ORIGIN" (their own bundled deps,
#                                       e.g. libdash_scriptcheck.so -> libsecp256k1)
#
# BUILD_RPATH, not BUILD_WITH_INSTALL_RPATH: CMake places explicit BUILD_RPATH
# entries ahead of the link-derived build-tree directories and keeps those, so
#   - in the build tree "$ORIGIN/lib" names a directory that does not exist and
#     the loader falls through to the same directories as before (tests, the
#     build-tree --help smoke and dash_scriptcheck in src/impl/dash keep working);
#   - the release Package step, which resolves the bundle with `ldd` on the copied
#     binary, still finds libdash_scriptcheck.so through the build-tree entry;
#   - in the unpacked tarball "$ORIGIN/lib" resolves first, so the bundled
#     libraries are used whether or not the host has its own copy.
# RUNPATH (DT_RUNPATH, the toolchain default) ranks below LD_LIBRARY_PATH, so
# start.sh behaves exactly as before. INSTALL_RPATH carries the same entry for a
# future `cmake --install`; there are no install() rules today.
#
# Linux only: on macOS the release job rewrites install names to
# @executable_path/lib (otool/install_name_tool), and Windows has no RUNPATH.
function(c2pool_linux_package_runpath _tgt _entry)
    if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        return()
    endif()
    get_target_property(_build_rpath ${_tgt} BUILD_RPATH)
    if (NOT _build_rpath)
        set(_build_rpath "")
    endif()
    list(PREPEND _build_rpath "${_entry}")
    set_target_properties(${_tgt} PROPERTIES
        BUILD_RPATH   "${_build_rpath}"
        INSTALL_RPATH "${_entry}")
endfunction()
