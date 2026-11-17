# Build-time version header generator.
#
# Runs `git describe` every build (this script is invoked by an always-out-of-date
# custom target) and writes C2POOL_VERSION into a generated header. Using a
# BUILD-time step rather than a configure-time execute_process() means an
# incremental rebuild in a build dir that was configured at an older commit no
# longer bakes the stale configure-era hash into the binary — the version string
# tracks the source actually being compiled.
#
# copy_if_different keeps the header's mtime stable when the version is unchanged,
# so a no-op rebuild does not force every version-including TU to recompile.
#
# Invoked as:  cmake -DSRC_DIR=<repo> -DOUT_FILE=<path> -P GenerateVersionHeader.cmake

# 1. A git checkout: the tag (or tag-N-gHASH, or the bare hash without tags).
#    `-c safe.directory=*`: a tree owned by another user (e.g. cloned as root, built
#    as a service user) otherwise makes git refuse with "dubious ownership" and the
#    version silently fell back.
#    Only if SRC_DIR is itself the top of a git tree: an unpacked source archive
#    that happens to sit inside some other repository must not take that repo's tag.
execute_process(
    COMMAND git -c safe.directory=* rev-parse --show-toplevel
    WORKING_DIRECTORY ${SRC_DIR}
    OUTPUT_VARIABLE _c2pool_git_top
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
get_filename_component(_c2pool_src_real "${SRC_DIR}" REALPATH)
if(_c2pool_git_top)
    get_filename_component(_c2pool_git_top "${_c2pool_git_top}" REALPATH)
endif()
if(_c2pool_git_top STREQUAL _c2pool_src_real)
    execute_process(
        COMMAND git -c safe.directory=* describe --tags --always --dirty
        WORKING_DIRECTORY ${SRC_DIR}
        OUTPUT_VARIABLE C2POOL_GIT_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
endif()
# 2. A source archive (GitHub "Source code" tarball/zip, `git archive`): no .git, but
#    cmake/version-archive.txt carries the tag via export-subst (.gitattributes).
if(NOT C2POOL_GIT_VERSION AND EXISTS ${SRC_DIR}/cmake/version-archive.txt)
    file(STRINGS ${SRC_DIR}/cmake/version-archive.txt _c2pool_archive_version LIMIT_COUNT 1)
    string(STRIP "${_c2pool_archive_version}" _c2pool_archive_version)
    if(_c2pool_archive_version AND NOT _c2pool_archive_version MATCHES "Format")
        set(C2POOL_GIT_VERSION "${_c2pool_archive_version}")
    endif()
endif()
# 3. Neither: say so instead of claiming an old release number (was "0.1.0-alpha").
if(NOT C2POOL_GIT_VERSION)
    set(C2POOL_GIT_VERSION "unknown")
endif()
# Strip a leading 'v' from tag-derived versions (v0.2.5 -> 0.2.5).
string(REGEX REPLACE "^v" "" C2POOL_GIT_VERSION "${C2POOL_GIT_VERSION}")

file(WRITE ${OUT_FILE}.tmp
     "#pragma once\n#define C2POOL_VERSION \"${C2POOL_GIT_VERSION}\"\n")
execute_process(
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OUT_FILE}.tmp ${OUT_FILE}
)
file(REMOVE ${OUT_FILE}.tmp)
