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

execute_process(
    COMMAND git describe --tags --always --dirty
    WORKING_DIRECTORY ${SRC_DIR}
    OUTPUT_VARIABLE C2POOL_GIT_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT C2POOL_GIT_VERSION)
    set(C2POOL_GIT_VERSION "0.1.0-alpha")
endif()
# Strip a leading 'v' from tag-derived versions (v0.2.5 -> 0.2.5).
string(REGEX REPLACE "^v" "" C2POOL_GIT_VERSION "${C2POOL_GIT_VERSION}")

file(WRITE ${OUT_FILE}.tmp
     "#pragma once\n#define C2POOL_VERSION \"${C2POOL_GIT_VERSION}\"\n")
execute_process(
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OUT_FILE}.tmp ${OUT_FILE}
)
file(REMOVE ${OUT_FILE}.tmp)
