# CTest retry wrapper for a TRACKED timing flake (script mode).
#
#   cmake -DEXE=<test binary> -DNAME=<ctest name> -DISSUE=<issue number>
#         [-DTRIES=3] -P cmake/RetryTest.cmake
#
# ONLY for a test whose race is tracked in an open GitHub issue (ISSUE is
# required). Never use it to hide a new failure: a new red gets fixed, or gets
# its own issue first. Never for a safety pin whose failure has no root cause
# in its issue. Drop the test from the wrapper when its race is fixed.
#
# Runs EXE up to TRIES times (default 3). The first attempt that exits 0 passes
# the test. A test that fails all TRIES attempts still FAILS. Every attempt's
# output is inherited (streamed into the CTest log as it runs, never captured
# or swallowed), and the wrapper adds these lines:
#   attempt n/N FAILED rc=<rc>: <name> (flake #<issue>)    after a failed attempt
#   RETRY n/N <name> (flake #<issue>)                      before every retry
#   RETRY passed on attempt n/N <name> (flake #<issue>)    on a late pass
# A passing test's output reaches only Testing/Temporary/LastTest.log, not the
# console of `ctest --output-on-failure`. CI uploads that file on every run and
# turns these lines into warnings (scripts/ci/report_test_retries.sh).
#
# CTest has no per-test repeat property (`ctest --repeat until-pass:N` is a
# command-line option for the whole run), hence this script. The test's
# TIMEOUT covers all attempts together, and the test's ENVIRONMENT reaches EXE
# through this process. A missing EXE (target not built) fails at once.

if(NOT DEFINED EXE OR "${EXE}" STREQUAL "")
  message(FATAL_ERROR "RetryTest: EXE is required (-DEXE=<test binary>)")
endif()
if(NOT DEFINED ISSUE OR NOT "${ISSUE}" MATCHES "^[0-9]+$")
  message(FATAL_ERROR "RetryTest: ISSUE is required (-DISSUE=<number of the "
                      "issue that tracks this flake>); this wrapper is only "
                      "for a tracked flake")
endif()
if(NOT DEFINED NAME OR "${NAME}" STREQUAL "")
  get_filename_component(NAME "${EXE}" NAME)
endif()
if(NOT DEFINED TRIES OR "${TRIES}" STREQUAL "")
  set(TRIES 3)
endif()
if(NOT "${TRIES}" MATCHES "^[1-9][0-9]*$")
  message(FATAL_ERROR "RetryTest: TRIES must be a positive integer, got '${TRIES}'")
endif()
if(NOT EXISTS "${EXE}")
  message(FATAL_ERROR "RetryTest: ${NAME}: test binary not found: ${EXE} "
                      "(target not built?); not retried")
endif()

set(_tag "${NAME} (flake #${ISSUE})")
set(_passed FALSE)
set(_rc "")
foreach(_i RANGE 1 ${TRIES})
  if(_i GREATER 1)
    message("RETRY ${_i}/${TRIES} ${_tag}")
  endif()
  # No OUTPUT_*/ERROR_* options: the child shares this process's stdout and
  # stderr, so every attempt's full output lands in the CTest log.
  execute_process(COMMAND "${EXE}" RESULT_VARIABLE _rc)
  if("${_rc}" STREQUAL "0")
    set(_passed TRUE)
    if(_i GREATER 1)
      message("RETRY passed on attempt ${_i}/${TRIES} ${_tag}")
    endif()
    break()
  endif()
  message("attempt ${_i}/${TRIES} FAILED rc=${_rc}: ${_tag}")
endforeach()

if(NOT _passed)
  message(FATAL_ERROR "RetryTest: ${_tag} failed all ${TRIES} attempts "
                      "(last rc=${_rc}). This is a real failure; the retry "
                      "does not hide it.")
endif()
