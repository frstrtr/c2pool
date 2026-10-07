# ─────────────────────────────────────────────────────────────────────────────
# Path B, slice S1 (subset): header-only, not linked by any running target.
#
#   pathb_params.hpp         lane parameters, Monero symbols, integer helpers
#   pathb_wire_v3.hpp        side_data_v3, receipt body v3, carrier body v3
#   pathb_pbx1.hpp           PBX1 coinbase tx_extra
#   pathb_caps.hpp           w_min, D_max, RECEIPT_CAP / FRAME_CAP, I/O buffers, blob_cap,
#                            J, relay horizons
#   pathb_branch.hpp         window inputs from the branch of prev_id(tip)
#   pathb_catchup.hpp        catch-up template rule, template freshness
#   pathb_journal.hpp        rewind journal of depth J
#   pathb_headers_first.hpp  side-branch decision from announced headers
#   pathb_ratchet_state.hpp  ratchet state S, rs_step, the receipts_root fold
#   pathb_retarget.hpp       carrier retarget (K01, K02, K03)
#   pathb_fork_choice.hpp    carrier tree, fork choice, switch plan
#   pathb_receipt_admission.hpp  slice S2 (thin): self-carried receipts, LEGALLY
#                            DEAD, carried_root, stub coinbase (unwired)
#
# `xmr_pathb` is an INTERFACE target: the include root, xmr_coin (Keccak,
# vendored difficulty) and Boost headers (the vendored difficulty's uint128).
# Its KATs are in test/ and are listed in both build.yml --target lists.
# ─────────────────────────────────────────────────────────────────────────────

add_library(xmr_pathb INTERFACE)
target_include_directories(xmr_pathb INTERFACE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(xmr_pathb INTERFACE xmr_coin)
if (TARGET Boost::headers)
    target_link_libraries(xmr_pathb INTERFACE Boost::headers)
elseif (TARGET Boost::boost)
    target_link_libraries(xmr_pathb INTERFACE Boost::boost)
elseif (DEFINED Boost_INCLUDE_DIRS)
    target_include_directories(xmr_pathb INTERFACE ${Boost_INCLUDE_DIRS})
endif()
target_compile_features(xmr_pathb INTERFACE cxx_std_20)

if (BUILD_TESTING)
    add_subdirectory(test)
endif()
