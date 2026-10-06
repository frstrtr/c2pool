# ─────────────────────────────────────────────────────────────────────────────
# Path B, slice S1 (subset) KATs. STL + xmr_coin + Boost headers; no RandomX,
# no monerod. Run on both CI legs.
#
#   v37_xmr_side_data_v3_kat         side_data_v3 layout, golden bytes, mm_root, refusals
#   v37_xmr_pathb_body_v3_kat        receipt and carrier body codecs, caps, mutation pass
#   v37_xmr_pathb_pbx1_kat           PBX1 tx_extra forms and refusals
#   v37_xmr_relay_horizons_kat       horizons, J, blob_cap, w_min, D_max, RECEIPT_CAP
#   v37_xmr_pathb_branch_kat         window inputs on the branch of prev_id(tip)
#   xmr_template_catchup_kat         catch-up template rule
#   v37_xmr_pathb_journal_kat        rewind journal, rebuild verdict
#   v37_xmr_pathb_headers_first_kat  side-branch decision from headers
#   xmr_share_retarget_kat           carrier retarget: formula, widths, scenarios
#   xmr_carrier_sharechain_kat       carrier fork choice, deferral, switch plans,
#                                    headers-first over the retarget
#
# DRIFT-GUARD: this tree is outside the glob of
# tools/ci/check_test_target_allowlist.py, so every target below is listed by
# hand in BOTH `--target` lists of .github/workflows/build.yml.
# gen_pathb_golden.py regenerates the side_data_v3 golden vector.
# ─────────────────────────────────────────────────────────────────────────────

if (BUILD_TESTING)
    foreach(_pathb_kat
            v37_xmr_side_data_v3_kat
            v37_xmr_pathb_body_v3_kat
            v37_xmr_pathb_pbx1_kat
            v37_xmr_relay_horizons_kat
            v37_xmr_pathb_branch_kat
            xmr_template_catchup_kat
            v37_xmr_pathb_journal_kat
            v37_xmr_pathb_headers_first_kat
            xmr_share_retarget_kat
            xmr_carrier_sharechain_kat)
        add_executable(${_pathb_kat} ${_pathb_kat}.cpp)
        target_include_directories(${_pathb_kat} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_link_libraries(${_pathb_kat} PRIVATE xmr_pathb)
        add_test(NAME ${_pathb_kat} COMMAND ${_pathb_kat})
    endforeach()
    # v37_xmr_pathb_body_v3_kat reads the relay frame header of
    # src/c2pool/v37/xmr/relay/xmr_relay_wire.hpp (xmr_receipt.hpp by its bare name).
    target_include_directories(v37_xmr_pathb_body_v3_kat PRIVATE ${CMAKE_SOURCE_DIR}/src/impl/xmr/receipt)
endif()
