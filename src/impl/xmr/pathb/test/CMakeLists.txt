# ─────────────────────────────────────────────────────────────────────────────
# Path B, slice S1 (subset) KATs. STL + xmr_coin + Boost headers; no RandomX,
# no monerod. Run on both CI legs. The slice S2 (thin) KATs follow them.
#
#   v37_xmr_side_data_v3_kat         side_data_v3 layout, golden bytes, mm_root, refusals,
#                                    ratchet state S and the receipts_root fold
#   v37_xmr_pathb_body_v3_kat        receipt and carrier body codecs, I/O buffers, consensus
#                                    caps, check_relay_buffers, mutation pass
#   v37_xmr_pathb_pbx1_kat           PBX1 tx_extra forms and refusals
#   v37_xmr_relay_horizons_kat       horizons, J, blob_cap, w_min, D_max, RECEIPT_CAP
#   v37_xmr_pathb_branch_kat         window inputs on the branch of prev_id(tip)
#   xmr_template_catchup_kat         catch-up template rule
#   v37_xmr_pathb_journal_kat        rewind journal, rebuild verdict
#   v37_xmr_pathb_headers_first_kat  side-branch decision from headers
#   xmr_share_retarget_kat           carrier retarget: formula, widths, scenarios
#   xmr_carrier_sharechain_kat       carrier fork choice, deferral, switch plans,
#                                    headers-first over the retarget, receipts_root fold
#
# Slice S2 KATs (pathb_receipt_admission.hpp, pathb_header_rules.hpp):
#   xmr_receipt_freshness_kat        freshness 0 <= h(r) - h(tip) <= 2 (K07)
#   xmr_receipt_legally_dead_kat     the 7 delta-1 liveness vectors, no clock (K05)
#   xmr_receipt_carriage_kat         open carriage of any miner's receipts, order, R_MAX,
#                                    open bin, dedup, omission, carried_root fold (K08)
#   v37_xmr_receipt_header_rules_kat major == hf(h), timestamp >= median60 (P_r branch)
#   v37_xmr_receipt_wire_cap_kat     size verdicts: STRIKE / DROP, strike counter, caps (K18)
#   xmr_carrier_timestamp_kat        carrier record H, carrier header rules, no clock
#   v37_xmr_receipt_id_kat           id = keccak256(hashing_blob), replay dedup
#   v37_xmr_receipt_defer_kat        defer-never-ban resolution
#   xmr_receipt_solo_leech_kat       one-output miner tx / window split miner tx: BAN before RandomX
#
# Slice S3 (payout economics) KATs (pathb_wide/emission/buckets/window/
# coinbase_split/joiner.hpp; unwired, engine byte-identical):
#   xmr_window_kat                   window to COVERAGE x D_net, no decay, window_root golden
#   xmr_window_spend_floor_kat       W_max per entry, F6 1500-bin stop, f_spend
#   xmr_window_merge_back_kat        owner/author below B(A_t) floor merge back
#   v37_xmr_window_branch_kat        window of the block's OWN tip; A_t anchor
#   v37_xmr_window_fork_height_kat   hf16 vs hf17 format; hf17 Fused -> REFUSE, no token, no RandomX
#   v37_xmr_coinbase_reserve_kat     N(B) at Z/2; the two written forms are equal
#   xmr_coinbase_output_gate_kat     N rule caps outputs; in-bin cut; cap 10000
#   xmr_window_split_kat             q_i = floor(R w_i / W), Sum(vout) == R
#   v37_xmr_coinbase_output_order_kat  hf16 by identity ascending; no fee output; hf17 Ko order, equal Ko
#   v37_xmr_coinbase_extra_layout_kat  hf16 PBX1 extra 74 B; miner tx weighed; hf17 extra; mainnet sample
#   v37_xmr_bin_fold_kat             fold at f, seal D_fin 0, late push REFUSED
#   v37_xmr_mmr_golden_kat           row_leaf/comp_root/mmr_leaf goldens; MMR proofs
#   v37_xmr_base_reward_kat          B(A) emission; anchor without agc -> DEFER
#   v37_xmr_joiner_kat               span at L' (x0, x1); attempts, claims, candidates,
#                                    buckets at the at header; joins at L = 4,700 (pathb_join.hpp)
#   xmr_wide_int_extreme_kat         U320 split / W_max / merge-back at the extremes
#   v37_xmr_fairness_cap_kat         20% miner + 40000 small: all paid, Sum == R
#   v37_xmr_fairness_schedules_kat   payout share == work share within 0.003
#   v37_xmr_pathb_coinbase_kat       Sum(vout) == R (kept name xmr_coinbase_kat)
#   v37_xmr_pathb_e2e_kat            window->split->miner tx->roots #13 (kept name xmr_e2e_kat)
#
# Slice S3b-2 KAT (pathb_miner_tx.hpp, pathb_coinbase_split.hpp; unwired):
#   v37_xmr_pathb_miner_tx_kat       mainnet blocks 3755897 / 3755902 / 3774472 byte for byte;
#                                    canonical miner tx self-golden; KeyCache; #12 outcomes
#
# Slice S4 (the ratchet activation module; pathb_ratchet_activation.hpp,
# pathb_lane_rules.hpp, pathb_hello.hpp; unwired) KATs:
#   v37_xmr_epoch_kat                activation, HOLD, frames, epoch_at / AR, kind 2,
#                                    commitment, HELLO diagnostics
#   xmr_epoch_tally_kat              tally, rs_step step 1, failure / re-proposal,
#                                    start-up checks, layout MT
#   v37_xmr_ballot_kat               the ballot writer and its encoding
#   xmr_epoch_accounting_kat         weights across an epoch (C24)
#   v37_xmr_donation_split_kat       K16 author share and identity (C26)
#   v37_xmr_monero_rules_digest_kat  K20 monero_rules_digest
#   v37_xmr_pathb_hello_kat          rules block TLV golden, trailer codec; the Path B
#                                    tail (S3b-3), forbidden-literal scan
#
# Slice S3b-3 KAT (pathb_bucket_wire.hpp; unwired):
#   v37_xmr_pathb_bucket_wire_kat    FC_GETBUCKETS / FC_BUCKETS codec, verifier, paging,
#                                    serving rule, per-peer budget
#
# Slice S3b-4a KAT (pathb_admit.hpp, pathb_header_index.hpp, pathb_claim_view.hpp; unwired):
#   v37_xmr_pathb_admit_kat          the admission pipeline (S1.3, S2.3), the deep-tip
#                                    boundary and the closure, the write step, the
#                                    deferred store, the claim extension point
#
# Slice S4w-a KATs (the Path B node modules; unwired):
#   v37_xmr_relay_family_c_kat       FC_CARRIER / FC_GETCARRIER / FC_GETHEADERS / FC_HEADERS
#                                    (first_pos) and FB_RECEIPTS v3 codecs, frame versions
#   v37_xmr_pathb_store_kat          the node's own store: K_PHEAD / K_PCARRIER / K_AR, one batch
#                                    per position, the prefix load, the two-phase reload
#
# DRIFT-GUARD: this tree is outside the glob of
# tools/ci/check_test_target_allowlist.py, so every target below is listed by
# hand in BOTH `--target` lists of .github/workflows/build.yml.
# gen_pathb_golden.py regenerates the side_data_v3 and ratchet-state golden vectors.
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
            xmr_carrier_sharechain_kat
            xmr_receipt_freshness_kat
            xmr_receipt_legally_dead_kat
            xmr_receipt_carriage_kat
            v37_xmr_receipt_id_kat
            v37_xmr_receipt_defer_kat
            xmr_receipt_solo_leech_kat
            v37_xmr_receipt_header_rules_kat
            v37_xmr_receipt_wire_cap_kat
            xmr_carrier_timestamp_kat
            xmr_window_kat
            xmr_window_spend_floor_kat
            xmr_window_merge_back_kat
            v37_xmr_window_branch_kat
            v37_xmr_window_fork_height_kat
            v37_xmr_coinbase_reserve_kat
            xmr_coinbase_output_gate_kat
            xmr_window_split_kat
            v37_xmr_coinbase_output_order_kat
            v37_xmr_coinbase_extra_layout_kat
            v37_xmr_bin_fold_kat
            v37_xmr_mmr_golden_kat
            v37_xmr_base_reward_kat
            v37_xmr_joiner_kat
            xmr_wide_int_extreme_kat
            v37_xmr_fairness_cap_kat
            v37_xmr_fairness_schedules_kat
            v37_xmr_pathb_coinbase_kat
            v37_xmr_pathb_e2e_kat
            v37_xmr_pathb_miner_tx_kat
            v37_xmr_epoch_kat
            xmr_epoch_tally_kat
            v37_xmr_ballot_kat
            xmr_epoch_accounting_kat
            v37_xmr_donation_split_kat
            v37_xmr_monero_rules_digest_kat
            v37_xmr_pathb_hello_kat
            v37_xmr_pathb_bucket_wire_kat
            v37_xmr_pathb_admit_kat
            v37_xmr_relay_family_c_kat
            v37_xmr_pathb_store_kat)
        add_executable(${_pathb_kat} ${_pathb_kat}.cpp)
        target_include_directories(${_pathb_kat} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_link_libraries(${_pathb_kat} PRIVATE xmr_pathb)
        add_test(NAME ${_pathb_kat} COMMAND ${_pathb_kat})
    endforeach()
    # v37_xmr_pathb_body_v3_kat and v37_xmr_receipt_wire_cap_kat read the relay
    # frame header of src/c2pool/v37/xmr/relay/xmr_relay_wire.hpp (xmr_receipt.hpp
    # by its bare name).
    target_include_directories(v37_xmr_pathb_body_v3_kat PRIVATE ${CMAKE_SOURCE_DIR}/src/impl/xmr/receipt)
    target_include_directories(v37_xmr_receipt_wire_cap_kat PRIVATE ${CMAKE_SOURCE_DIR}/src/impl/xmr/receipt)
    # v37_xmr_pathb_miner_tx_kat: a test-only TU compares the author key references
    # with c2pool/v37/xmr/xmr_fee_model.hpp and pathb's keys with the settle
    # derivation (settle/xmr_coinbase.cpp, compiled into the KAT only).
    target_sources(v37_xmr_pathb_miner_tx_kat PRIVATE
            v37_xmr_pathb_miner_tx_author.cpp
            ${CMAKE_SOURCE_DIR}/src/impl/xmr/settle/xmr_coinbase.cpp)
    # v37_xmr_donation_split_kat reads the donation keys of the fee model source.
    target_compile_definitions(v37_xmr_donation_split_kat PRIVATE C2POOL_SRC_DIR="${CMAKE_SOURCE_DIR}/src")
    # xmr_carrier_timestamp_kat scans the Path B headers for a clock read;
    # v37_xmr_pathb_hello_kat scans them for the forbidden N-rule / reserve literals.
    target_compile_definitions(xmr_carrier_timestamp_kat PRIVATE
            PATHB_SRC_DIR="${CMAKE_CURRENT_SOURCE_DIR}/..")
    target_compile_definitions(v37_xmr_pathb_hello_kat PRIVATE
            PATHB_SRC_DIR="${CMAKE_CURRENT_SOURCE_DIR}/..")
    # v37_xmr_pathb_store_kat also runs its store through the LevelDB archive.
    target_link_libraries(v37_xmr_pathb_store_kat PRIVATE xmr_pathb_store)
    # v37_xmr_joiner_kat replays several chains of 4,700+ carriers (ASan ~12 min).
    set_tests_properties(v37_xmr_joiner_kat PROPERTIES TIMEOUT 3000)
endif()
