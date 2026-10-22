// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// T5 golden gentx fixtures -- VERBATIM copies (byte-for-byte, including the
// py2 json.dump trailing spaces) of the six frozen golden vectors emitted by the
// Python p2pool reference generator p2pool/test/gen_gentx_golden.py.
//
//   source: frstrtr/p2pool-merged-v36 commit f38d6bb7 p2pool/test/golden/
//
// Embedded so ltc_gentx_golden_kat_test.cpp never reads the p2pool checkout at
// test runtime. Do not hand-edit: regenerate from the p2pool commit instead.
// ---------------------------------------------------------------------------

namespace ltc_t5_golden {

struct GoldenFixture
{
    const char* file;   // basename under p2pool/test/golden/ @ f38d6bb7
    const char* json;   // verbatim file contents
};

inline constexpr GoldenFixture kFixtures[] = {
    {"ltc_gentx_empty_difftest_p2pkh.json", R"GOLDEN({
  "_comment": "OFFLINE golden vector for the LTC gentx path. Frozen reference target for c2pool ltc_gentx_dump. Regenerate with p2pool.test.gen_gentx_golden.", 
  "artifact": {
    "gentx_hex": "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff040380841effffffff030000000000000000266a24aa21a9ed92ac07c7b9e008effde0e4753064f2328b1c8cd3d0b488f4bf1bba8cb9338c36807c814a0000000017a9148c6272621d89e8fa526dd86acff60c7136be8e858700000000000000002a6a28d3fb6ef66d53e2d3d6fdd1815c480b0cccd0ba2dbaa55138758845ea8d622027000000000000000001205b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d00000000", 
    "gentx_txid_hex": "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff040380841effffffff030000000000000000266a24aa21a9ed92ac07c7b9e008effde0e4753064f2328b1c8cd3d0b488f4bf1bba8cb9338c36807c814a0000000017a9148c6272621d89e8fa526dd86acff60c7136be8e858700000000000000002a6a28d3fb6ef66d53e2d3d6fdd1815c480b0cccd0ba2dbaa55138758845ea8d622027000000000000000000000000", 
    "new_tx_bytes": 0, 
    "other_tx_hashes": [], 
    "share_info": {
      "absheight": 1, 
      "abswork": 1048577, 
      "bits": {
        "__floatinginteger_bits__": 504365055
      }, 
      "far_share_hash": null, 
      "max_bits": {
        "__floatinginteger_bits__": 504365055
      }, 
      "merged_addresses": null, 
      "merged_coinbase_info": null, 
      "merged_payout_hash": null, 
      "segwit_data": {
        "txid_merkle_link": {
          "branch": [], 
          "index": 0
        }, 
        "wtxid_merkle_root": 0
      }, 
      "share_data": {
        "coinbase": {
          "__hex__": "0380841e"
        }, 
        "desired_version": 36, 
        "donation": 655, 
        "nonce": 1526618878, 
        "previous_share_hash": null, 
        "pubkey_hash": 6495562832581790663061892574634853316331521383, 
        "pubkey_type": 0, 
        "stale_info": null, 
        "subsidy": 1250000000
      }, 
      "timestamp": 1700000000
    }, 
    "share_info_packed_hex": "0000000000000000000000000000000000000000000000000000000000000000040380841efe5afe5a67452301efcdab8967452301efcdab896745230100fe807c814a8f020024000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffff0f1effff0f1e00f1536501000000fe01001000000000000000000000000000000000000000000000000000000000000000000000", 
    "template_weight": 0
  }, 
  "block_target_hex": "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 
  "desired_target_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 
  "frozen_epoch": 1700000000.0, 
  "gbt_transaction_fees": [], 
  "gbt_transaction_hashes": [], 
  "gbt_transactions": [], 
  "height": 2000000, 
  "net": "litecoin", 
  "pubkey_hash": "0123456789abcdef0123456789abcdef01234567", 
  "pubkey_type": 0, 
  "scenario": "empty", 
  "share_version": 36, 
  "subsidy": 1250000000, 
  "user": "difftest_p2pkh", 
  "v36_active": true
}
)GOLDEN"},
    {"ltc_gentx_empty_difftest_p2wpkh.json", R"GOLDEN({
  "_comment": "OFFLINE golden vector for the LTC gentx path. Frozen reference target for c2pool ltc_gentx_dump. Regenerate with p2pool.test.gen_gentx_golden.", 
  "artifact": {
    "gentx_hex": "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff040380841effffffff030000000000000000266a24aa21a9ed92ac07c7b9e008effde0e4753064f2328b1c8cd3d0b488f4bf1bba8cb9338c36807c814a0000000017a9148c6272621d89e8fa526dd86acff60c7136be8e858700000000000000002a6a28caad215e7a3b3f8d2d4adeae60e1b633b58af225a8dad321d330782fcba698d0000000000000000001205b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d00000000", 
    "gentx_txid_hex": "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff040380841effffffff030000000000000000266a24aa21a9ed92ac07c7b9e008effde0e4753064f2328b1c8cd3d0b488f4bf1bba8cb9338c36807c814a0000000017a9148c6272621d89e8fa526dd86acff60c7136be8e858700000000000000002a6a28caad215e7a3b3f8d2d4adeae60e1b633b58af225a8dad321d330782fcba698d0000000000000000000000000", 
    "new_tx_bytes": 0, 
    "other_tx_hashes": [], 
    "share_info": {
      "absheight": 1, 
      "abswork": 1048577, 
      "bits": {
        "__floatinginteger_bits__": 504365055
      }, 
      "far_share_hash": null, 
      "max_bits": {
        "__floatinginteger_bits__": 504365055
      }, 
      "merged_addresses": null, 
      "merged_coinbase_info": null, 
      "merged_payout_hash": null, 
      "segwit_data": {
        "txid_merkle_link": {
          "branch": [], 
          "index": 0
        }, 
        "wtxid_merkle_root": 0
      }, 
      "share_data": {
        "coinbase": {
          "__hex__": "0380841e"
        }, 
        "desired_version": 36, 
        "donation": 655, 
        "nonce": 1526618878, 
        "previous_share_hash": null, 
        "pubkey_hash": 12991125665163581326123785149269706632663042766, 
        "pubkey_type": 1, 
        "stale_info": null, 
        "subsidy": 1250000000
      }, 
      "timestamp": 1700000000
    }, 
    "share_info_packed_hex": "0000000000000000000000000000000000000000000000000000000000000000040380841efe5afe5ace8a4602de9b5713cf8a4602de9b5713cf8a460201fe807c814a8f020024000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffff0f1effff0f1e00f1536501000000fe01001000000000000000000000000000000000000000000000000000000000000000000000", 
    "template_weight": 0
  }, 
  "block_target_hex": "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 
  "desired_target_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 
  "frozen_epoch": 1700000000.0, 
  "gbt_transaction_fees": [], 
  "gbt_transaction_hashes": [], 
  "gbt_transactions": [], 
  "height": 2000000, 
  "net": "litecoin", 
  "pubkey_hash": "02468acf13579bde02468acf13579bde02468ace", 
  "pubkey_type": 1, 
  "scenario": "empty", 
  "share_version": 36, 
  "subsidy": 1250000000, 
  "user": "difftest_p2wpkh", 
  "v36_active": true
}
)GOLDEN"},
    {"ltc_gentx_twotx_difftest_p2pkh.json", R"GOLDEN({
  "_comment": "OFFLINE golden vector for the LTC gentx path. Frozen reference target for c2pool ltc_gentx_dump. Regenerate with p2pool.test.gen_gentx_golden.", 
  "artifact": {
    "gentx_hex": "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff040380841effffffff030000000000000000266a24aa21a9eda6f476b663531fe725a724de245142c10d0a7d004d4055b2ce95a425b34c4f15807c814a0000000017a9148c6272621d89e8fa526dd86acff60c7136be8e858700000000000000002a6a28a240ab338b66cb062ae7df9ab41605bb42fd5c876c5d83da7ad451e9f03b0924000000000000000001205b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d00000000", 
    "gentx_txid_hex": "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff040380841effffffff030000000000000000266a24aa21a9eda6f476b663531fe725a724de245142c10d0a7d004d4055b2ce95a425b34c4f15807c814a0000000017a9148c6272621d89e8fa526dd86acff60c7136be8e858700000000000000002a6a28a240ab338b66cb062ae7df9ab41605bb42fd5c876c5d83da7ad451e9f03b0924000000000000000000000000", 
    "new_tx_bytes": 187, 
    "other_tx_hashes": [
      "653b2e0b2061788a9f93d8d0a7dbf469f72407b1944ac27b9d9d70e6e9c19841", 
      "b668088ebd4ecbe61d85a78f09e8d991cb40fefea2988aefa514d88304777114"
    ], 
    "share_info": {
      "absheight": 1, 
      "abswork": 1048577, 
      "bits": {
        "__floatinginteger_bits__": 504365055
      }, 
      "far_share_hash": null, 
      "max_bits": {
        "__floatinginteger_bits__": 504365055
      }, 
      "merged_addresses": null, 
      "merged_coinbase_info": null, 
      "merged_payout_hash": null, 
      "segwit_data": {
        "txid_merkle_link": {
          "branch": [
            45788159464033286127369463833799921008767842079284580797967791505657263396929, 
            8859742648666923327804044782388915676279839733971246680963548844893144175462
          ], 
          "index": 0
        }, 
        "wtxid_merkle_root": 61900901454555766205236516933145462873951574491966020060412654908150232913885
      }, 
      "share_data": {
        "coinbase": {
          "__hex__": "0380841e"
        }, 
        "desired_version": 36, 
        "donation": 655, 
        "nonce": 1526618878, 
        "previous_share_hash": null, 
        "pubkey_hash": 6495562832581790663061892574634853316331521383, 
        "pubkey_type": 0, 
        "stale_info": null, 
        "subsidy": 1250000000
      }, 
      "timestamp": 1700000000
    }, 
    "share_info_packed_hex": "0000000000000000000000000000000000000000000000000000000000000000040380841efe5afe5a67452301efcdab8967452301efcdab896745230100fe807c814a8f020024024198c1e9e6709d9d7bc24a94b10724f769f4dba7d0d8939f8a7861200b2e3b656653d1b037d86595347244ef03deeefb9431b808a837e27225046a42c76f9613dd17947d08c7965b5e162dce553ccbf3af4274a92c56cdc63ae655152cabda88000000000000000000000000000000000000000000000000000000000000000000ffff0f1effff0f1e00f1536501000000fe01001000000000000000000000000000000000000000000000000000000000000000000000", 
    "template_weight": 187
  }, 
  "block_target_hex": "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 
  "desired_target_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 
  "frozen_epoch": 1700000000.0, 
  "gbt_transaction_fees": [
    1000, 
    2000
  ], 
  "gbt_transaction_hashes": [
    "653b2e0b2061788a9f93d8d0a7dbf469f72407b1944ac27b9d9d70e6e9c19841", 
    "b668088ebd4ecbe61d85a78f09e8d991cb40fefea2988aefa514d88304777114"
  ], 
  "gbt_transactions": [
    "0100000001111111111111111111111111111111111111111111111111111111111111111100000000085151515151515151ffffffff01a0860100000000001976a914202020202020202020202020202020202020202088ac00000000", 
    "010000000112111111111111111111111111111111111111111111111111111111111111110100000009515151515151515151ffffffff01888a0100000000001976a914212121212121212121212121212121212121212188ac00000000"
  ], 
  "height": 2000000, 
  "net": "litecoin", 
  "pubkey_hash": "0123456789abcdef0123456789abcdef01234567", 
  "pubkey_type": 0, 
  "scenario": "twotx", 
  "share_version": 36, 
  "subsidy": 1250000000, 
  "user": "difftest_p2pkh", 
  "v36_active": true
}
)GOLDEN"},
    {"ltc_gentx_twotx_difftest_p2wpkh.json", R"GOLDEN({
  "_comment": "OFFLINE golden vector for the LTC gentx path. Frozen reference target for c2pool ltc_gentx_dump. Regenerate with p2pool.test.gen_gentx_golden.", 
  "artifact": {
    "gentx_hex": "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff040380841effffffff030000000000000000266a24aa21a9eda6f476b663531fe725a724de245142c10d0a7d004d4055b2ce95a425b34c4f15807c814a0000000017a9148c6272621d89e8fa526dd86acff60c7136be8e858700000000000000002a6a28ca58800152638206bdc35da7e44b1755f78a89443b68f0d381871fed8e505151000000000000000001205b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d00000000", 
    "gentx_txid_hex": "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff040380841effffffff030000000000000000266a24aa21a9eda6f476b663531fe725a724de245142c10d0a7d004d4055b2ce95a425b34c4f15807c814a0000000017a9148c6272621d89e8fa526dd86acff60c7136be8e858700000000000000002a6a28ca58800152638206bdc35da7e44b1755f78a89443b68f0d381871fed8e505151000000000000000000000000", 
    "new_tx_bytes": 187, 
    "other_tx_hashes": [
      "653b2e0b2061788a9f93d8d0a7dbf469f72407b1944ac27b9d9d70e6e9c19841", 
      "b668088ebd4ecbe61d85a78f09e8d991cb40fefea2988aefa514d88304777114"
    ], 
    "share_info": {
      "absheight": 1, 
      "abswork": 1048577, 
      "bits": {
        "__floatinginteger_bits__": 504365055
      }, 
      "far_share_hash": null, 
      "max_bits": {
        "__floatinginteger_bits__": 504365055
      }, 
      "merged_addresses": null, 
      "merged_coinbase_info": null, 
      "merged_payout_hash": null, 
      "segwit_data": {
        "txid_merkle_link": {
          "branch": [
            45788159464033286127369463833799921008767842079284580797967791505657263396929, 
            8859742648666923327804044782388915676279839733971246680963548844893144175462
          ], 
          "index": 0
        }, 
        "wtxid_merkle_root": 61900901454555766205236516933145462873951574491966020060412654908150232913885
      }, 
      "share_data": {
        "coinbase": {
          "__hex__": "0380841e"
        }, 
        "desired_version": 36, 
        "donation": 655, 
        "nonce": 1526618878, 
        "previous_share_hash": null, 
        "pubkey_hash": 12991125665163581326123785149269706632663042766, 
        "pubkey_type": 1, 
        "stale_info": null, 
        "subsidy": 1250000000
      }, 
      "timestamp": 1700000000
    }, 
    "share_info_packed_hex": "0000000000000000000000000000000000000000000000000000000000000000040380841efe5afe5ace8a4602de9b5713cf8a4602de9b5713cf8a460201fe807c814a8f020024024198c1e9e6709d9d7bc24a94b10724f769f4dba7d0d8939f8a7861200b2e3b656653d1b037d86595347244ef03deeefb9431b808a837e27225046a42c76f9613dd17947d08c7965b5e162dce553ccbf3af4274a92c56cdc63ae655152cabda88000000000000000000000000000000000000000000000000000000000000000000ffff0f1effff0f1e00f1536501000000fe01001000000000000000000000000000000000000000000000000000000000000000000000", 
    "template_weight": 187
  }, 
  "block_target_hex": "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 
  "desired_target_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 
  "frozen_epoch": 1700000000.0, 
  "gbt_transaction_fees": [
    1000, 
    2000
  ], 
  "gbt_transaction_hashes": [
    "653b2e0b2061788a9f93d8d0a7dbf469f72407b1944ac27b9d9d70e6e9c19841", 
    "b668088ebd4ecbe61d85a78f09e8d991cb40fefea2988aefa514d88304777114"
  ], 
  "gbt_transactions": [
    "0100000001111111111111111111111111111111111111111111111111111111111111111100000000085151515151515151ffffffff01a0860100000000001976a914202020202020202020202020202020202020202088ac00000000", 
    "010000000112111111111111111111111111111111111111111111111111111111111111110100000009515151515151515151ffffffff01888a0100000000001976a914212121212121212121212121212121212121212188ac00000000"
  ], 
  "height": 2000000, 
  "net": "litecoin", 
  "pubkey_hash": "02468acf13579bde02468acf13579bde02468ace", 
  "pubkey_type": 1, 
  "scenario": "twotx", 
  "share_version": 36, 
  "subsidy": 1250000000, 
  "user": "difftest_p2wpkh", 
  "v36_active": true
}
)GOLDEN"},
    {"ltc_gentx_threetx_difftest_p2pkh.json", R"GOLDEN({
  "_comment": "OFFLINE golden vector for the LTC gentx path. Frozen reference target for c2pool ltc_gentx_dump. Regenerate with p2pool.test.gen_gentx_golden.", 
  "artifact": {
    "gentx_hex": "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff040380841effffffff030000000000000000266a24aa21a9ed243eab01da61ad7ef367a2a87552014df27caa9b8cb9ff30e199ee322827e6be807c814a0000000017a9148c6272621d89e8fa526dd86acff60c7136be8e858700000000000000002a6a2825e89c43b76aa3f1f641434e69884d9c2ead040b38272cad3b594fdb563cf04a000000000000000001205b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d00000000", 
    "gentx_txid_hex": "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff040380841effffffff030000000000000000266a24aa21a9ed243eab01da61ad7ef367a2a87552014df27caa9b8cb9ff30e199ee322827e6be807c814a0000000017a9148c6272621d89e8fa526dd86acff60c7136be8e858700000000000000002a6a2825e89c43b76aa3f1f641434e69884d9c2ead040b38272cad3b594fdb563cf04a000000000000000000000000", 
    "new_tx_bytes": 282, 
    "other_tx_hashes": [
      "653b2e0b2061788a9f93d8d0a7dbf469f72407b1944ac27b9d9d70e6e9c19841", 
      "b668088ebd4ecbe61d85a78f09e8d991cb40fefea2988aefa514d88304777114", 
      "ea171233a6dc21edc1ef2102959637e0de2d848640abb4cb622c523baa9a5008"
    ], 
    "share_info": {
      "absheight": 1, 
      "abswork": 1048577, 
      "bits": {
        "__floatinginteger_bits__": 504365055
      }, 
      "far_share_hash": null, 
      "max_bits": {
        "__floatinginteger_bits__": 504365055
      }, 
      "merged_addresses": null, 
      "merged_coinbase_info": null, 
      "merged_payout_hash": null, 
      "segwit_data": {
        "txid_merkle_link": {
          "branch": [
            45788159464033286127369463833799921008767842079284580797967791505657263396929, 
            73871307035585373679039297950815448972386762858795771027328847431548379830691
          ], 
          "index": 0
        }, 
        "wtxid_merkle_root": 114827900443378441823717646130880161203726997094886044968725561990880823519200
      }, 
      "share_data": {
        "coinbase": {
          "__hex__": "0380841e"
        }, 
        "desired_version": 36, 
        "donation": 655, 
        "nonce": 1526618878, 
        "previous_share_hash": null, 
        "pubkey_hash": 6495562832581790663061892574634853316331521383, 
        "pubkey_type": 0, 
        "stale_info": null, 
        "subsidy": 1250000000
      }, 
      "timestamp": 1700000000
    }, 
    "share_info_packed_hex": "0000000000000000000000000000000000000000000000000000000000000000040380841efe5afe5a67452301efcdab8967452301efcdab896745230100fe807c814a8f020024024198c1e9e6709d9d7bc24a94b10724f769f4dba7d0d8939f8a7861200b2e3b65a399a3aa5c882460991ce704a82f95cbadb46d954be5fc31a62e392898ad51a3e0a7b2792d1f7aed64cf8e109f4ab097c1eda874e8fac8211e2d76f3d949defd000000000000000000000000000000000000000000000000000000000000000000ffff0f1effff0f1e00f1536501000000fe01001000000000000000000000000000000000000000000000000000000000000000000000", 
    "template_weight": 282
  }, 
  "block_target_hex": "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 
  "desired_target_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 
  "frozen_epoch": 1700000000.0, 
  "gbt_transaction_fees": [
    1000, 
    2000, 
    3000
  ], 
  "gbt_transaction_hashes": [
    "653b2e0b2061788a9f93d8d0a7dbf469f72407b1944ac27b9d9d70e6e9c19841", 
    "b668088ebd4ecbe61d85a78f09e8d991cb40fefea2988aefa514d88304777114", 
    "ea171233a6dc21edc1ef2102959637e0de2d848640abb4cb622c523baa9a5008"
  ], 
  "gbt_transactions": [
    "0100000001111111111111111111111111111111111111111111111111111111111111111100000000085151515151515151ffffffff01a0860100000000001976a914202020202020202020202020202020202020202088ac00000000", 
    "010000000112111111111111111111111111111111111111111111111111111111111111110100000009515151515151515151ffffffff01888a0100000000001976a914212121212121212121212121212121212121212188ac00000000", 
    "01000000011311111111111111111111111111111111111111111111111111111111111111020000000a51515151515151515151ffffffff01708e0100000000001976a914222222222222222222222222222222222222222288ac00000000"
  ], 
  "height": 2000000, 
  "net": "litecoin", 
  "pubkey_hash": "0123456789abcdef0123456789abcdef01234567", 
  "pubkey_type": 0, 
  "scenario": "threetx", 
  "share_version": 36, 
  "subsidy": 1250000000, 
  "user": "difftest_p2pkh", 
  "v36_active": true
}
)GOLDEN"},
    {"ltc_gentx_threetx_difftest_p2wpkh.json", R"GOLDEN({
  "_comment": "OFFLINE golden vector for the LTC gentx path. Frozen reference target for c2pool ltc_gentx_dump. Regenerate with p2pool.test.gen_gentx_golden.", 
  "artifact": {
    "gentx_hex": "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff040380841effffffff030000000000000000266a24aa21a9ed243eab01da61ad7ef367a2a87552014df27caa9b8cb9ff30e199ee322827e6be807c814a0000000017a9148c6272621d89e8fa526dd86acff60c7136be8e858700000000000000002a6a285f13a7cb5ac643623fc53d6984c6b9970329955d335eb00c9a066b6a6a87c834000000000000000001205b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d00000000", 
    "gentx_txid_hex": "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff040380841effffffff030000000000000000266a24aa21a9ed243eab01da61ad7ef367a2a87552014df27caa9b8cb9ff30e199ee322827e6be807c814a0000000017a9148c6272621d89e8fa526dd86acff60c7136be8e858700000000000000002a6a285f13a7cb5ac643623fc53d6984c6b9970329955d335eb00c9a066b6a6a87c834000000000000000000000000", 
    "new_tx_bytes": 282, 
    "other_tx_hashes": [
      "653b2e0b2061788a9f93d8d0a7dbf469f72407b1944ac27b9d9d70e6e9c19841", 
      "b668088ebd4ecbe61d85a78f09e8d991cb40fefea2988aefa514d88304777114", 
      "ea171233a6dc21edc1ef2102959637e0de2d848640abb4cb622c523baa9a5008"
    ], 
    "share_info": {
      "absheight": 1, 
      "abswork": 1048577, 
      "bits": {
        "__floatinginteger_bits__": 504365055
      }, 
      "far_share_hash": null, 
      "max_bits": {
        "__floatinginteger_bits__": 504365055
      }, 
      "merged_addresses": null, 
      "merged_coinbase_info": null, 
      "merged_payout_hash": null, 
      "segwit_data": {
        "txid_merkle_link": {
          "branch": [
            45788159464033286127369463833799921008767842079284580797967791505657263396929, 
            73871307035585373679039297950815448972386762858795771027328847431548379830691
          ], 
          "index": 0
        }, 
        "wtxid_merkle_root": 114827900443378441823717646130880161203726997094886044968725561990880823519200
      }, 
      "share_data": {
        "coinbase": {
          "__hex__": "0380841e"
        }, 
        "desired_version": 36, 
        "donation": 655, 
        "nonce": 1526618878, 
        "previous_share_hash": null, 
        "pubkey_hash": 12991125665163581326123785149269706632663042766, 
        "pubkey_type": 1, 
        "stale_info": null, 
        "subsidy": 1250000000
      }, 
      "timestamp": 1700000000
    }, 
    "share_info_packed_hex": "0000000000000000000000000000000000000000000000000000000000000000040380841efe5afe5ace8a4602de9b5713cf8a4602de9b5713cf8a460201fe807c814a8f020024024198c1e9e6709d9d7bc24a94b10724f769f4dba7d0d8939f8a7861200b2e3b65a399a3aa5c882460991ce704a82f95cbadb46d954be5fc31a62e392898ad51a3e0a7b2792d1f7aed64cf8e109f4ab097c1eda874e8fac8211e2d76f3d949defd000000000000000000000000000000000000000000000000000000000000000000ffff0f1effff0f1e00f1536501000000fe01001000000000000000000000000000000000000000000000000000000000000000000000", 
    "template_weight": 282
  }, 
  "block_target_hex": "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 
  "desired_target_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 
  "frozen_epoch": 1700000000.0, 
  "gbt_transaction_fees": [
    1000, 
    2000, 
    3000
  ], 
  "gbt_transaction_hashes": [
    "653b2e0b2061788a9f93d8d0a7dbf469f72407b1944ac27b9d9d70e6e9c19841", 
    "b668088ebd4ecbe61d85a78f09e8d991cb40fefea2988aefa514d88304777114", 
    "ea171233a6dc21edc1ef2102959637e0de2d848640abb4cb622c523baa9a5008"
  ], 
  "gbt_transactions": [
    "0100000001111111111111111111111111111111111111111111111111111111111111111100000000085151515151515151ffffffff01a0860100000000001976a914202020202020202020202020202020202020202088ac00000000", 
    "010000000112111111111111111111111111111111111111111111111111111111111111110100000009515151515151515151ffffffff01888a0100000000001976a914212121212121212121212121212121212121212188ac00000000", 
    "01000000011311111111111111111111111111111111111111111111111111111111111111020000000a51515151515151515151ffffffff01708e0100000000001976a914222222222222222222222222222222222222222288ac00000000"
  ], 
  "height": 2000000, 
  "net": "litecoin", 
  "pubkey_hash": "02468acf13579bde02468acf13579bde02468ace", 
  "pubkey_type": 1, 
  "scenario": "threetx", 
  "share_version": 36, 
  "subsidy": 1250000000, 
  "user": "difftest_p2wpkh", 
  "v36_active": true
}
)GOLDEN"},
};

} // namespace ltc_t5_golden
