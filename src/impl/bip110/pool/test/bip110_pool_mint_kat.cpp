// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_pool_mint_kat — END-TO-END known-answer test for the M3 v36 sharechain
// MINT primitive (bip110::pool::create_local_share). The node_compile KAT only
// takes the mint's ADDRESS (instantiation); the identity KAT reproduces a real
// block hash on the verify side. This KAT is the missing piece cont2 flagged: it
// RUNS the mint to completion, pulls the minted share back out of the tracker,
// and asserts:
//   [1] the mint succeeds (non-null hash) and the share lands in the tracker;
//   [2] donation == 66 (the wire-genesis FREEZE value, 0.1%);
//   [3] the abswork %2^64 wrap (PR-A-cont NIT-2) actually dropped the high 64
//       bits (we feed an abswork with bit-64 set and prove only the low 64 survive);
//   [4] segwit_data is populated with the REAL coinbase-only witness merkle root
//       ZERO (merkle([0]), python v36 data.py:1090) when no witness commitment is
//       supplied — NOT the 0xff None-sentinel;
//   [5] the coinbase OP_RETURN round-trips: the last_txout_nonce embedded in the
//       mined coinbase is the one stored on the share;
//   [6] MINT/VERIFY HASH SYMMETRY: recomputing compute_share_hash over the minted
//       share's small header + the reconstructed merkle root (the exact
//       derivation the verify path at share_check.hpp:2592-2597 uses) reproduces
//       the share's stored m_hash byte-for-byte — i.e. the minted hash IS the
//       BLAKE2b block-identity hash a peer will recompute on verify.
//
// The share PoW must meet the share target or create_local_share early-returns
// null (share_check.hpp:2607). override_bits/override_max_bits (applied on the
// has_frozen path) set an artificially easy target (~2^255) and we GRIND the
// header nonce until the BLAKE2b share hash falls under it — a handful of tries.

#include "../share_tracker.hpp"     // ShareTracker -> share_check.hpp (create_local_share) + share_identity + share_types
#include "../config_pool.hpp"
#include "../../coin/block.hpp"     // coin::BlockHeaderType

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace {

int g_fail = 0;

void expect_true(const std::string& name, bool cond)
{
    if (cond) std::printf("  [ok]   %s\n", name.c_str());
    else { std::printf("  [FAIL] %s\n", name.c_str()); ++g_fail; }
}

void expect_eq_hex(const std::string& name, const std::string& got, const std::string& want)
{
    if (got == want) std::printf("  [ok]   %s\n", name.c_str());
    else {
        std::printf("  [FAIL] %s\n         got : %s\n         want: %s\n",
                    name.c_str(), got.c_str(), want.c_str());
        ++g_fail;
    }
}

std::vector<unsigned char> from_hex(const std::string& s)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::vector<unsigned char> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<unsigned char>((nib(s[i]) << 4) | nib(s[i + 1])));
    return out;
}

// REAL BIP-110 block 961640 v2 header (flags=0/clear_bits=0/xor_key=0 — passes
// check_header_fail_closed). Reused as a well-formed 164B v2 header carrier; we
// grind its nonce for the KAT's easy share target.
const char* HDR_961640 =
    "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000"
    "c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc768"
    "4dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d030000000000000000"
    "0000001e0300000000000000000000000000000000000068ac0e0000000000000000000000"
    "00000000000000000000000000000000000000000000000000";

} // namespace

int main()
{
    using namespace bip110::pool;
    namespace coin = bip110::coin;

    std::printf("bip110_pool_mint_kat: M3 v36 sharechain MINT end-to-end\n");

    ShareTracker tracker;

    // Parse the real 164B v2 header into a full coin::BlockHeaderType.
    std::vector<unsigned char> hdr_bytes = from_hex(HDR_961640);
    coin::BlockHeaderType full;
    { PackStream ps(hdr_bytes); ps >> full; }
    expect_true("[pre] carrier header is v2 (flags/clear_bits/xor_key zero)",
                full.is_v2() && full.m_flags == 0);

    // A 25-byte P2PKH payout script so the share gets a pubkey_hash/type identity.
    std::vector<unsigned char> payout_script = {
        0x76, 0xa9, 0x14,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,
        0xbb,0xcc,0xdd,0xee,0xff,0x01,0x02,0x03,0x04,0x05,
        0x88, 0xac };

    // ~20-byte coinbase scriptSig (share.m_coinbase is bounded 2..100 bytes).
    BaseScript coinbase_bs;
    coinbase_bs.m_data = { 0x03, 0x28,0xab,0x0e, 0x00, 0x00, 0x2f, 0x62, 0x69,
                           0x70, 0x31, 0x31, 0x30, 0x2f, 0x00, 0x00, 0x00, 0x00 };

    // A KNOWN full coinbase (actual_coinbase_bytes): create_local_share hashes
    // THESE bytes for the tx-merkle root and extracts ref_hash + last_txout_nonce
    // from the last 44 bytes (share_check.hpp:2458,2569). We embed a sentinel
    // last_txout_nonce (8 bytes at size-12) and assert it round-trips onto the
    // share, and we recompute the merkle root from these same bytes for the
    // mint/verify hash-symmetry check.
    const uint64_t KAT_NONCE = 0x0102030405060708ULL;
    std::vector<unsigned char> actual_coinbase(80, 0xAB);   // 80 > 44, arbitrary body
    // ref_hash[32] || last_txout_nonce[8] || locktime[4] = final 44 bytes.
    for (int i = 0; i < 32; ++i) actual_coinbase[actual_coinbase.size() - 44 + i] = (unsigned char)(0x40 + i);
    std::memcpy(actual_coinbase.data() + actual_coinbase.size() - 12, &KAT_NONCE, 8);
    actual_coinbase[actual_coinbase.size() - 4] = 0;  // locktime = 0
    actual_coinbase[actual_coinbase.size() - 3] = 0;
    actual_coinbase[actual_coinbase.size() - 2] = 0;
    actual_coinbase[actual_coinbase.size() - 1] = 0;

    // abswork with bit-64 SET so the %2^64 wrap is observable: GetLow64() == 777.
    uint128 frozen_abswork; frozen_abswork.SetHex("10000000000000309");  // (1<<64) + 0x309
    expect_true("[pre] test abswork has high bits (pre-wrap != low64)",
                frozen_abswork != uint128(frozen_abswork.GetLow64()));

    // Easy share target (~2^255) via override_bits (has_frozen path): grind the
    // header nonce until the BLAKE2b share hash falls under it.
    const uint32_t EASY_BITS = 0x207fffff;
    const uint64_t subsidy = 312500000ULL;   // 3.125 BTC-era

    uint256 minted;
    uint32_t grind = 0;
    for (; grind < 200000; ++grind) {
        full.m_nonce = grind;
        uint256 h;
        try {
            h = create_local_share(
                tracker, full, coinbase_bs,
                /* subsidy */               subsidy,
                /* prev_share (genesis) */  uint256(),
                /* merkle_branches */       std::vector<uint256>{},
                payout_script,
                /* donation */              66,
                /* merged_addrs */          {},
                /* stale_info */            StaleInfo::none,
                /* segwit_active */         true,
                /* witness_commitment */    std::string{},   // coinbase-only -> ZERO root
                /* message_data */          {},
                /* actual_coinbase_bytes */ actual_coinbase,
                /* witness_root */          uint256(),
                /* override_max_bits */     EASY_BITS,
                /* override_bits */         EASY_BITS,
                /* frozen_absheight */      1,
                /* frozen_abswork */        frozen_abswork,
                /* frozen_far_share_hash */ uint256(),
                /* frozen_timestamp */      full.m_timestamp,
                /* frozen_merged_payout */  uint256(),
                /* has_frozen */            true,           // REQUIRED for override_bits to apply
                /* frozen_merkle_branches*/ std::vector<uint256>{},
                /* frozen_witness_root */   uint256(),
                /* frozen_merged_cb_info */ std::vector<unsigned char>{},
                /* share_version */         36,
                /* desired_version */       36);
        } catch (const std::exception& e) {
            std::printf("  [FAIL] create_local_share threw: %s\n", e.what());
            ++g_fail; break;
        }
        if (!h.IsNull()) { minted = h; break; }
    }

    expect_true("[1] mint succeeded (non-null share hash under easy target)", !minted.IsNull());
    expect_true("[1] mint landed in the tracker", tracker.chain.contains(minted));
    if (minted.IsNull() || !tracker.chain.contains(minted)) {
        std::printf("RESULT: FAIL — mint did not produce a tracked share (grind=%u).\n", grind);
        return 1;
    }
    std::printf("  [info] minted after %u nonce grind(s): %s\n", grind, minted.GetHex().c_str());

    // Recompute the expected merkle root the SAME way the mint (share_check.hpp:
    // 2581-2592) and the verify path (:704-718) do: Hash(actual_coinbase) folded
    // through the (empty) merkle link.
    uint256 gentx_hash = Hash(std::span<const unsigned char>(actual_coinbase.data(), actual_coinbase.size()));

    tracker.chain.get(minted).share.invoke([&](auto* s) {
        expect_true("[2] donation == 66 (wire-genesis FREEZE 0.1%)", s->m_donation == 66);

        expect_true("[3] abswork %2^64 wrap dropped the high bits (== low64)",
                    s->m_abswork == uint128(s->m_abswork.GetLow64()));
        expect_true("[3] abswork wrap value == 0x309 (777) — high bit-64 discarded",
                    s->m_abswork == uint128(0x309));

        expect_true("[4] segwit_data populated (v36-genesis: always has_value)",
                    s->m_segwit_data.has_value());
        if (s->m_segwit_data.has_value())
            expect_eq_hex("[4] wtxid root == ZERO (coinbase-only real root, merkle([0]); "
                          "python v36 data.py:1090 — NOT the 0xff None-sentinel)",
                          s->m_segwit_data->m_wtxid_merkle_root.GetHex(),
                          uint256().GetHex());

        expect_true("[5] coinbase last_txout_nonce round-trips onto the share",
                    s->m_last_txout_nonce == KAT_NONCE);

        // [6] MINT/VERIFY hash symmetry.
        uint256 mr = check_merkle_link(gentx_hash, s->m_merkle_link);
        uint256 recomputed = compute_share_hash(s->m_min_header, mr);
        expect_eq_hex("[6] compute_share_hash(minted small-header, merkle) == stored m_hash",
                      recomputed.GetHex(), s->m_hash.GetHex());
        expect_eq_hex("[6] stored m_hash == the value create_local_share returned",
                      s->m_hash.GetHex(), minted.GetHex());
        expect_true("[6] m_pow_hash set (self-validation passed) and == m_hash",
                    s->m_pow_hash == s->m_hash);
    });

    if (g_fail == 0) {
        std::printf("RESULT: PASS — MINT end-to-end: share minted, fields round-trip, "
                    "abswork wrapped, segwit sentinel, mint==verify BLAKE2b hash.\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d check(s) failed.\n", g_fail);
    return 1;
}
