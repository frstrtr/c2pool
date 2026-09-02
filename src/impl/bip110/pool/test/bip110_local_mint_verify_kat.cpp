// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_local_mint_verify_kat — FINDING A / #941 red→green KAT for the M3
// sharechain "no bip110 shares even though it is live" symptom.
//
// The operator saw /web/sync_status report chain_size:0 / verified_size:0 /
// has_shares:false while the node was actively minting. Two independent defects
// produced that: (A1) the dashboard callbacks were never wired (covered by the
// build + the flag-ON wiring in main_bip110), and (A2 / #941) a locally-minted
// share only ever landed in the RAW chain — it was NEVER added to the VERIFIED
// set, so verified_size stayed 0 and the persistence callback (which feeds the
// LevelDB flush buffer) never fired.
//
// This KAT proves A2 at the tracker level — the layer get_tracker_snapshot()
// reads (chain_count = chain.size(), verified_count = verified.size()):
//   [RED, pre-fix]  create_local_share() alone: chain.size()==1 but
//                   verified.size()==0 and the persist callback did NOT fire —
//                   i.e. a mined share is INVISIBLE (has_shares would be false)
//                   and NON-PERSISTENT.
//   [GREEN, fix]    mark_own_share_verified() (the direct own-share verify the
//                   mint path now calls) puts the share in verified AND fires
//                   the persist callback — verified.size()==1, in verified set,
//                   in the persist buffer.
//   [idempotent]    a second mark_own_share_verified() is a no-op (no double
//                   verify, no duplicate persist).
//
// The fix does NOT route the own share through the crash-prone peer
// attempt_verify() path (the one disabled after the kr1z1s SIGSEGV): the own
// share is trivially valid (create_local_share cross-checked its gentx), so it
// is added to verified directly, under the exclusive-lock discipline the mint
// path already holds. This KAT exercises that direct path.

#include "../share_tracker.hpp"     // ShareTracker (+ mark_own_share_verified) -> create_local_share
#include "../config_pool.hpp"
#include "../../coin/block.hpp"     // coin::BlockHeaderType

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

int g_fail = 0;

void expect_true(const std::string& name, bool cond)
{
    if (cond) std::printf("  [ok]   %s\n", name.c_str());
    else { std::printf("  [FAIL] %s\n", name.c_str()); ++g_fail; }
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

// REAL BIP-110 block 961640 v2 header (flags/clear_bits/xor_key zero — passes
// check_header_fail_closed). Reused as a well-formed 164B v2 header carrier; we
// grind its nonce for the KAT's easy share target. (Same carrier as the mint KAT.)
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

    std::printf("bip110_local_mint_verify_kat: FINDING A/#941 own-share verify + persist\n");

    ShareTracker tracker;

    // Simulate the NodeImpl persistence buffer: the node wires m_on_share_verified
    // to push the hash into m_verified_flush_buf (node.hpp). Record the same way
    // so we can assert the minted share ENTERS the persist set.
    std::vector<uint256> persist_buf;
    tracker.m_on_share_verified = [&persist_buf](const uint256& h) { persist_buf.push_back(h); };

    // Parse the real 164B v2 header.
    std::vector<unsigned char> hdr_bytes = from_hex(HDR_961640);
    coin::BlockHeaderType full;
    { PackStream ps(hdr_bytes); ps >> full; }

    // 25-byte P2PKH payout script (gives the share a pubkey_hash identity).
    std::vector<unsigned char> payout_script = {
        0x76, 0xa9, 0x14,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,
        0xbb,0xcc,0xdd,0xee,0xff,0x01,0x02,0x03,0x04,0x05,
        0x88, 0xac };

    BaseScript coinbase_bs;
    coinbase_bs.m_data = { 0x03, 0x28,0xab,0x0e, 0x00, 0x00, 0x2f, 0x62, 0x69,
                           0x70, 0x31, 0x31, 0x30, 0x2f, 0x00, 0x00, 0x00, 0x00 };

    const uint64_t KAT_NONCE = 0x0102030405060708ULL;
    std::vector<unsigned char> actual_coinbase(80, 0xAB);
    for (int i = 0; i < 32; ++i) actual_coinbase[actual_coinbase.size() - 44 + i] = (unsigned char)(0x40 + i);
    std::memcpy(actual_coinbase.data() + actual_coinbase.size() - 12, &KAT_NONCE, 8);
    actual_coinbase[actual_coinbase.size() - 4] = 0;
    actual_coinbase[actual_coinbase.size() - 3] = 0;
    actual_coinbase[actual_coinbase.size() - 2] = 0;
    actual_coinbase[actual_coinbase.size() - 1] = 0;

    uint128 frozen_abswork; frozen_abswork.SetHex("10000000000000309");
    const uint32_t EASY_BITS = 0x207fffff;
    const uint64_t subsidy = 312500000ULL;

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
                /* witness_commitment */    std::string{},
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
                /* has_frozen */            true,
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

    expect_true("[pre] mint succeeded (non-null share under easy target)", !minted.IsNull());
    if (minted.IsNull()) { std::printf("RESULT: FAIL — mint produced no share.\n"); return 1; }

    // ── RED (pre-fix state): create_local_share ONLY touched the raw chain ──
    expect_true("[RED] chain_size>0 after mint (has_shares would be true)",
                tracker.chain.size() == 1 && tracker.chain.contains(minted));
    expect_true("[RED] verified_size==0 after mint alone (the #941 bug: mint does NOT verify)",
                tracker.verified.size() == 0);
    expect_true("[RED] persist buffer empty after mint alone (verified callback never fired)",
                persist_buf.empty());

    // ── GREEN (the fix): direct own-share verify the mint path now performs ──
    bool ok = tracker.mark_own_share_verified(minted);
    expect_true("[GREEN] mark_own_share_verified returned true", ok);
    expect_true("[GREEN] verified_size>0 (share now VISIBLE — verified_count reflects the mint)",
                tracker.verified.size() == 1);
    expect_true("[GREEN] minted share is in the VERIFIED set", tracker.verified.contains(minted));
    expect_true("[GREEN] minted share entered the PERSIST buffer (m_on_share_verified fired)",
                persist_buf.size() == 1 && persist_buf[0] == minted);
    expect_true("[GREEN] raw chain still intact (chain_size unchanged)",
                tracker.chain.size() == 1 && tracker.chain.contains(minted));

    // ── idempotent: a second call must NOT double-verify or double-persist ──
    bool ok2 = tracker.mark_own_share_verified(minted);
    expect_true("[idem] second mark_own_share_verified still true (already verified)", ok2);
    expect_true("[idem] verified_size still 1 (no duplicate)", tracker.verified.size() == 1);
    expect_true("[idem] persist buffer still 1 (no duplicate persist)", persist_buf.size() == 1);

    if (g_fail == 0) {
        std::printf("RESULT: PASS — a mined share is now VISIBLE (verified_size>0) and enters "
                    "the persist set, via the direct own-share verify (NOT peer attempt_verify).\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d assertion(s) failed.\n", g_fail);
    return 1;
}
