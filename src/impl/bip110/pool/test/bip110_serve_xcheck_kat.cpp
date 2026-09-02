// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_serve_xcheck_kat — pre-serve reward-safety XCHECK sub-check (e) KAT.
//
// THE COVERAGE GAP THIS CLOSES: the 10 bip110 KATs exercise the MINT / consensus
// math, but NONE exercised the live SERVE template + the [BIP110-WS] pre-serve
// reward-safety XCHECK that build_connection_coinbase runs before handing a job to
// miners. That gap hid a FLAG-ON serve-path regression caught LIVE on contabo:
//
//   [BIP110-WS] XCHECK FAILED — refusing to serve populated template ... — job
//   suppressed.
//
// on EVERY notify, so the pool served NO work with --bip110-sharechain ON.
//
// ROOT CAUSE (fixed): XCHECK sub-check (e) recomputes the coinbase witness
// commitment as SHA256d(witness_merkle_root || reserved) and compares it to the
// commitment the coinbase carries. It hardcoded the reserved half to 32 zeros.
// But the flag-ON served coinbase legitimately carries the P2Pool witness reserved
// value ('[P2Pool]'*4) — its commitment output is compute_p2pool_witness_commitment
// over the real ZERO witness root, which is SHA256d(ZERO || '[P2Pool]'*4). So the
// recompute (SHA256d(ZERO || 0*32)) never matched the coinbase (SHA256d(ZERO ||
// '[P2Pool]'*4)) and (e) rejected a VALID, consensus-required construction. This
// construction is required: the found block's segwit consensus check is commitment
// == SHA256d(witness_root || reserved) with reserved='[P2Pool]'*4, and mint==verify
// needs the served coinbase txid to match generate_share_transaction. The fix is
// XCHECK (e) using the SAME reserved value the coinbase carries (serve_xcheck.hpp
// :xcheck_witness_commitment), not a hardcoded zero.
//
// THIS KAT drives the PRODUCTION SSOT bip110::stratum::xcheck_witness_commitment
// against the PRODUCTION mint-side commitment builder compute_p2pool_witness_
// commitment (share_check.hpp) — two independently-defined production functions —
// and asserts:
//   [1] the FLAG-ON serve template (P2Pool commitment + '[P2Pool]'*4 reserved)
//       PASSES the XCHECK  (RED on the pre-fix tree: the hardcoded-zero recompute
//       rejected it and all work was suppressed; GREEN after the fix).
//   [2] the OFF/M2 serve template (zero-reserved commitment + empty reserved)
//       PASSES the XCHECK unchanged (byte-identical M2 path is not disturbed).
//   [3] STRENGTH — the check is NOT weakened: the flag-ON commitment with a WRONG
//       (zero) reserved value FAILS (this is the exact pre-fix rejection), a
//       tampered commitment FAILS, and the M2 commitment with a WRONG ('[P2Pool]'*4)
//       reserved value FAILS.
// Network-free, no HeaderChain, no daemon.

#include "../share_tracker.hpp"            // share_check.hpp: compute_p2pool_witness_commitment,
                                           // bip110::pool::P2POOL_WITNESS_NONCE
#include "../../coin/template_builder.hpp" // coin::witness_merkle_root
#include "../../stratum/serve_xcheck.hpp"  // bip110::stratum::xcheck_witness_commitment (SSOT)

#include <core/uint256.hpp>
#include <core/hash.hpp>

#include <cstdio>
#include <cstdint>
#include <vector>

static int g_fail = 0;
static void expect_true(const char* name, bool cond) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) ++g_fail;
}

// The witness-commitment aa21a9ed output prefix (OP_RETURN PUSH_36 + magic).
static std::vector<unsigned char> commit_output(const uint256& commitment) {
    std::vector<unsigned char> sc = {0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};
    const auto cb = commitment.GetChars();
    sc.insert(sc.end(), cb.begin(), cb.end());
    return sc;
}

int main() {
    using namespace bip110;
    std::printf("bip110_serve_xcheck_kat: pre-serve XCHECK (e) witness-commitment\n");

    // Coinbase-only served template => the witness merkle root collapses to the
    // single ZERO leaf (the coinbase wtxid is defined 0). This is what both the
    // OFF and flag-ON serve paths, and the XCHECK's body re-derivation, produce.
    const std::vector<uint256> body_wtxids;                       // coinbase-only
    const uint256 real_wroot = coin::witness_merkle_root(body_wtxids);   // ZERO
    expect_true("[0] coinbase-only witness merkle root is ZERO", real_wroot.IsNull());

    // The P2Pool witness reserved value the flag-ON coinbase splices into its
    // witness stack (build_connection_coinbase / assemble_gentx_coinbase).
    const std::vector<unsigned char> pool_reserved(
        std::begin(pool::P2POOL_WITNESS_NONCE), std::end(pool::P2POOL_WITNESS_NONCE));
    expect_true("[0] P2Pool witness reserved value is 32 bytes",
                pool_reserved.size() == 32);
    const std::vector<unsigned char> empty_reserved;             // OFF/M2 => 32 zeros

    // ── FLAG-ON serve template commitment (exactly build_connection_coinbase:411-417):
    //    compute_p2pool_witness_commitment(real ZERO root) = SHA256d(ZERO||'[P2Pool]'*4).
    const uint256 pool_commit = pool::compute_p2pool_witness_commitment(real_wroot);
    const std::vector<unsigned char> flag_on_output = commit_output(pool_commit);

    // ── OFF/M2 serve template commitment (build_connection_coinbase:270-289):
    //    SHA256d(ZERO || 0*32).
    uint256 zero_reserved256;                                    // 32 zeros
    const uint256 m2_commit = Hash(real_wroot, zero_reserved256);
    const std::vector<unsigned char> m2_output = commit_output(m2_commit);

    // Sanity: the two constructions are genuinely different commitments (else the
    // whole regression would be vacuous — the bug depends on reserved mattering).
    expect_true("[0] flag-ON and M2 commitments differ (reserved value matters)",
                pool_commit != m2_commit);

    // ── [1] THE REGRESSION: flag-ON serve template PASSES the XCHECK ──────────
    // RED on the pre-fix tree (hardcoded 32-zero reserved => rejected => all work
    // suppressed). GREEN after the fix (reserved derived from the coinbase).
    expect_true("[1] FLAG-ON serve template passes XCHECK (valid work served)",
        stratum::xcheck_witness_commitment(body_wtxids, pool_reserved, flag_on_output));

    // ── [2] OFF/M2 serve template PASSES the XCHECK unchanged ─────────────────
    expect_true("[2] OFF/M2 serve template passes XCHECK (byte-identical path intact)",
        stratum::xcheck_witness_commitment(body_wtxids, empty_reserved, m2_output));

    // ── [3] STRENGTH — the XCHECK is NOT weakened ─────────────────────────────
    // (3a) flag-ON commitment recomputed with the WRONG (zero) reserved value must
    //      FAIL — this is EXACTLY the pre-fix behaviour that suppressed all work,
    //      and proves the fix did not "serve coinbase-only anyway".
    expect_true("[3a] flag-ON commitment with zero reserved is REJECTED (pre-fix bug reproduced)",
        !stratum::xcheck_witness_commitment(body_wtxids, empty_reserved, flag_on_output));
    // (3b) a tampered commitment must FAIL under the correct reserved value.
    {
        std::vector<unsigned char> tampered = flag_on_output;
        tampered.back() ^= 0x01;
        expect_true("[3b] tampered flag-ON commitment is REJECTED",
            !stratum::xcheck_witness_commitment(body_wtxids, pool_reserved, tampered));
    }
    // (3c) the M2 commitment recomputed with the WRONG ('[P2Pool]'*4) reserved
    //      value must FAIL (reserved must match the coinbase in both directions).
    expect_true("[3c] M2 commitment with P2Pool reserved is REJECTED",
        !stratum::xcheck_witness_commitment(body_wtxids, pool_reserved, m2_output));

    if (g_fail == 0) {
        std::printf("RESULT: PASS — flag-ON serve template passes the pre-serve "
                    "XCHECK; OFF path unchanged; check not weakened.\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d assertion(s) failed.\n", g_fail);
    return 1;
}
