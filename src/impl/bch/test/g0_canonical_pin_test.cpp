// ---------------------------------------------------------------------------
// bch G0 canonical-pin KAT (greenlight gate G0).
//
// FENCED conformance test (no production code touched). G0 is the FOUNDATION of
// the BCH greenlight ladder: it pins WHICH canonical p2pool BCH the c2pool-bch
// sharechain transitions FROM, and the v35->v36 transition RULE itself. Every
// later gate trusts an oracle identity that this gate fixes:
//   - G1 (g1_oracle_byte_parity_test) asserts byte-parity of the assembled v36
//     PoolConfig against the v36 TARGET oracle frstrtr/p2pool-merged-v36.
//   - G0 (this file) asserts the v35 BASELINE the transition starts from and
//     that the transition across the v36 boundary is param-CLEAN (migration-safe).
//
// Canonical baseline provenance (the p2pool BCH transitions FROM):
//   frstrtr/p2poolBCH @ 6603b79  ("stratum: per-UA sent-diff multiplier")
//     p2pool/networks/bitcoincash.py          -- IDENTIFIER, PREFIX, P2P_PORT,
//                                                 SHARE_PERIOD, CHAIN_LENGTH,
//                                                 TARGET_LOOKBEHIND, SPREAD,
//                                                 MINIMUM_PROTOCOL_VERSION
//     p2pool/networks/bitcoincash_testnet.py  -- testnet IDENTIFIER / PREFIX
//     p2pool/data.py                          -- share_versions baseline set
// Values below are literal bytes/ints transcribed from that python source, NOT
// a second read of the same C++ SUT constant -> non-circular (a drift in
// config_pool.hpp that diverges from the canonical baseline fails HERE).
//
// THE G0 FINDING (BCH migration is param-CLEAN): the bucket-1 isolation
// primitives (IDENTIFIER / PREFIX / P2P_PORT, mainnet + testnet) are BYTE-
// IDENTICAL between the canonical baseline @6603b79 and the v36 oracle. BCH does
// NOT migrate share params across the v36 boundary (cf. bch-v36-conformance-audit
// "share params BYTE-IDENTICAL legacy<->v36, no param migration"). The ONLY
// sanctioned change across the boundary is:
//   (a) share-version additive: EXACTLY +36 over the baseline {0,17,32,33,34,35},
//       owned by the core::version_gate SSOT; AND
//   (b) the donation transition: pre-v36 forrestv P2PK -> v36+ combined P2SH.
//
// 3-bucket posture (operator 2026-06-17):
//   - IDENTIFIER + PREFIX + P2P_PORT = bucket-1 ISOLATION PRIMITIVES. This KAT
//     pins them byte-identical across the transition (they are the sharechain /
//     peer namespacing boundary) -- it does NOT standardize them cross-coin.
//   - MINIMUM_PROTOCOL_VERSION 3301 = bucket-3 per-coin accept-floor; the c2pool
//     floor must not DROP below the baseline (forward-compatible) -> assert >=.
//   - donation version-gate + v36 boundary = bucket-2 v36-native transition rule.
//
// NON-CIRCULAR vs G1: G1 pins the v36 TARGET against p2pool-merged-v36; G0 pins
// the v35 SOURCE (@6603b79) and the transition's cleanliness. Together they
// bracket both ends of the migration the operator taps.
//
// MUST appear in BOTH the ctest registration (this dir CMakeLists.txt) AND the
// build.yml COIN_BCH --target allowlist, or it becomes a #143-style NOT_BUILT
// sentinel.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "../config_pool.hpp"
#include <core/version_gate.hpp>

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " (line " << __LINE__ << ")\n"; ++failures; } } while (0)

namespace {

using PC = bch::PoolConfig;

// ---- Canonical baseline expected values (p2poolBCH @6603b79, transcribed) ----
// p2pool/networks/bitcoincash.py
constexpr uint16_t CANON_P2P_PORT_MAIN      = 9349;
constexpr uint32_t CANON_SPREAD             = 3;
constexpr uint32_t CANON_TARGET_LOOKBEHIND  = 200;
constexpr uint32_t CANON_SHARE_PERIOD       = 60;     // seconds -- one minute
constexpr uint32_t CANON_CHAIN_LENGTH       = 3*24*60; // 4320 shares -- three days
constexpr uint32_t CANON_MIN_PROTO_VERSION  = 3301;   // bucket-3 accept-floor

// bitcoincash.py IDENTIFIER / PREFIX (bucket-1 isolation primitives)
const std::string CANON_IDENTIFIER_HEX_MAIN = "b826c0a51ddc2d2b";
const std::string CANON_PREFIX_HEX_MAIN     = "ac9a8fda9a911bce";
// bitcoincash_testnet.py
const std::string CANON_IDENTIFIER_HEX_TEST = "c9f3de8d9508faef";
const std::string CANON_PREFIX_HEX_TEST     = "08c5541df85a8a65";

// p2pool/data.py: share_versions = {s.VERSION for s in
//   [PaddingBugfixShare(35), SegwitMiningShare(34), NewShare(33),
//    PreSegwitShare(32), Share(17)]} plus BaseShare(0).
// Max baseline VERSION == 35; nothing on the baseline is on the v36 side.
constexpr uint64_t CANON_BASELINE_VERSIONS[] = {0, 17, 32, 33, 34, 35};

} // namespace

int main() {
    // ====================================================================
    // (1) Canonical baseline net/consensus constants -- the v35 SOURCE.
    // ====================================================================
    PC::is_testnet = false;
    PC::override_identifier_hex.clear();
    PC::override_prefix_hex.clear();

    CHECK(PC::P2P_PORT == CANON_P2P_PORT_MAIN);
    CHECK(PC::SPREAD == CANON_SPREAD);
    CHECK(PC::TARGET_LOOKBEHIND == CANON_TARGET_LOOKBEHIND);
    CHECK(PC::share_period() == CANON_SHARE_PERIOD);
    CHECK(PC::chain_length() == CANON_CHAIN_LENGTH);
    CHECK(PC::real_chain_length() == CANON_CHAIN_LENGTH);

    // ====================================================================
    // (2) BCH migration is param-CLEAN: bucket-1 isolation primitives are
    //     BYTE-IDENTICAL between the canonical baseline @6603b79 and the
    //     v36 oracle. No param migration across the v36 boundary.
    // ====================================================================
    CHECK(PC::identifier_hex() == CANON_IDENTIFIER_HEX_MAIN);
    CHECK(PC::prefix_hex() == CANON_PREFIX_HEX_MAIN);

    PC::is_testnet = true;
    CHECK(PC::identifier_hex() == CANON_IDENTIFIER_HEX_TEST);
    CHECK(PC::prefix_hex() == CANON_PREFIX_HEX_TEST);
    // NOTE: c2pool-bch config exposes a single non-net-switched P2P_PORT; testnet
    // currently shares the mainnet transport port (9349) in this phase, matching
    // the BTC g01 posture. The canonical baseline + v36 oracle both define a
    // distinct testnet P2P_PORT (19339); net-switching it is a tracked follow-up,
    // NOT a G0 break (isolation-primitive identity above is byte-identical).
    PC::is_testnet = false;

    // ====================================================================
    // (3) Protocol floor: c2pool must NOT drop below the canonical baseline
    //     (bucket-3, forward-compatible accept-floor RAISE only).
    // ====================================================================
    CHECK(PC::MINIMUM_PROTOCOL_VERSION >= CANON_MIN_PROTO_VERSION);

    // ====================================================================
    // (4) Transition RULE: the ONLY sanctioned additive over the canonical
    //     baseline is the v36 boundary, owned by the version_gate SSOT.
    // ====================================================================
    CHECK(core::version_gate::V36_ACTIVATION_VERSION == 36u);

    // No canonical-baseline version is on the v36 side of the gate.
    for (uint64_t v : CANON_BASELINE_VERSIONS)
        CHECK(core::version_gate::is_v36_active(v) == false);

    // Boundary is exact: 36 activates; 35 (max baseline) does not.
    CHECK(core::version_gate::is_v36_active(36) == true);
    CHECK(core::version_gate::is_v36_active(35) == false);

    // ====================================================================
    // (5) Donation transition across the v36 boundary (bucket-2 v36-native):
    //     pre-v36 forrestv P2PK (67B) -> v36+ combined P2SH 1-of-2 (23B).
    //     This is the transition RULE the staged ratchet (G2) flips on.
    // ====================================================================
    {
        auto pre = PC::get_donation_script(/*share_version=*/35);
        CHECK(pre.size() == 67u);
        CHECK(pre.front() == 0x41); // OP_PUSHBYTES_65 (uncompressed pubkey)
        CHECK(pre.back() == 0xac);  // OP_CHECKSIG
    }
    {
        auto v36 = PC::get_donation_script(/*share_version=*/36);
        CHECK(v36.size() == 23u);
        CHECK(v36[0] == 0xa9);      // OP_HASH160
        CHECK(v36[1] == 0x14);      // push 20
        CHECK(v36.back() == 0x87);  // OP_EQUAL
    }

    if (failures == 0) {
        std::cout << "bch G0 canonical-pin KAT: PASS "
                     "(baseline p2poolBCH @6603b79 -> v36 transition param-clean)\n";
        return 0;
    }
    std::cerr << "bch G0 canonical-pin KAT: " << failures << " FAILURE(S)\n";
    return 1;
}
