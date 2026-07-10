// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::PoolConfig G1 oracle byte-parity KAT (greenlight gate G1).
//
// FENCED conformance test (no production code touched). G1 is the byte-parity
// gate: it pins the fully-assembled bch::PoolConfig net/consensus constants and
// the bucket-1 isolation primitives (PREFIX / IDENTIFIER) against values
// hand-transcribed from the BCH oracle frstrtr/p2pool-merged-v36:
//   networks/bitcoincash.py          -- P2P_PORT, IDENTIFIER, PREFIX,
//                                        MINIMUM_PROTOCOL_VERSION, SHARE_PERIOD,
//                                        CHAIN_LENGTH, SPREAD, TARGET_LOOKBEHIND,
//                                        MAX_TARGET, DUST_THRESHOLD
//   networks/bitcoincash_testnet.py  -- testnet IDENTIFIER / PREFIX
//
// NON-CIRCULAR: the expected side below is literal bytes/ints typed from the
// oracle python source, NOT a second read of the same C++ SUT constant. A drift
// in config_pool.hpp that silently diverges from the oracle fails here even
// though every other bch test (which sources the same SUT constant on both
// sides) stays green.
//
// 3-bucket posture (operator 2026-06-17):
//   - IDENTIFIER + PREFIX  = bucket-1 ISOLATION PRIMITIVES -> pinned per-coin /
//     per-instance as the sharechain + peer namespacing boundary. This KAT
//     GUARDS them against accidental "standardization"; it does NOT unify them.
//   - MINIMUM_PROTOCOL_VERSION 3301 = bucket-3 per-coin accept-floor (transition
//     compat), NOT standardized (see memory share-constant-prescan).
//   - donation version-gate = bucket-2 v36-native (combined P2SH for sv>=36).
//
// SEGWIT_ACTIVATION_VERSION == 0 (BCH has no SegWit) is already pinned by
// coinbase_kat_segwit_predicate_test; not duplicated here.
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
#include <core/uint256.hpp>

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " (line " << __LINE__ << ")\n"; ++failures; } } while (0)

namespace {

using PC = bch::PoolConfig;

// ---- Oracle expected values (frstrtr/p2pool-merged-v36, transcribed) --------
// networks/bitcoincash.py
constexpr uint16_t ORACLE_P2P_PORT          = 9349;
constexpr uint32_t ORACLE_SPREAD            = 3;
constexpr uint32_t ORACLE_TARGET_LOOKBEHIND = 200;
constexpr uint32_t ORACLE_MIN_PROTO_VERSION = 3301;   // bucket-3 accept-floor
constexpr uint32_t ORACLE_SHARE_PERIOD      = 60;     // seconds
constexpr uint32_t ORACLE_CHAIN_LENGTH      = 4320;   // 3 days / 60s
constexpr uint64_t ORACLE_DUST_THRESHOLD    = 100000; // 0.001 BCH

// bitcoincash.py IDENTIFIER / PREFIX (bucket-1 isolation primitives)
const std::string ORACLE_IDENTIFIER_HEX_MAIN = "b826c0a51ddc2d2b";
const std::string ORACLE_PREFIX_HEX_MAIN     = "ac9a8fda9a911bce";
// bitcoincash_testnet.py
const std::string ORACLE_IDENTIFIER_HEX_TEST = "c9f3de8d9508faef";
const std::string ORACLE_PREFIX_HEX_TEST     = "08c5541df85a8a65";

// MAX_TARGET = 2**256 // 2**32 - 1 (bdiff 1), bitcoincash.py -- same as BTC.
uint256 oracle_max_target() {
    uint256 t;
    t.SetHex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return t;
}

} // namespace

int main() {
    // -- mainnet net/consensus constants -----------------------------------
    PC::is_testnet = false;
    PC::override_identifier_hex.clear();
    PC::override_prefix_hex.clear();

    CHECK(PC::P2P_PORT == ORACLE_P2P_PORT);
    CHECK(PC::SPREAD == ORACLE_SPREAD);
    CHECK(PC::TARGET_LOOKBEHIND == ORACLE_TARGET_LOOKBEHIND);
    CHECK(PC::MINIMUM_PROTOCOL_VERSION == ORACLE_MIN_PROTO_VERSION);
    CHECK(PC::share_period() == ORACLE_SHARE_PERIOD);
    CHECK(PC::chain_length() == ORACLE_CHAIN_LENGTH);
    CHECK(PC::real_chain_length() == ORACLE_CHAIN_LENGTH);
    CHECK(PC::dust_threshold() == ORACLE_DUST_THRESHOLD);
    CHECK(PC::max_target() == oracle_max_target());

    // -- bucket-1 isolation primitives: mainnet ----------------------------
    CHECK(PC::identifier_hex() == ORACLE_IDENTIFIER_HEX_MAIN);
    CHECK(PC::prefix_hex() == ORACLE_PREFIX_HEX_MAIN);

    // -- bucket-2 donation version-gate (v36-native) -----------------------
    // Pre-V36 share -> forrestv P2PK (67B, 0x41 ... 0xac).
    {
        auto pre = PC::get_donation_script(/*share_version=*/35);
        CHECK(pre.size() == 67u);
        CHECK(pre.front() == 0x41);  // OP_PUSHBYTES_65
        CHECK(pre[1] == 0x04);       // uncompressed pubkey marker
        CHECK(pre.back() == 0xac);   // OP_CHECKSIG
    }
    // V36+ share -> combined P2SH 1-of-2 (23B, 0xa9 0x14 <20B> 0x87).
    {
        auto v36 = PC::get_donation_script(/*share_version=*/36);
        CHECK(v36.size() == 23u);
        CHECK(v36[0] == 0xa9);       // OP_HASH160
        CHECK(v36[1] == 0x14);       // push 20
        CHECK(v36.back() == 0x87);   // OP_EQUAL
    }

    // -- bucket-1 isolation primitives: testnet keeps its own namespace -----
    PC::is_testnet = true;
    CHECK(PC::identifier_hex() == ORACLE_IDENTIFIER_HEX_TEST);
    CHECK(PC::prefix_hex() == ORACLE_PREFIX_HEX_TEST);
    // testnet cadence matches mainnet (bitcoincash_testnet.py)
    CHECK(PC::share_period() == ORACLE_SHARE_PERIOD);
    CHECK(PC::chain_length() == ORACLE_CHAIN_LENGTH);
    PC::is_testnet = false;

    if (failures == 0) {
        std::cout << "g1_oracle_byte_parity_test: ALL PASS"
                  << " (p2pool-merged-v36 bitcoincash[_testnet].py)\n";
        return 0;
    }
    std::cerr << "g1_oracle_byte_parity_test: " << failures << " FAILURE(S)\n";
    return 1;
}