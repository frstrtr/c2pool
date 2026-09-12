// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Cross-coin address conversion within Family A (design §4.1, requirement 5)
// with the #961 money-misdirection guard.
//
// Algebraic fact (design §4.1): every Family-A coin shares the secp256k1 curve,
// the same hash160 for P2PKH/P2WPKH, the same SHA256(script) for P2WSH, and the
// same x-only key for P2TR — so the PAYLOAD is byte-identical across coins and a
// conversion is purely a re-encoding under the target's version byte / HRP IFF
// the target supports that type.
//
// This is a direct lift of the hardened #961 engine in core/address_utils
// (classify_address_for_coin + the Own/Foreign/Invalid trichotomy). READ-ONLY:
// it derives address strings only, it never touches a private key or signs.
//
// Algorithm:
//   1. decode+classify the source string under the SOURCE SSOT — must be Own;
//   2. extract {type, payload} from the resulting (coin-agnostic) scriptPubKey;
//   3. capability-gate the TARGET (segwit/taproot present? — else refuse);
//   4. re-encode the SAME script under the TARGET SSOT;
//   5. MANDATORY round-trip proof — decode the result under the TARGET SSOT and
//      assert it is Own AND its scriptPubKey (thus its payload) is byte-identical
//      to the source's. A mismatch refuses rather than emitting a wrong address.
//
// REFUSED (the #961 guard):
//   (a) any BCH endpoint — CashAddr is a different encoding, never a prefix swap
//       (use BchTranscode.hpp for the sanctioned payload-level path);
//   (b) a type absent on the target (segwit/taproot -> DOGE/DASH/NMC/BCH);
//   (c) a mainnet<->testnet crossing;
//   (d) a source that is Foreign or Invalid to its claimed source coin.

#include "ConvertCoins.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace c2w::convert {

enum class AddrType { Unknown, P2PKH, P2SH, P2WPKH, P2WSH, P2TR };

enum class Status {
    Ok,
    RefuseSourceForeign,       // source well-formed but for a DIFFERENT coin
    RefuseSourceInvalid,       // source unparseable under the source SSOT (e.g. a CashAddr)
    RefuseBchNoPrefixSwap,     // #961 (a): BCH endpoint — never a prefix swap
    RefuseTypeAbsentOnTarget,  // #961 (b): segwit/taproot absent on target
    RefuseNetworkMismatch,     // #961 (c): mainnet<->testnet
    RefuseTargetEncodeFailed,  // target re-encode produced nothing
    RefuseRoundTripFailed,     // #961 round-trip proof failed (payload changed)
    RefuseUnknownCoin,         // unknown ticker
};

struct ConvertResult {
    Status      status = Status::RefuseUnknownCoin;
    AddrType    type   = AddrType::Unknown;
    std::string source_address;
    std::string target_address;
    std::string source_payload_hex;    // hash160 / witness program of the source
    std::string target_payload_hex;    // recovered from the round-trip decode
    std::vector<unsigned char> script; // the coin-agnostic scriptPubKey
    std::string reason;                // human-readable explanation
    bool ok() const { return status == Status::Ok; }
};

// Convert `address` (asserted to be a `source`-coin address) to `target`.
ConvertResult convert_address(const std::string& address,
                              const ConvertCoin& source,
                              const ConvertCoin& target);

// Ticker-string overload; RefuseUnknownCoin if either ticker is unknown.
ConvertResult convert_address(const std::string& address,
                              const std::string& source_ticker,
                              const std::string& target_ticker);

// Helpers (exposed for tests / UI display).
AddrType    classify_script_type(const std::vector<unsigned char>& script);
std::string payload_hex_of(const std::vector<unsigned char>& script);
const char* status_str(Status s);
const char* addr_type_str(AddrType t);

} // namespace c2w::convert
