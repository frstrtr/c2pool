// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BCH CashAddr <-> Base58Check transcode helper (design §4.1: "a BCH<->base58
// transcode helper on top of cashaddr.hpp", the second of the two named gaps).
//
// #961 rule: BCH is NEVER a prefix swap — CashAddr is a different encoding, so
// the generic converter (Convert.hpp) refuses any BCH endpoint. The sanctioned
// path is a PAYLOAD-LEVEL transcode: decode one encoding to its {type, hash},
// re-encode under the other, then prove the payload survived a round trip. A
// naive base58 version-byte swap of a BCH address (or vice-versa) would silently
// misdirect funds because BCH'"'"'s legacy base58 versions collide with BTC'"'"'s.
//
// READ-ONLY: derives address strings only; never touches a key.

#include "Convert.hpp"        // AddrType
#include "ConvertCoins.hpp"   // ConvertCoin

#include <string>
#include <vector>

namespace c2w::convert {

struct TranscodeResult {
    bool        ok = false;
    AddrType    type = AddrType::Unknown;
    std::string source_address;
    std::string target_address;
    std::string payload_hex;   // the hash160 shared by both encodings
    std::string reason;
};

// BCH CashAddr -> Base58Check under `base58_target` (any non-BCH Family-A coin,
// e.g. BTC/LTC/DOGE...). PUBKEY_TYPE -> P2PKH(target.p2pkh_version);
// SCRIPT_TYPE(20) -> P2SH(target.p2sh_version). 32-byte P2SH32 and token-aware
// hashes with no base58 form are refused. `cashaddr_prefix` selects the network
// (defaults to BCH mainnet). A mandatory payload round-trip is enforced.
TranscodeResult bch_cashaddr_to_base58(const std::string& cashaddr,
                                       const ConvertCoin& base58_target,
                                       const std::string& cashaddr_prefix = "bitcoincash");

// Base58Check (P2PKH/P2SH under `base58_source`) -> BCH CashAddr under `bch`.
// The source must be Own to `base58_source`; the produced CashAddr is proved to
// decode back to the same scriptPubKey.
TranscodeResult base58_to_bch_cashaddr(const std::string& address,
                                       const ConvertCoin& base58_source,
                                       const ConvertCoin& bch);

} // namespace c2w::convert
