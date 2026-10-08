// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BIP39: mnemonic <-> entropy <-> seed, with a REAL checksum verify (design
// §3.1 — the baseline only counted words). English wordlist is mandatory and
// embedded; the wordlist registry (wordlists.hpp) is structured for more
// languages. Seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048).

#include "wordlists.hpp"
#include "../../../secure/SecureString.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace c2w::hdkeys {

enum class Bip39Error {
    Ok,
    BadWordCount,     // not 12/15/18/21/24 words
    UnknownWord,      // a token is not in the selected wordlist
    BadChecksum,      // words parse but the BIP39 checksum bits are wrong
    BadEntropyLength, // entropy not 16/20/24/28/32 bytes
};

const char* to_string(Bip39Error e);

// Number of mnemonic words for a given entropy strength in bits.
// 128->12, 160->15, 192->18, 224->21, 256->24.
struct Bip39 {
    // entropy (16..32 bytes, multiple of 4) -> space-joined mnemonic.
    static std::string encode(const std::vector<uint8_t>& entropy,
                              Bip39Error& err,
                              Language lang = Language::English);

    // Validate word count AND the real checksum. Recovers entropy on success.
    static Bip39Error validate(const std::string& mnemonic,
                               Language lang = Language::English);
    static Bip39Error decode(const std::string& mnemonic,
                             std::vector<uint8_t>& entropy_out,
                             Language lang = Language::English);

    // mnemonic (+ optional passphrase) -> 64-byte BIP39 seed.
    // NOTE: caller passes an already-NFKD-normalised mnemonic for non-ASCII
    //       languages (English is ASCII, so a no-op). The passphrase salt is
    //       "mnemonic" ‖ passphrase per the spec.
    static secure::SecureBytes to_seed(const std::string& mnemonic,
                                       const std::string& passphrase = "");

    // Generate a fresh mnemonic from a VETTED CSPRNG (design §3.4). strength_bits
    // must be one of 128/160/192/224/256. Throws std::invalid_argument otherwise.
    static std::string generate(int strength_bits = 256,
                                Language lang = Language::English);

    // First 4 checksum bytes shown to the operator as a "fingerprint" to catch
    // the passphrase silent-fork hazard (design §3.1). This is HMAC-SHA512 of a
    // fixed tag over the seed — a display aid, not a key.
    static std::string seed_fingerprint(const secure::SecureBytes& seed);
};

// PBKDF2-HMAC-SHA512 (exposed for reuse/testing; used by Bip39::to_seed).
void pbkdf2_hmac_sha512(const uint8_t* pass, size_t pass_len,
                        const uint8_t* salt, size_t salt_len,
                        uint32_t iterations,
                        uint8_t* out, size_t out_len);

} // namespace c2w::hdkeys
