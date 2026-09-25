// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ┌───────────────────────────────────────────────────────────────────────────┐
// │  EXPERIMENTAL — CUSTOM CRYPTOGRAPHY — NOT SLIP-39.  DO NOT USE TO GUARD     │
// │  REAL FUNDS UNTIL INDEPENDENTLY REVIEWED (design §3.4 + §7 risk note).      │
// └───────────────────────────────────────────────────────────────────────────┘
//
// Split / shuffle seed backup, ported from the operator's `frstrtr/mnemonic_gen`
// (operator-owned; relicensed into c2pool under AGPL-3.0-or-later on this port).
//
// This is a BESPOKE 2-of-2 even/odd split with a reversible password-keyed
// shuffle of the BIP39 wordlist. It is deliberately behind this clearly-labelled
// "experimental backup" API and is NOT wired into the normal import/generation
// paths. The §7 risk flag stands verbatim:
//   * a 2-of-2 split is WEAKER than a threshold (SLIP-39 Shamir) scheme — each
//     recovered 12-word half narrows the brute-force of the other;
//   * the scheme is unreviewed custom crypto and needs an independent security
//     review before it guards real seeds;
//   * SLIP-39 should be offered as the standard reviewed alternative.
//
// Scheme (mnemonic_gen v1 / "legacy", the round-trippable one `ungen.py` reverses):
//   seed64  = BIP39 seed of the 24-word salt mnemonic (empty passphrase)
//   key     = PBKDF2-HMAC-SHA256(password, seed64, iterations=100000, 32 bytes)
//   perm    = Fisher-Yates over indices[0..2047] driven by HMAC-DRBG-SHA256(
//             key, nonce="mnemonic-shuffle-v1")  (big-endian u32 stream)
//   split   : a 24-word mnemonic's even-index words -> share A (12), odd -> B (12)
//   map     : each original word's wordlist index i -> perm[i] (the shuffled word)
//   recover : mapped word's index m -> perm^-1[m] -> original word
//
// HARD RULE (design §3.4): all fresh entropy — the 24-word master AND the salt
// mnemonic — comes from the vetted CSPRNG (Bip39::generate -> Csprng getrandom),
// NEVER the mnemonic_gen demo RNG. The demo RNG is not ported.

#include <cstdint>
#include <string>
#include <vector>

namespace c2w::hdkeys {

struct SeedShuffleParams {
    // PBKDF2-HMAC-SHA256 iteration count. Production default matches mnemonic_gen
    // v1 (ungen.py). Round-trip fidelity only requires gen and ungen to agree;
    // KATs may lower it for speed. (The mnemonic_gen v2 Argon2id path is NOT
    // ported — it is not the round-trippable reference the design cites.)
    uint32_t pbkdf2_iterations = 100000;
};

// The deterministic wordlist permutation S (size 2048): S[pos] = the original
// English-wordlist index of the word placed at shuffled position `pos`.
std::vector<int> deterministic_shuffle(const std::string& password,
                                       const std::string& salt_mnemonic24,
                                       const SeedShuffleParams& params = {});

struct SplitBackup {
    bool ok = false;
    std::string error;
    std::string master_mnemonic;  // the original 24-word seed (CSPRNG-generated)
    std::string share_even;       // 12-word share (even index positions)
    std::string share_odd;        // 12-word share (odd index positions)
    std::string salt_mnemonic;    // 24-word salt mnemonic (CSPRNG-generated)
    int iterations_tried = 0;     // probe attempts consumed
};

// Generate a fresh backup-able 24-word master (CSPRNG) whose plain even/odd
// halves are valid BIP39, plus a salt (CSPRNG) whose shuffle maps both halves to
// valid 12-word BIP39 shares (mnemonic_gen's generate-and-probe flow). The two
// shares + salt mnemonic + password reconstruct the master.
SplitBackup generate_split_backup(const std::string& password,
                                  const SeedShuffleParams& params = {},
                                  int max_probe_iters = 2000000);

struct RecoverResult {
    bool ok = false;
    std::string error;
    std::string master_mnemonic;  // recovered 24-word (valid iff ok)
};

// Reverse: recover the original 24-word master from the two shares, the salt
// mnemonic, and the password (mnemonic_gen ungen.py).
RecoverResult recover_split_backup(const std::string& share_even,
                                   const std::string& share_odd,
                                   const std::string& salt_mnemonic24,
                                   const std::string& password,
                                   const SeedShuffleParams& params = {});

} // namespace c2w::hdkeys
