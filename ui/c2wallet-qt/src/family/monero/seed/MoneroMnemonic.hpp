// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// ui/c2wallet-qt/src/family/monero/seed/MoneroMnemonic.hpp
//
// The Monero 25-word electrum-style mnemonic codec (design §3.2): 24 data words
// (8 groups of 3, each group a little-endian uint32) that encode the 32-byte
// private spend key, plus a 25th CRC32 checksum word. This is the "build from
// scratch" seed format -- absent from the c2pool tree -- driven by the vendored
// Keccak only for downstream key derivation, not here.
//
// A 24-word (checksum-less) phrase decodes to the same 32 bytes and is accepted
// for import; encode always emits the full 25-word form.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "../MoneroCrypto.hpp"   // Bytes32
#include "MoneroWordlist.hpp"

namespace c2wallet::monero {

struct MnemonicDecode {
    bool            ok{false};
    std::string     error;
    Bytes32         key{};            // 32-byte private spend key material
    const Wordlist* language{nullptr};
    bool            had_checksum{false};
};

// Decode a Monero 25-word (or 24-word, checksum-less) mnemonic to its 32-byte
// key. Tries each registered language; matches words by unique-prefix so both
// full words and prefix-truncated forms are accepted. Verifies the CRC32
// checksum word when 25 words are supplied.
MnemonicDecode mnemonic_decode(const std::string& phrase);

// Encode a 32-byte key to a full 25-word mnemonic (24 data words + checksum).
std::string mnemonic_encode(const Bytes32& key, const Wordlist& language = english_wordlist());

// The checksum word index: CRC32 over the concatenated unique-prefix of each of
// the given data words, modulo the word count. Exposed for testing.
std::size_t mnemonic_checksum_index(const std::vector<std::string>& words, int prefix_len);

// Standard CRC-32 (IEEE 802.3, reflected, matching boost::crc_32_type). Exposed
// for testing.
std::uint32_t crc32_ieee(const std::uint8_t* data, std::size_t len);

} // namespace c2wallet::monero
