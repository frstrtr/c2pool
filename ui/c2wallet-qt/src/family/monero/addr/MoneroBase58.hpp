// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// ui/c2wallet-qt/src/family/monero/addr/MoneroBase58.hpp
//
// Monero's OWN block-based Base58 (design §3.2) -- NOT Bitcoin Base58/Base58Check.
// Monero encodes in 8-byte blocks: a full 8-byte block becomes exactly 11
// characters, and a trailing partial block of b bytes becomes a fixed number of
// characters per the block-size table. This scheme is used for every Monero
// address form; it is absent from the Bitcoin-family code, so it is built here.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace c2wallet::monero {

// Encode raw bytes to Monero Base58. Never fails.
std::string base58_encode(const std::vector<std::uint8_t>& data);

// Decode Monero Base58. Returns true and fills `out` on success; false if the
// string contains a non-alphabet character or a malformed (impossible) block
// length.
bool base58_decode(const std::string& enc, std::vector<std::uint8_t>& out);

} // namespace c2wallet::monero
