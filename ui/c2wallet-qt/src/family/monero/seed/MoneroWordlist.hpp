// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// ui/c2wallet-qt/src/family/monero/seed/MoneroWordlist.hpp
//
// Monero electrum-style mnemonic wordlist registry (design §3.2). Each language
// is a 1626-word list plus a "unique prefix length": the number of leading
// characters that make every word distinguishable, which is also the amount
// used both for the checksum and for prefix (autocomplete-tolerant) matching.
//
// English is embedded (english_wordlist.hpp). The registry is intentionally a
// list of language descriptors so additional wordlists (Spanish, Portuguese,
// ...) can be added by dropping in another *_wordlist.hpp and registering it,
// without touching the mnemonic codec.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <vector>

namespace c2wallet::monero {

struct Wordlist {
    const char*        name;        // e.g. "English"
    const char* const* words;       // pointer to a 1626-entry array
    std::size_t        count;       // always 1626 for a Monero wordlist
    int                prefix_len;  // unique prefix length (English = 3)
};

// The English wordlist (canonical Monero order; from monero-project english.h).
const Wordlist& english_wordlist();

// All registered languages, English first.
const std::vector<const Wordlist*>& monero_languages();

} // namespace c2wallet::monero
