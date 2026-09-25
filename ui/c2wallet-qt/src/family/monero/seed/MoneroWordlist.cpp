// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
#include "MoneroWordlist.hpp"

#include "english_wordlist.hpp"   // wordlists::kEnglish[1626]

namespace c2wallet::monero {

const Wordlist& english_wordlist()
{
    static const Wordlist wl{
        "English",
        wordlists::kEnglish,
        wordlists::kEnglishCount,
        wordlists::kEnglishPrefixLen,
    };
    return wl;
}

const std::vector<const Wordlist*>& monero_languages()
{
    static const std::vector<const Wordlist*> langs{
        &english_wordlist(),
        // Additional languages register here as their *_wordlist.hpp lands.
    };
    return langs;
}

} // namespace c2wallet::monero
