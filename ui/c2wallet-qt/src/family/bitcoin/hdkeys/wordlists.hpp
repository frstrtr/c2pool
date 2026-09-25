// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BIP39 wordlist registry. English is mandatory and embedded (wordlist_english.cpp).
// The registry is structured so further languages (JP needs NFKD + ideographic-space
// join per design §3.1, ES/FR/IT/CS/PT/ZH...) drop in as extra wordlist_<lang>.cpp
// translation units without touching the BIP39 engine.

#include <array>
#include <string>

namespace c2w::hdkeys {

enum class Language {
    English,
    // Reserved for M1-A follow-ons; only English is embedded in this PR.
};

// The 2048-word BIP39 English list, canonical order.
const std::array<const char*, 2048>& wordlist_english();

// Resolve a language to its 2048-word list. Throws std::runtime_error for a
// language whose list is not embedded yet.
const std::array<const char*, 2048>& wordlist_for(Language lang);

} // namespace c2w::hdkeys
