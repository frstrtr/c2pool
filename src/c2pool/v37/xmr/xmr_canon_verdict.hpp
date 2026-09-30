// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// src/c2pool/v37/xmr/xmr_canon_verdict.hpp -- the three outcomes of a canonical
// coinbase check (xmr_canonical_coinbase.hpp). Split out so the receipt ingest
// can hold a verdict without pulling the settlement builder in.
#pragma once

#include <cstdint>
#include <string>

namespace c2pool::v37n::xmr::canon {

enum class Verdict : std::uint8_t { Match = 0, Mismatch = 1, Undecidable = 2 };
inline const char* to_string(Verdict v) {
    switch (v) {
        case Verdict::Match: return "match";
        case Verdict::Mismatch: return "mismatch";
        case Verdict::Undecidable: return "undecidable";
    }
    return "?";
}

struct Result {
    Verdict     v = Verdict::Undecidable;
    std::string why;
};

} // namespace c2pool::v37n::xmr::canon
