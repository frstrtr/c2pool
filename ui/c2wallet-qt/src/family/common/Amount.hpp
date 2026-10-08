// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// GAP-5 — integer-only amount formatting + strict parsing for the Family-A
// money paths (design docs/design/c2wallet-qt.md §5.5 money-path discipline;
// threat-model T-1 "both-units amounts"). This header is deliberately Qt-free
// and std-only: NEVER route money through QString::toDouble / std::stod — a
// double cannot represent 21e6 * 1e8 satoshis exactly, so every amount on a
// money path is an int64 count of the smallest unit and is rendered/parsed by
// pure integer arithmetic here.
//
// format_amount(sats, decimals)  -> the decimal-unit string ("0.10000000").
// parse_amount(text, decimals)   -> strict: rejects sign, exponent, whitespace,
//   non-digits, an over-long fractional part, and any int64 overflow.
//
// Every amount in the UI renders BOTH units always (T-1): the whole-unit string
// from format_amount AND the raw satoshi integer.

#include <cstdint>
#include <string>
#include <string_view>

namespace c2w::amount {

// Largest int64 (9223372036854775807) — the overflow ceiling for parse_amount.
inline constexpr int64_t kMaxInt64 = 9223372036854775807LL;

// Render a signed satoshi count as a fixed-point decimal string with exactly
// `decimals` fractional digits. Integer arithmetic only. A negative value keeps
// its leading '-'. `decimals` is clamped to [0, 18].
inline std::string format_amount(int64_t sats, int decimals) {
    if (decimals < 0) decimals = 0;
    if (decimals > 18) decimals = 18;

    const bool neg = sats < 0;
    // Take the magnitude without UB on INT64_MIN by working in unsigned.
    uint64_t mag = neg ? (~static_cast<uint64_t>(sats) + 1ULL) : static_cast<uint64_t>(sats);

    uint64_t scale = 1;
    for (int i = 0; i < decimals; ++i) scale *= 10ULL;

    const uint64_t whole = mag / scale;
    const uint64_t frac = mag % scale;

    std::string out;
    if (neg) out.push_back('-');
    out += std::to_string(whole);
    if (decimals > 0) {
        out.push_back('.');
        std::string f = std::to_string(frac);
        // Left-pad the fractional part to exactly `decimals` digits.
        if (static_cast<int>(f.size()) < decimals)
            out.append(static_cast<size_t>(decimals) - f.size(), '0');
        out += f;
    }
    return out;
}

struct ParsedAmount {
    bool        ok = false;
    int64_t     sats = 0;
    std::string error;
};

// Strict whole-unit -> satoshi parse. Accepts ONLY:
//   * ASCII digits and at most one '.'
//   * at most `decimals` digits after the '.'
//   * no leading/trailing whitespace, no '+'/'-', no 'e'/'E' exponent
// Refuses on int64 overflow. An empty integer part is allowed only as ".5"?  NO
// — we require at least one digit somewhere and reject a bare "." / "".
inline ParsedAmount parse_amount(std::string_view s, int decimals) {
    ParsedAmount r;
    if (decimals < 0) decimals = 0;
    if (decimals > 18) decimals = 18;

    if (s.empty()) { r.error = "empty amount"; return r; }

    // No sign, no exponent, no whitespace anywhere — scan once.
    int dot = -1;
    int ndigits = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (c == '.') {
            if (dot >= 0) { r.error = "more than one decimal point"; return r; }
            dot = static_cast<int>(i);
        } else if (c >= '0' && c <= '9') {
            ++ndigits;
        } else {
            r.error = "invalid character in amount (digits and one '.' only)";
            return r;
        }
    }
    if (ndigits == 0) { r.error = "no digits in amount"; return r; }

    std::string_view intpart = dot < 0 ? s : s.substr(0, static_cast<size_t>(dot));
    std::string_view fracpart = dot < 0 ? std::string_view{} : s.substr(static_cast<size_t>(dot) + 1);

    if (static_cast<int>(fracpart.size()) > decimals) {
        r.error = "too many fractional digits (max " + std::to_string(decimals) + ")";
        return r;
    }

    // Assemble the digit string scaled to satoshis, then parse with overflow
    // checks — never through a floating type.
    std::string digits;
    digits.reserve(intpart.size() + static_cast<size_t>(decimals));
    digits.append(intpart.begin(), intpart.end());
    digits.append(fracpart.begin(), fracpart.end());
    // Pad the fractional side with trailing zeros up to `decimals`.
    for (int i = static_cast<int>(fracpart.size()); i < decimals; ++i) digits.push_back('0');
    if (digits.empty()) digits = "0";

    uint64_t acc = 0;
    for (char c : digits) {
        const uint64_t d = static_cast<uint64_t>(c - '0');
        if (acc > (static_cast<uint64_t>(kMaxInt64) - d) / 10ULL) {
            r.error = "amount overflows int64";
            return r;
        }
        acc = acc * 10ULL + d;
    }
    r.ok = true;
    r.sats = static_cast<int64_t>(acc);
    return r;
}

} // namespace c2w::amount
