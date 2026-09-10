// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/anchor/xmr_anchor_codec.hpp
//
// The `.inc` FILE FORMAT for the trust-anchor bundle: the on-disk shape of
// contracts/anchor.hpp's AnchorBundle, its digest rule, its writer and its
// fail-closed reader. WF-C2b owns this file; contracts/anchor.hpp owns the
// struct and the semantic self-check, and neither reaches into the other.
//
// WHY A LINE-ORIENTED TEXT FORMAT AND NOT A BLOB. The bundle is the node's
// trust root. It is reviewed by a human before a release pins it and it is
// diffed between releases, so its serialisation has exactly two jobs: be
// unambiguous to a parser, and be readable by the person signing off on it.
// A binary blob is better at neither. The shape follows monerod's own
// checkpoints file -- one fact per line, keyword first -- because that is the
// artefact this one is the analogue of, and a reviewer who knows that file can
// read this one.
//
// DOUBLE DUTY: the same bytes are the release-EMBEDDED bundle. The file opens
// with a raw-string-literal frame so a build can `#include` it as a `const
// char*` (monerod's .inc convention, same trick), and the reader below treats
// the two frame lines as framing rather than content, so the identical file
// loads from disk and from the binary. There is therefore ONE artefact, never a
// text copy and a header copy that can drift.
//
// THE DIGEST RULE, stated once and implemented once. The digest is SHA-256 over
// the BODY: every line that is not the frame, not blank, not a `#` comment and
// not the `digest` line itself, each with trailing whitespace stripped and each
// terminated by a single '\n', in file order. The writer emits the canonical
// body and the digest of it; the reader recomputes over the body it actually
// read and compares. Comments are deliberately outside the digest so a release
// can annotate a bundle -- provenance, capture date, the daemon version -- and
// still be the same bundle. What the digest protects is the DATA.
//
// WHAT THE DIGEST IS NOT: a signature. Anyone who can rewrite the file can
// rewrite the digest line. It catches a truncated fetch, a merge conflict and
// an editor; the anchor's real defence is that C2's boot fetches the block at
// `height` from peers and refuses to start unless it hashes to `id`.
//
// LONG-TERM WINDOW COMPRESSION. `ltw` carries 100 000 entries and Monero's
// long-term weight is a median-of-100000 that moves slowly, so a real bundle is
// long runs of one value. The list grammar therefore admits `<count>x<value>`
// beside a bare `<value>`; both expand to the same numbers, the digest covers
// whatever spelling the file used, and the writer emits runs. A real stagenet
// bundle drops from ~700 KB to a few KB with no loss of information and no
// change to what the loader ends up holding.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/contracts/anchor.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_sha256.hpp"

namespace c2pool::xmr::native {

// The only format version this build reads. A bump means a reader change, so a
// newer file is REFUSED rather than parsed on a guess.
inline constexpr std::uint32_t ANCHOR_INC_FORMAT_VERSION = 1;

inline constexpr const char* ANCHOR_INC_FRAME_OPEN  = "R\"ANCHOR(";
inline constexpr const char* ANCHOR_INC_FRAME_CLOSE = ")ANCHOR\"";

// --- why a parse failed ------------------------------------------------------
// Distinct from AnchorStatus (contracts/anchor.hpp), which judges a bundle that
// already parsed. Keeping them apart is what lets a boot log say "the file is
// damaged" and "the file is fine but describes another chain" differently.
enum class AnchorParse : std::uint8_t {
    Ok = 0,
    Empty,          // nothing to parse
    BadFormat,      // missing/unsupported `format` line
    UnknownKey,     // a keyword this reader does not implement
    BadField,       // a value did not parse, or is out of range
    DuplicateKey,   // a once-only key appeared twice
    MissingKey,     // a required key never appeared
    DigestPlace,    // `digest` is absent or is not the last body line
    DigestMismatch, // the body does not hash to the digest line
};

inline const char* to_string(AnchorParse s) noexcept {
    switch (s) {
        case AnchorParse::Ok:             return "Ok";
        case AnchorParse::Empty:          return "Empty";
        case AnchorParse::BadFormat:      return "BadFormat";
        case AnchorParse::UnknownKey:     return "UnknownKey";
        case AnchorParse::BadField:       return "BadField";
        case AnchorParse::DuplicateKey:   return "DuplicateKey";
        case AnchorParse::MissingKey:     return "MissingKey";
        case AnchorParse::DigestPlace:    return "DigestPlace";
        case AnchorParse::DigestMismatch: return "DigestMismatch";
    }
    return "?";
}

namespace anchor_codec {

// --- small, strict scalar helpers -------------------------------------------
// Every one of these REFUSES on anything it does not fully understand: no
// leading '+', no sign, no whitespace tolerance inside a token, no silent
// truncation on overflow. A trust root is the wrong place for strtoull's habit
// of returning a number for input that was not one.

inline char hex_digit(std::uint8_t v) noexcept { return "0123456789abcdef"[v & 0x0fu]; }

inline std::string to_hex(const std::uint8_t* p, std::size_t n) {
    std::string s;
    s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(hex_digit(static_cast<std::uint8_t>(p[i] >> 4)));
        s.push_back(hex_digit(p[i]));
    }
    return s;
}

// One overload covers both a block id and a digest: Hash IS
// std::array<std::uint8_t, 32>, and a second declaration would be a redefinition
// rather than an overload.
inline std::string to_hex(const std::array<std::uint8_t, 32>& d) { return to_hex(d.data(), d.size()); }

inline bool hex_value(char c, std::uint8_t& out) noexcept {
    if (c >= '0' && c <= '9') { out = static_cast<std::uint8_t>(c - '0');      return true; }
    if (c >= 'a' && c <= 'f') { out = static_cast<std::uint8_t>(c - 'a' + 10); return true; }
    if (c >= 'A' && c <= 'F') { out = static_cast<std::uint8_t>(c - 'A' + 10); return true; }
    return false;
}

// Exactly 64 lowercase-or-uppercase hex characters, nothing else.
inline bool parse_hash(const std::string& tok, Hash& out) noexcept {
    if (tok.size() != 64) return false;
    for (std::size_t i = 0; i < 32; ++i) {
        std::uint8_t hi = 0, lo = 0;
        if (!hex_value(tok[2 * i], hi) || !hex_value(tok[2 * i + 1], lo)) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

inline bool parse_digest(const std::string& tok, std::array<std::uint8_t, 32>& out) noexcept {
    Hash h{};
    if (!parse_hash(tok, h)) return false;
    for (std::size_t i = 0; i < 32; ++i) out[i] = h[i];
    return true;
}

// Decimal, 1..20 digits, overflow-checked.
inline bool parse_u64(const std::string& tok, std::uint64_t& out) noexcept {
    if (tok.empty() || tok.size() > 20) return false;
    std::uint64_t v = 0;
    for (char c : tok) {
        if (c < '0' || c > '9') return false;
        const std::uint64_t d = static_cast<std::uint64_t>(c - '0');
        if (v > (0xFFFFFFFFFFFFFFFFull - d) / 10ull) return false;   // overflow
        v = v * 10ull + d;
    }
    out = v;
    return true;
}

// Lower-case hex, 1..16 digits, no 0x prefix. Used for the 128-bit words so a
// cumulative difficulty reads the same way monerod prints wide_* fields.
inline bool parse_u64_hex(const std::string& tok, std::uint64_t& out) noexcept {
    if (tok.empty() || tok.size() > 16) return false;
    std::uint64_t v = 0;
    for (char c : tok) {
        std::uint8_t d = 0;
        if (!hex_value(c, d)) return false;
        v = (v << 4) | d;
    }
    out = v;
    return true;
}

inline std::string u64_hex(std::uint64_t v) {
    if (v == 0) return "0";
    char buf[17];
    int n = 0;
    while (v) { buf[n++] = hex_digit(static_cast<std::uint8_t>(v & 0xfu)); v >>= 4; }
    std::string s;
    s.reserve(static_cast<std::size_t>(n));
    for (int i = n - 1; i >= 0; --i) s.push_back(buf[i]);
    return s;
}

inline std::string u128_text(const U128& d) { return u64_hex(d.hi) + " " + u64_hex(d.lo); }

// --- line/token plumbing -----------------------------------------------------
inline std::string rstrip(const std::string& s) {
    std::size_t e = s.size();
    while (e > 0 && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) --e;
    return s.substr(0, e);
}

inline std::vector<std::string> split_ws(const std::string& s) {
    std::vector<std::string> out;
    std::size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
        const std::size_t b = i;
        while (i < s.size() && s[i] != ' ' && s[i] != '\t') ++i;
        if (i > b) out.push_back(s.substr(b, i - b));
    }
    return out;
}

// A body line is anything that is not the frame, not blank and not a comment.
inline bool is_frame_or_ignorable(const std::string& line) {
    const std::string t = rstrip(line);
    if (t.empty()) return true;
    if (t[0] == '#') return true;
    if (t == ANCHOR_INC_FRAME_OPEN || t == ANCHOR_INC_FRAME_CLOSE) return true;
    // Tolerate the frame lines carrying a trailing `;` or leading indent the way a
    // generated header sometimes does, but nothing else.
    std::size_t b = 0;
    while (b < t.size() && (t[b] == ' ' || t[b] == '\t')) ++b;
    const std::string u = t.substr(b);
    return u == ANCHOR_INC_FRAME_OPEN || u == ANCHOR_INC_FRAME_CLOSE
        || u == std::string(ANCHOR_INC_FRAME_CLOSE) + ";";
}

// One `<value>` or `<count>x<value>` token, appended to `out`. `cap` bounds the
// expansion so a malformed run cannot ask for an allocation the size of memory.
inline bool append_run(const std::string& tok, std::vector<std::uint64_t>& out, std::size_t cap) {
    const std::size_t x = tok.find('x');
    if (x == std::string::npos) {
        std::uint64_t v = 0;
        if (!parse_u64(tok, v)) return false;
        if (out.size() + 1 > cap) return false;
        out.push_back(v);
        return true;
    }
    std::uint64_t count = 0, value = 0;
    if (!parse_u64(tok.substr(0, x), count)) return false;
    if (!parse_u64(tok.substr(x + 1), value)) return false;
    if (count == 0) return false;                          // an empty run is a typo, not a value
    if (count > cap || out.size() + count > cap) return false;
    out.insert(out.end(), static_cast<std::size_t>(count), value);
    return true;
}

// The writer's inverse: collapse equal neighbours into runs of >= 4 (below that
// the run spelling is longer than the values it replaces).
inline std::string run_encode_ltw(const std::vector<std::uint64_t>& v, std::size_t per_line) {
    std::string s;
    std::size_t on_line = 0;
    auto emit = [&](const std::string& tok) {
        if (on_line == 0) s += "ltw";
        s += " ";
        s += tok;
        if (++on_line == per_line) { s += "\n"; on_line = 0; }
    };
    std::size_t i = 0;
    while (i < v.size()) {
        std::size_t j = i;
        while (j < v.size() && v[j] == v[i]) ++j;
        const std::size_t run = j - i;
        if (run >= 4) {
            if (on_line != 0) { s += "\n"; on_line = 0; }
            s += "ltw " + std::to_string(run) + "x" + std::to_string(v[i]) + "\n";
        } else {
            for (std::size_t k = 0; k < run; ++k) emit(std::to_string(v[i]));
        }
        i = j;
    }
    if (on_line != 0) s += "\n";
    return s;
}

}  // namespace anchor_codec

// --- the canonical body ------------------------------------------------------
// Everything the digest covers, in the order a reviewer reads it. This is a pure
// function of the bundle: the same bundle always produces the same bytes, which
// is what makes "regenerate and diff" a meaningful release check.
inline std::string anchor_body_text(const AnchorBundle& b) {
    using namespace anchor_codec;
    std::string s;
    s.reserve(4096 + b.long_term_weights.size() * 4);

    s += "format " + std::to_string(ANCHOR_INC_FORMAT_VERSION) + "\n";
    s += "network " + b.network + "\n";
    s += "height " + std::to_string(b.height) + "\n";
    s += "id " + to_hex(b.id) + "\n";
    s += "prev_id " + to_hex(b.prev_id) + "\n";
    s += "timestamp " + std::to_string(b.timestamp) + "\n";
    s += "major_version " + std::to_string(static_cast<unsigned>(b.major_version)) + "\n";
    s += "cumulative_difficulty " + u128_text(b.cumulative_difficulty) + "\n";
    s += "already_generated_coins " + std::to_string(b.already_generated_coins) + "\n";

    for (const auto& sd : b.seed_ids)
        s += "seed " + std::to_string(sd.first) + " " + to_hex(sd.second) + "\n";

    for (const auto& d : b.difficulty_window)
        s += "diff " + std::to_string(d.first) + " " + u128_text(d.second) + "\n";

    for (std::size_t i = 0; i < b.short_term_weights.size(); ++i) {
        if (i % 10 == 0) s += (i ? "\nstw" : "stw");
        s += " " + std::to_string(b.short_term_weights[i]);
    }
    if (!b.short_term_weights.empty()) s += "\n";

    s += run_encode_ltw(b.long_term_weights, 20);

    for (const auto& c : b.monerod_checkpoints)
        s += "checkpoint " + std::to_string(c.first) + " " + to_hex(c.second) + "\n";

    return s;
}

// The canonical digest of a bundle: SHA-256 of the body above.
inline std::array<std::uint8_t, 32> anchor_digest(const AnchorBundle& b) {
    return anchor_hash::sha256(anchor_body_text(b));
}

// --- the writer --------------------------------------------------------------
// `header_comment` is free text (provenance: which daemon, which date, which
// tool run). It sits outside the digest on purpose -- see the DIGEST RULE note.
inline std::string write_anchor_inc(const AnchorBundle& b, const std::string& header_comment = {}) {
    using namespace anchor_codec;
    std::string s;
    s += ANCHOR_INC_FRAME_OPEN;
    s += "\n";
    if (!header_comment.empty()) {
        std::size_t i = 0;
        while (i <= header_comment.size()) {
            const std::size_t nl = header_comment.find('\n', i);
            const std::string line = header_comment.substr(i, nl == std::string::npos ? std::string::npos : nl - i);
            s += "# " + rstrip(line) + "\n";
            if (nl == std::string::npos) break;
            i = nl + 1;
        }
    }
    const std::string body = anchor_body_text(b);
    s += body;
    s += "digest " + to_hex(anchor_hash::sha256(body)) + "\n";
    s += ANCHOR_INC_FRAME_CLOSE;
    s += "\n";
    return s;
}

// --- the reader --------------------------------------------------------------
// FAIL-CLOSED IN THE STRICT SENSE: it returns a bundle only when every line was
// understood, every once-only key appeared once, every window filled to exactly
// the length contracts/anchor.hpp pins, `digest` was the last body line, and the
// body hashes to it. It performs NO semantic judgement -- that is
// anchor_self_check()'s job and load_anchor() calls it next -- so that a boot
// log can tell "the file is damaged" from "the file is for another chain".
inline AnchorParse parse_anchor_inc(const std::string& text, AnchorBundle& out, std::string& why) {
    using namespace anchor_codec;

    out = AnchorBundle{};
    why.clear();

    bool have_format = false, have_network = false, have_height = false;
    bool have_id = false, have_prev = false, have_ts = false, have_ver = false;
    bool have_cumdiff = false, have_coins = false;
    std::array<std::uint8_t, 32> file_digest{};
    bool have_digest = false;

    std::string body;
    body.reserve(text.size());

    std::size_t pos = 0;
    std::size_t lineno = 0;
    auto fail = [&](AnchorParse st, const std::string& msg) {
        why = "anchor .inc line " + std::to_string(lineno) + ": " + msg;
        return st;
    };

    while (pos <= text.size()) {
        const std::size_t nl = text.find('\n', pos);
        const std::string raw = text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        pos = (nl == std::string::npos) ? text.size() + 1 : nl + 1;
        ++lineno;

        if (is_frame_or_ignorable(raw)) continue;
        const std::string line = rstrip(raw);

        // Anything after the digest line is content the digest does not cover,
        // which would be a place to hide a field. Refuse it.
        if (have_digest) return fail(AnchorParse::DigestPlace, "content after the digest line");

        const std::vector<std::string> t = split_ws(line);
        if (t.empty()) continue;
        const std::string& key = t[0];

        if (key == "digest") {
            if (t.size() != 2) return fail(AnchorParse::BadField, "digest takes one 64-hex value");
            if (!parse_digest(t[1], file_digest)) return fail(AnchorParse::BadField, "digest is not 64 hex");
            have_digest = true;
            continue;   // NOT part of the body
        }

        body += line;
        body += "\n";

        if (key == "format") {
            if (have_format) return fail(AnchorParse::DuplicateKey, "format repeated");
            std::uint64_t v = 0;
            if (t.size() != 2 || !parse_u64(t[1], v)) return fail(AnchorParse::BadFormat, "format takes one number");
            if (v != ANCHOR_INC_FORMAT_VERSION)
                return fail(AnchorParse::BadFormat, "format " + t[1] + " is not the "
                            + std::to_string(ANCHOR_INC_FORMAT_VERSION) + " this build reads");
            have_format = true;
        } else if (!have_format) {
            return fail(AnchorParse::BadFormat, "'" + key + "' before the format line");
        } else if (key == "network") {
            if (have_network) return fail(AnchorParse::DuplicateKey, "network repeated");
            if (t.size() != 2) return fail(AnchorParse::BadField, "network takes one name");
            out.network = t[1];
            have_network = true;
        } else if (key == "height") {
            if (have_height) return fail(AnchorParse::DuplicateKey, "height repeated");
            if (t.size() != 2 || !parse_u64(t[1], out.height)) return fail(AnchorParse::BadField, "height");
            have_height = true;
        } else if (key == "id") {
            if (have_id) return fail(AnchorParse::DuplicateKey, "id repeated");
            if (t.size() != 2 || !parse_hash(t[1], out.id)) return fail(AnchorParse::BadField, "id");
            have_id = true;
        } else if (key == "prev_id") {
            if (have_prev) return fail(AnchorParse::DuplicateKey, "prev_id repeated");
            if (t.size() != 2 || !parse_hash(t[1], out.prev_id)) return fail(AnchorParse::BadField, "prev_id");
            have_prev = true;
        } else if (key == "timestamp") {
            if (have_ts) return fail(AnchorParse::DuplicateKey, "timestamp repeated");
            if (t.size() != 2 || !parse_u64(t[1], out.timestamp)) return fail(AnchorParse::BadField, "timestamp");
            have_ts = true;
        } else if (key == "major_version") {
            if (have_ver) return fail(AnchorParse::DuplicateKey, "major_version repeated");
            std::uint64_t v = 0;
            if (t.size() != 2 || !parse_u64(t[1], v) || v > 255) return fail(AnchorParse::BadField, "major_version");
            out.major_version = static_cast<std::uint8_t>(v);
            have_ver = true;
        } else if (key == "cumulative_difficulty") {
            if (have_cumdiff) return fail(AnchorParse::DuplicateKey, "cumulative_difficulty repeated");
            if (t.size() != 3 || !parse_u64_hex(t[1], out.cumulative_difficulty.hi)
                              || !parse_u64_hex(t[2], out.cumulative_difficulty.lo))
                return fail(AnchorParse::BadField, "cumulative_difficulty takes <hi_hex> <lo_hex>");
            have_cumdiff = true;
        } else if (key == "already_generated_coins") {
            if (have_coins) return fail(AnchorParse::DuplicateKey, "already_generated_coins repeated");
            if (t.size() != 2 || !parse_u64(t[1], out.already_generated_coins))
                return fail(AnchorParse::BadField, "already_generated_coins");
            have_coins = true;
        } else if (key == "seed") {
            if (out.seed_ids.size() >= ANCHOR_MAX_SEED_IDS)
                return fail(AnchorParse::BadField, "more than "
                            + std::to_string(ANCHOR_MAX_SEED_IDS) + " seed rows");
            std::uint64_t h = 0;
            Hash id{};
            if (t.size() != 3 || !parse_u64(t[1], h) || !parse_hash(t[2], id))
                return fail(AnchorParse::BadField, "seed takes <height> <64hex>");
            out.seed_ids.emplace_back(h, id);
        } else if (key == "diff") {
            if (out.difficulty_window.size() >= ANCHOR_DIFFICULTY_WINDOW)
                return fail(AnchorParse::BadField, "more than "
                            + std::to_string(ANCHOR_DIFFICULTY_WINDOW) + " diff rows");
            std::uint64_t ts = 0;
            U128 cd{};
            if (t.size() != 4 || !parse_u64(t[1], ts) || !parse_u64_hex(t[2], cd.hi) || !parse_u64_hex(t[3], cd.lo))
                return fail(AnchorParse::BadField, "diff takes <timestamp> <hi_hex> <lo_hex>");
            out.difficulty_window.emplace_back(ts, cd);
        } else if (key == "stw") {
            for (std::size_t i = 1; i < t.size(); ++i)
                if (!append_run(t[i], out.short_term_weights, ANCHOR_SHORT_TERM_WEIGHTS))
                    return fail(AnchorParse::BadField, "stw value '" + t[i] + "'");
        } else if (key == "ltw") {
            for (std::size_t i = 1; i < t.size(); ++i)
                if (!append_run(t[i], out.long_term_weights, ANCHOR_LONG_TERM_WEIGHTS))
                    return fail(AnchorParse::BadField, "ltw value '" + t[i] + "'");
        } else if (key == "checkpoint") {
            std::uint64_t h = 0;
            Hash id{};
            if (t.size() != 3 || !parse_u64(t[1], h) || !parse_hash(t[2], id))
                return fail(AnchorParse::BadField, "checkpoint takes <height> <64hex>");
            out.monerod_checkpoints.emplace_back(h, id);
        } else {
            return fail(AnchorParse::UnknownKey, "unknown keyword '" + key + "'");
        }
    }

    if (body.empty()) { why = "anchor .inc has no content"; return AnchorParse::Empty; }
    if (!have_format || !have_network || !have_height || !have_id || !have_prev
        || !have_ts || !have_ver || !have_cumdiff || !have_coins) {
        why = "anchor .inc is missing a required key (format/network/height/id/prev_id/"
              "timestamp/major_version/cumulative_difficulty/already_generated_coins)";
        return AnchorParse::MissingKey;
    }
    if (!have_digest) { why = "anchor .inc has no digest line"; return AnchorParse::DigestPlace; }

    // Window lengths are checked here as well as in anchor_self_check: the parser
    // needs the counts to bound its own allocations, and a short window is a file
    // defect, so it is reported as one.
    if (out.difficulty_window.size() != ANCHOR_DIFFICULTY_WINDOW
        || out.short_term_weights.size() != ANCHOR_SHORT_TERM_WEIGHTS
        || out.long_term_weights.size() != ANCHOR_LONG_TERM_WEIGHTS) {
        why = "anchor .inc window lengths are "
            + std::to_string(out.difficulty_window.size()) + "/"
            + std::to_string(out.short_term_weights.size()) + "/"
            + std::to_string(out.long_term_weights.size()) + ", required "
            + std::to_string(ANCHOR_DIFFICULTY_WINDOW) + "/"
            + std::to_string(ANCHOR_SHORT_TERM_WEIGHTS) + "/"
            + std::to_string(ANCHOR_LONG_TERM_WEIGHTS);
        return AnchorParse::BadField;
    }

    const std::array<std::uint8_t, 32> got = anchor_hash::sha256(body);
    if (got != file_digest) {
        why = "anchor .inc digest mismatch: body hashes to " + to_hex(got)
            + ", file says " + to_hex(file_digest);
        return AnchorParse::DigestMismatch;
    }
    out.digest = file_digest;

    why.clear();
    return AnchorParse::Ok;
}

}  // namespace c2pool::xmr::native
