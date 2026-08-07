// SPDX-License-Identifier: AGPL-3.0-or-later
// B-BCH.SHARE-REMOVE-OWNS-DATA — source-structural guard pinning that the
// think-P1 bad-share removal borrows (owns_data=false) from `verified` and lets
// only the owning `chain` destroy the share. This is the BCH-lane mirror of the
// dash/btc/ltc KATs shipped with the #1131 fix (#1163): the source was fixed on
// all five lanes, but only three carried the regression pin. This file adds the
// missing pin on the BCH lane so a re-introduction of the owning form HERE fails.
//
// THE DEFECT THIS PINS (#1131, latent double free):
//   In ShareTracker::think() the bad-share removal does, per share `bad`:
//       if (verified.contains(bad)) verified.remove(bad);   // owns_data=TRUE (default)
//       if (chain.remove(bad))      ++removed_count;         // owns_data=TRUE (default)
//   `verified` is a BORROWING view — it holds the SAME raw share pointers that
//   `chain` OWNS (every removal in node.cpp already pairs
//   verified.remove(h, /*owns_data=*/false) with chain.remove(h)). With the
//   default owns_data=true, verified.remove() calls share.destroy() -> delete,
//   then chain.remove() calls destroy() on the SAME pointer again: a double
//   free / "unaligned tcache chunk" abort, exactly the hotel-primary signature.
//
//   It is UNREACHABLE TODAY only because of the `if (verified.contains(bad))
//   continue;` guard ~20 lines earlier, which makes the inner
//   `verified.contains(bad)` always false. The moment that guard is loosened
//   (e.g. wiring the mint path) the landmine arms. The fix pre-arms it: pass
//   owns_data=false so the borrowing view can never destroy.
//
// WHY A STRUCTURAL TEST: the buggy statement is dead code today, so a runtime
// repro cannot reach it without first perturbing unrelated control flow — the
// same situation as the sibling latent-UAF race913 (PR #1114) and the #1134
// oracle-ownership guard (PR #1150). A guard that asserts the OWNERSHIP SHAPE
// in the shipped source is the deterministic red/green this invariant admits.
// Restore the bare `verified.remove(bad);` form -> RED; keep the borrowing
// owns_data=false form -> GREEN.
//
// Harness: plain int main() + CHECK (the BCH test tree has no GTest dependency);
// the ASSERTION LOGIC is a faithful copy of the dash/btc/ltc KATs — same
// strip_comments / remove_call_args / count_of shape.
#include <cstddef>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#ifndef BCH_SHARE_TRACKER_SRC
#error "BCH_SHARE_TRACKER_SRC must be defined by CMake to the path of src/impl/bch/share_tracker.hpp"
#endif

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

std::string read_text(const char* path)
{
    std::ifstream in(path);
    CHECK(in.good());
    std::stringstream ss; ss << in.rdbuf();
    return ss.str();
}

// Replace every comment with spaces, preserving byte offsets and line breaks.
// The fix's own doc comment deliberately quotes the pre-fix `verified.remove(bad)`
// expression, so the assertions below MUST run over comment-free code or they
// would pass against the buggy form for the wrong reason.
std::string strip_comments(const std::string& s)
{
    std::string out = s;
    enum { kCode, kLine, kBlock, kStr, kChr } st = kCode;
    for (size_t i = 0; i < out.size(); ++i) {
        const char c = out[i];
        const char n = (i + 1 < out.size()) ? out[i + 1] : '\0';
        switch (st) {
        case kCode:
            if (c == '/' && n == '/') { st = kLine;  out[i] = ' '; out[i + 1] = ' '; ++i; }
            else if (c == '/' && n == '*') { st = kBlock; out[i] = ' '; out[i + 1] = ' '; ++i; }
            else if (c == '"')  st = kStr;
            else if (c == '\'') st = kChr;
            break;
        case kLine:
            if (c == '\n') st = kCode; else out[i] = ' ';
            break;
        case kBlock:
            if (c == '*' && n == '/') { out[i] = ' '; out[i + 1] = ' '; ++i; st = kCode; }
            else if (c != '\n') out[i] = ' ';
            break;
        case kStr:
            if (c == '\\') ++i; else if (c == '"') st = kCode;
            break;
        case kChr:
            if (c == '\\') ++i; else if (c == '\'') st = kCode;
            break;
        }
    }
    return out;
}

size_t count_of(const std::string& hay, const std::string& needle)
{
    size_t n = 0, pos = 0;
    while ((pos = hay.find(needle, pos)) != std::string::npos) { ++n; pos += needle.size(); }
    return n;
}

// The argument text of a `verified.remove(bad<...>)` call: everything between
// the first '(' after the match and its matching ')'.
std::string remove_call_args(const std::string& code)
{
    const std::string key = "verified.remove(bad";
    const size_t k = code.find(key);
    if (k == std::string::npos) return "";
    const size_t open = code.find('(', k);
    if (open == std::string::npos) return "";
    int depth = 0;
    for (size_t i = open; i < code.size(); ++i) {
        if (code[i] == '(') ++depth;
        else if (code[i] == ')') { if (--depth == 0) return code.substr(open + 1, i - open - 1); }
    }
    return "";
}

} // namespace

int main()
{
    const std::string code = strip_comments(read_text(BCH_SHARE_TRACKER_SRC));

    // The think-P1 removal block must exist — anchor the assertions to real code.
    CHECK(code.find("if (chain.remove(bad))") != std::string::npos);   // removal block present
    CHECK(count_of(code, "verified.remove(bad") >= 1u);                 // a verified.remove(bad ...) exists

    // #1131: the borrowing view must NEVER be removed-from with the default
    // owns_data=true. The bare `verified.remove(bad)` form (no second argument)
    // destroys a share `chain` also owns -> double free.
    // RED against the shipped bug: exactly the bare, owns_data-defaulted form.
    CHECK(count_of(code, "verified.remove(bad)") == 0u);

    // GREEN shape: the call carries an explicit second argument, and it is false.
    const std::string args = remove_call_args(code);
    CHECK(!args.empty());                              // a verified.remove(bad ...) call was found
    CHECK(args.find(',') != std::string::npos);        // explicit owns_data argument passed
    CHECK(args.find("false") != std::string::npos);    // borrowing view -> owns_data=false
    CHECK(args.find("true") == std::string::npos);     // owns_data=true would double-free

    if (failures == 0) std::cout << "bch_share_remove_owns_data_test: OK\n";
    return failures == 0 ? 0 : 1;
}
