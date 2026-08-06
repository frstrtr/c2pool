// SPDX-License-Identifier: AGPL-3.0-or-later
// D-DASH.SHARE-REMOVE-OWNS-DATA — source-structural guard pinning that the
// think-P1 bad-share removal borrows (owns_data=false) from `verified` and lets
// only the owning `chain` destroy the share.
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
#include <gtest/gtest.h>

#include <cstddef>
#include <fstream>
#include <sstream>
#include <string>

#ifndef DASH_SHARE_TRACKER_SRC
#error "DASH_SHARE_TRACKER_SRC must be defined by CMake to the path of src/impl/dash/share_tracker.hpp"
#endif

namespace {

std::string read_text(const char* path)
{
    std::ifstream in(path);
    EXPECT_TRUE(in.good()) << "cannot open " << path;
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

// The think-P1 removal block must exist — anchor the assertions to real code.
TEST(DashShareRemoveOwnsData, RemovalBlockPresent)
{
    const std::string code = strip_comments(read_text(DASH_SHARE_TRACKER_SRC));
    EXPECT_NE(code.find("if (chain.remove(bad))"), std::string::npos)
        << "think-P1 bad-share removal block not found — test anchor is stale";
    EXPECT_GE(count_of(code, "verified.remove(bad"), 1u)
        << "expected a verified.remove(bad ...) in the removal block";
}

// #1131: the borrowing view must NEVER be removed-from with the default
// owns_data=true. The bare `verified.remove(bad)` form (no second argument)
// destroys a share `chain` also owns -> double free.
TEST(DashShareRemoveOwnsData, VerifiedRemoveDoesNotOwnData)
{
    const std::string code = strip_comments(read_text(DASH_SHARE_TRACKER_SRC));

    // RED against the shipped bug: exactly the bare, owns_data-defaulted form.
    EXPECT_EQ(count_of(code, "verified.remove(bad)"), 0u)
        << "verified.remove(bad) defaults owns_data=true and destroy()s a share "
           "chain.remove(bad) also owns -> #1131 double free; pass "
           "/*owns_data=*/false so the borrowing view cannot destroy";

    // GREEN shape: the call carries an explicit second argument, and it is false.
    const std::string args = remove_call_args(code);
    ASSERT_FALSE(args.empty()) << "no verified.remove(bad ...) call found";
    EXPECT_NE(args.find(','), std::string::npos)
        << "verified.remove(bad ...) must pass an explicit owns_data argument";
    EXPECT_NE(args.find("false"), std::string::npos)
        << "verified is a borrowing view — owns_data must be false";
    EXPECT_EQ(args.find("true"), std::string::npos)
        << "owns_data=true on a borrowing view double-frees with chain.remove()";
}
