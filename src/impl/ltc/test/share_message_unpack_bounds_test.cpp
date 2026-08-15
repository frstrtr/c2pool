// SPDX-License-Identifier: AGPL-3.0-or-later
// D-P2P.SHARE-MESSAGE-UNPACK-BOUNDS — #1129 out-of-bounds read in
// ShareMessage::unpack from an unsigned-underflow bounds check.
//
// THE DEFECT (#1129):
//   unpack(const unsigned char* data, size_t len, size_t offset, ShareMessage&)
//   opened with
//         if (len - offset < 8) return std::nullopt;
//   `len` and `offset` are size_t. If a caller passes offset > len, `len - offset`
//   WRAPS to a huge unsigned value, the `< 8` test is false, and the function
//   proceeds to std::memcpy(&out.msg_type, data + offset, ...) — an out-of-bounds
//   read past the buffer. Every one of the five lane copies (dash/ltc/dgb/bch/btc)
//   shipped the bare form.
//
//   Reachable-today or not, it is a one-token self-guard: the fix rejects an
//   offset past the end BEFORE the subtraction —
//         if (offset > len || len - offset < 8) return std::nullopt;
//
// This file pins BOTH halves:
//   (1) RUNTIME on the real ltc::ShareMessage::unpack — an offset past the end,
//       and a truncated header, must both return std::nullopt (never read OOB).
//       On the pre-fix form the overflow case does NOT return nullopt (and reads
//       OOB — a hard abort under ASan): RED. With the self-guard: GREEN.
//   (2) a source-structural guard that all five lanes carry the `offset > len`
//       self-guard on the first bounds check — covers dash, which has no runtime
//       test target of its own.

#include <gtest/gtest.h>

#include <cstddef>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <impl/ltc/share_messages.hpp>

// ─────────────────────────────────────────────────────────────────────────────
// (1) Runtime: truncated / overflow offset returns nullopt, never OOB-reads.
// ─────────────────────────────────────────────────────────────────────────────
TEST(ShareMessageUnpackBounds_1129, OffsetPastEndReturnsNullopt)
{
    // 5-byte buffer, offset=10 (> len). The bare `len - offset < 8` underflows
    // to ~2^64 and passes, then memcpy reads at data+10 — out of bounds. The
    // self-guard must reject this and return nullopt.
    std::vector<unsigned char> buf(5, 0x00);
    ltc::ShareMessage msg;
    const auto r = ltc::ShareMessage::unpack(buf.data(), buf.size(), /*offset=*/10, msg);
    EXPECT_FALSE(r.has_value())
        << "offset > len must return nullopt, not underflow the bounds check "
           "and read out of bounds (#1129)";
}

TEST(ShareMessageUnpackBounds_1129, OffsetEqualsLenReturnsNullopt)
{
    // Boundary: offset == len, zero bytes remain — len - offset == 0 < 8.
    std::vector<unsigned char> buf(8, 0x00);
    ltc::ShareMessage msg;
    const auto r = ltc::ShareMessage::unpack(buf.data(), buf.size(), /*offset=*/8, msg);
    EXPECT_FALSE(r.has_value());
}

TEST(ShareMessageUnpackBounds_1129, TruncatedHeaderReturnsNullopt)
{
    // Fewer than the 8 header bytes present from offset 0 — the guard's original
    // intent, which must keep working with the self-guard added.
    std::vector<unsigned char> buf(4, 0x00);
    ltc::ShareMessage msg;
    const auto r = ltc::ShareMessage::unpack(buf.data(), buf.size(), /*offset=*/0, msg);
    EXPECT_FALSE(r.has_value());
}

// ─────────────────────────────────────────────────────────────────────────────
// (2) Source-structural: every lane carries the offset>len self-guard.
// ─────────────────────────────────────────────────────────────────────────────
#ifndef C2POOL_IMPL_DIR
#error "C2POOL_IMPL_DIR must be defined by CMake to the path of src/impl"
#endif

namespace {

std::string read_text(const std::string& path)
{
    std::ifstream in(path);
    EXPECT_TRUE(in.good()) << "cannot open " << path;
    std::stringstream ss; ss << in.rdbuf();
    return ss.str();
}

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
        case kLine:  if (c == '\n') st = kCode; else out[i] = ' '; break;
        case kBlock: if (c == '*' && n == '/') { out[i] = ' '; out[i + 1] = ' '; ++i; st = kCode; }
                     else if (c != '\n') out[i] = ' '; break;
        case kStr:   if (c == '\\') ++i; else if (c == '"')  st = kCode; break;
        case kChr:   if (c == '\\') ++i; else if (c == '\'') st = kCode; break;
        }
    }
    return out;
}

const char* kLanes[] = {"dash", "ltc", "dgb", "bch", "btc"};

} // namespace

TEST(ShareMessageUnpackBounds_1129, SelfGuardPresentAllLanes)
{
    for (const char* lane : kLanes) {
        const std::string code =
            strip_comments(read_text(std::string(C2POOL_IMPL_DIR) + "/" + lane + "/share_messages.hpp"));

        ASSERT_NE(code.find("ShareMessage::unpack"), std::string::npos)
            << lane << ": ShareMessage::unpack not found — test anchor is stale";

        // The combined self-guard. The bare form `len - offset < 8` alone
        // underflows on offset>len; the fix prepends `offset > len ||`.
        EXPECT_NE(code.find("offset > len || len - offset < 8"), std::string::npos)
            << lane << ": ShareMessage::unpack must self-guard offset > len BEFORE "
                       "the size_t subtraction (#1129)";
    }
}
