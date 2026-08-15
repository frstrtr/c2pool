// SPDX-License-Identifier: AGPL-3.0-or-later
// D-CORE.SHARE-VARIANTS-CLONE-OWNERSHIP — #1130 double-free / use-after-free in
// NodeImpl::handle_get_share.
//
// THE DEFECT (#1130):
//   handle_get_share() walks the sharechain under a try_to_lock shared_lock and
//   pushes each `data.share` — a chain::ShareVariants that holds a RAW pointer
//   the sharechain OWNS and frees under m_tracker_mutex — into the returned
//   vector. That local shared_lock is RELEASED when handle_get_share returns.
//   The sharereq handler (protocol_actual.cpp / protocol_legacy.cpp) then
//   serializes those variants with pack(share) AFTER the lock is gone, so a
//   concurrent think()/prune on the compute thread can destroy() the very
//   pointer being packed: a use-after-free, and a double free once the pointer
//   is freed twice. (send_shares() is NOT affected — its caller holds the lock
//   across the pack, so its borrows never escape the critical section.)
//
// THE FIX: handle_get_share hands back OWNED copies — `for (auto& s : shares)
//   s = s.clone();` — and the caller destroy()s them after the wire write. Same
//   borrow-vs-own discipline as the #1131/#1163 verified.remove(owns_data=false)
//   fix: a value that must outlive the lock owns its memory; a borrow never frees.
//
// This file pins BOTH halves:
//   (1) a RUNTIME test of the clone() primitive — clone() returns an independent
//       heap object, and destroy()ing the clone leaves the borrowed original
//       intact (under ASan the aliasing bug would be a hard double-free abort);
//   (2) a source-structural guard (mirror of share_remove_owns_data_test.cpp)
//       that every lane's handle_get_share clone()s before returning and every
//       sharereq handler destroy()s the owned copies — deterministic red/green
//       covering all five lanes incl. dash, which has no runtime test target.

#include <gtest/gtest.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <variant>

#include <sharechain/share.hpp>

// ─────────────────────────────────────────────────────────────────────────────
// (1) Runtime: clone() ownership contract
// ─────────────────────────────────────────────────────────────────────────────
namespace {

struct DummyFormatter {};   // clone()/destroy()/hash() never touch the formatter

struct DummyShare : chain::BaseShare<uint64_t, 1>
{
    uint64_t payload{0};
    DummyShare() = default;
};

using DummyVariant = chain::ShareVariants<DummyFormatter, DummyShare>;

} // namespace

TEST(ShareVariantsClone_1130, CloneYieldsIndependentOwnedCopy)
{
    auto* owned = new DummyShare();
    owned->m_hash  = 0xABCDEFu;
    owned->payload = 42u;

    DummyVariant borrow;
    borrow = owned;                        // BORROW — aliases a pointer we own here

    DummyVariant copy = borrow.clone();    // OWNED — independent heap allocation

    // Distinct heap object, not an alias of the borrowed pointer.
    EXPECT_NE(std::get<DummyShare*>(copy), owned);
    // Deep-copied value + identity hash.
    EXPECT_EQ(std::get<DummyShare*>(copy)->payload, 42u);
    EXPECT_EQ(copy.hash(), owned->m_hash);

    // Destroying the clone must free ONLY the copy. If clone() had aliased the
    // borrowed pointer (the #1130 bug), this destroy() + the delete below would
    // free `owned` twice — a double free (ASan: heap-use-after-free / abort).
    copy.destroy();

    EXPECT_EQ(owned->payload, 42u);        // still readable → the original was NOT freed
    EXPECT_EQ(owned->m_hash, 0xABCDEFu);

    delete owned;                          // single, correct free of the original
}

// ─────────────────────────────────────────────────────────────────────────────
// (2) Source-structural: every lane clones on serve, every handler frees.
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

// Blank every comment (preserving offsets) so the assertions run over real code
// — the fix's own doc comments quote "clone()" / "destroy()" verbatim.
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

TEST(ShareVariantsClone_1130, HandleGetShareReturnsOwnedCopiesAllLanes)
{
    for (const char* lane : kLanes) {
        const std::string node =
            strip_comments(read_text(std::string(C2POOL_IMPL_DIR) + "/" + lane + "/node.cpp"));

        ASSERT_NE(node.find("handle_get_share"), std::string::npos)
            << lane << ": handle_get_share not found — test anchor is stale";

        // The served borrows must be turned into OWNED copies before the lock is
        // released. Revert the clone() → RED.
        EXPECT_NE(node.find(".clone()"), std::string::npos)
            << lane << ": handle_get_share must hand back OWNED clone()s, not the "
                       "raw pointers the sharechain frees under m_tracker_mutex (#1130)";
    }
}

TEST(ShareVariantsClone_1130, SharereqHandlersFreeOwnedCopiesAllLanes)
{
    for (const char* lane : kLanes) {
        for (const char* proto : {"protocol_actual.cpp", "protocol_legacy.cpp"}) {
            const std::string code =
                strip_comments(read_text(std::string(C2POOL_IMPL_DIR) + "/" + lane + "/" + proto));

            ASSERT_NE(code.find("handle_get_share"), std::string::npos)
                << lane << "/" << proto << ": sharereq handler not found — anchor stale";

            // The owned copies clone() produced must be freed exactly once, on
            // every path. Drop the destroy() → RED (leak; and the whole point of
            // owning the copy is lost).
            EXPECT_NE(code.find("share.destroy()"), std::string::npos)
                << lane << "/" << proto << ": sharereq handler must destroy() the "
                           "OWNED copies handle_get_share cloned for it (#1130)";
        }
    }
}
