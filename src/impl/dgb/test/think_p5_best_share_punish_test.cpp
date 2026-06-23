// dgb think() Phase-5 BEST-SHARE PUNISH WALK conformance KAT.
//
// FENCED, additive (no production code touched this slice). Pins
// src/impl/dgb/think_p5_best_share_punish.hpp against the p2pool data.py
// think() best-share resolution oracle (data.py:2142-2166): walk back off a
// naughty head, then dive to the deepest non-naughty descendant; report the
// punishment of the share finally landed on.
//
// Expectations are HAND-DERIVED by tracing the walk rules over a fake chain,
// NOT read back from the code under test — a conformance KAT that asks its
// subject for the answer passes vacuously. Pure graph traversal: links only
// core (no chain standup). MUST appear in BOTH this dir s CMakeLists.txt AND the
// build.yml --target allowlist, or it becomes a #143 NOT_BUILT sentinel
// (compiled-out, silently "passing").

#include <impl/dgb/think_p5_best_share_punish.hpp>

#include <gtest/gtest.h>

#include <map>
#include <string>
#include <vector>

namespace {

// A hand-built fake sharechain keyed by short string hashes. "" is the null
// sentinel. Each node carries a naughty count and a prev pointer; children are
// derived as the reverse of prev.
struct FakeChain {
    std::map<std::string, int32_t> naughty;          // present => contained
    std::map<std::string, std::string> prev;         // hash -> prev hash ("" = none)

    dgb::P5ChainAccessors<std::string> accessors() const {
        dgb::P5ChainAccessors<std::string> a;
        a.naughty = [this](const std::string& h) -> int32_t {
            auto it = naughty.find(h);
            return it == naughty.end() ? 0 : it->second;
        };
        a.prev_of = [this](const std::string& h) -> std::string {
            auto it = prev.find(h);
            return it == prev.end() ? std::string() : it->second;
        };
        a.contains = [this](const std::string& h) -> bool {
            return naughty.find(h) != naughty.end();
        };
        a.children = [this](const std::string& h) -> std::vector<std::string> {
            std::vector<std::string> kids;
            for (const auto& [k, p] : prev)
                if (p == h) kids.push_back(k);
            return kids;
        };
        a.is_null = [](const std::string& h) -> bool { return h.empty(); };
        return a;
    }
};

// ---- (1) a non-naughty head is its own best, punish 0 ----------------------
TEST(ThinkP5BestSharePunish, NonNaughtyHeadIsOwnBest)
{
    FakeChain c;
    c.naughty = {{"G", 0}, {"M", 0}};
    c.prev    = {{"M", "G"}, {"G", ""}};
    auto r = dgb::think_p5_best_share_punish<std::string>("M", true, c.accessors());
    EXPECT_EQ(r.best, "M");          // loop never entered
    EXPECT_EQ(r.punish_val, 0);
}

// ---- (2) start_valid == false is returned verbatim, walk skipped -----------
TEST(ThinkP5BestSharePunish, InvalidStartReturnedVerbatim)
{
    FakeChain c;
    c.naughty = {{"Z", 4}};          // naughty data present but must be ignored
    c.prev    = {{"Z", ""}};
    auto r = dgb::think_p5_best_share_punish<std::string>("Z", false, c.accessors());
    EXPECT_EQ(r.best, "Z");
    EXPECT_EQ(r.punish_val, 0);
}

// ---- (3) walk back off naughty heads, dive to deepest non-naughty descendant
// Chain:  G(0) -> A(3) -> X(2)=start
//         G(0) -> C(0) -> D(0) -> E(0, leaf)
// Trace: X naughty -> A naughty -> G non-naughty; dive from G: child A skipped
// (naughty), child C -> D -> E gives the deepest non-naughty chain => best = E.
// idx rests on G (naughty 0) => punish 0. Hand-derived, independent of subject.
TEST(ThinkP5BestSharePunish, WalkBackThenDiveToDeepestDescendant)
{
    FakeChain c;
    c.naughty = {{"G", 0}, {"A", 3}, {"X", 2}, {"C", 0}, {"D", 0}, {"E", 0}};
    c.prev    = {{"G", ""}, {"A", "G"}, {"X", "A"}, {"C", "G"}, {"D", "C"}, {"E", "D"}};
    auto r = dgb::think_p5_best_share_punish<std::string>("X", true, c.accessors());
    EXPECT_EQ(r.best, "E");
    EXPECT_EQ(r.punish_val, 0);
}

// ---- (4) the dive skips naughty children -----------------------------------
// As (3) but C also has a DEEPER naughty branch C -> F(7) -> H(0). H is deeper
// than E, but F is naughty so the whole branch is excluded; best is still E.
TEST(ThinkP5BestSharePunish, DiveSkipsNaughtyChildren)
{
    FakeChain c;
    c.naughty = {{"G", 0}, {"A", 3}, {"X", 2}, {"C", 0}, {"D", 0}, {"E", 0},
                 {"F", 7}, {"H", 0}};
    c.prev    = {{"G", ""}, {"A", "G"}, {"X", "A"}, {"C", "G"}, {"D", "C"},
                 {"E", "D"}, {"F", "C"}, {"H", "F"}};
    auto r = dgb::think_p5_best_share_punish<std::string>("X", true, c.accessors());
    EXPECT_EQ(r.best, "E");          // C->F->H excluded (F naughty); C->D->E wins
    EXPECT_EQ(r.punish_val, 0);
}

// ---- (5) naughty all the way to a missing prev -> stop, report punishment ---
// Chain:  Q(absent) <- P(5)=start.  prev(P)=Q but Q is NOT contained, so the
// walk breaks ON P. idx still points at P => punish = P naughty = 5.
TEST(ThinkP5BestSharePunish, NaughtyToMissingPrevReportsPunish)
{
    FakeChain c;
    c.naughty = {{"P", 5}};          // Q deliberately absent
    c.prev    = {{"P", "Q"}};
    auto r = dgb::think_p5_best_share_punish<std::string>("P", true, c.accessors());
    EXPECT_EQ(r.best, "P");
    EXPECT_EQ(r.punish_val, 5);
}

// ---- (6) naughty head with a null prev -> stop ON it, report punishment -----
TEST(ThinkP5BestSharePunish, NaughtyWithNullPrevReportsPunish)
{
    FakeChain c;
    c.naughty = {{"P", 2}};
    c.prev    = {{"P", ""}};         // null prev sentinel
    auto r = dgb::think_p5_best_share_punish<std::string>("P", true, c.accessors());
    EXPECT_EQ(r.best, "P");
    EXPECT_EQ(r.punish_val, 2);
}

} // namespace
