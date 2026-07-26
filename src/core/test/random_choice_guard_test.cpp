// Regression cover for issue #869 — the inverted addrme peer-relay guard.
//
// Two independent layers:
//
//  1. core::random::random_choice() must never index/dereference past the end
//     of an empty container. Before the fix random_int(0, 0) returned 0 and the
//     vector overload read list[0] while the map/list overloads dereferenced
//     end() — undefined behaviour reachable from a protocol handler.
//
//  2. A source KAT over the five per-coin protocol_legacy.cpp / protocol_actual.cpp
//     addrme handlers. Canonical p2pool (p2p.py handle_addrme) relays only when
//     the node HAS peers; the Legacy handlers shipped the inverted
//     `m_peers.empty()` predicate, so the relay fired only when there was
//     nothing to relay to and then picked a random element out of the empty
//     container. The KAT pins every guard to the `!m_peers.empty()` form so the
//     inversion cannot silently return in any of the ten sites.
//
// Folded into the EXISTING allowlisted core_test target — a standalone
// add_executable is not in build.yml's --target list, so CI would never build
// it and CTest would report the cases "Not Run".

#include <gtest/gtest.h>

#include <core/random.hpp>

#include <fstream>
#include <list>
#include <map>
#include <memory>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Layer 1: empty-container defence in depth
// ---------------------------------------------------------------------------

TEST(RandomChoiceGuard, EmptyVectorThrowsInsteadOfIndexingPastEnd)
{
    std::vector<int> empty;
    EXPECT_THROW(core::random::random_choice(empty), std::out_of_range);
}

TEST(RandomChoiceGuard, EmptyConstVectorThrowsInsteadOfIndexingPastEnd)
{
    const std::vector<int> empty;
    EXPECT_THROW(core::random::random_choice(empty), std::out_of_range);
}

TEST(RandomChoiceGuard, EmptyMapThrowsInsteadOfDereferencingEnd)
{
    // Mirrors pool::NodeInterface::m_peers — std::map<uint64_t, peer_ptr>.
    std::map<uint64_t, std::shared_ptr<int>> empty;
    EXPECT_THROW(core::random::random_choice(empty), std::out_of_range);
}

TEST(RandomChoiceGuard, EmptyListThrowsInsteadOfDereferencingEnd)
{
    std::list<int> empty;
    EXPECT_THROW(core::random::random_choice(empty), std::out_of_range);
}

TEST(RandomChoiceGuard, NonEmptyContainersStillReturnAMember)
{
    std::vector<int> v{7};
    EXPECT_EQ(7, core::random::random_choice(v));

    const std::vector<int> cv{9};
    EXPECT_EQ(9, core::random::random_choice(cv));

    std::map<uint64_t, int> m{{42u, 11}};
    EXPECT_EQ(11, core::random::random_choice(m));

    std::list<int> l{13};
    EXPECT_EQ(13, core::random::random_choice(l));

    // Multi-element: every draw must be an actual member, never a past-the-end
    // read. 64 draws is plenty to shake out an off-by-one in random_int's
    // half-open [min, max) contract.
    std::vector<int> many{1, 2, 3, 4, 5};
    for (int i = 0; i < 64; ++i)
    {
        const int drawn = core::random::random_choice(many);
        EXPECT_GE(drawn, 1);
        EXPECT_LE(drawn, 5);
    }

    std::map<uint64_t, int> mmany{{1u, 10}, {2u, 20}, {3u, 30}};
    for (int i = 0; i < 64; ++i)
    {
        const int drawn = core::random::random_choice(mmany);
        EXPECT_TRUE(drawn == 10 || drawn == 20 || drawn == 30);
    }
}

// ---------------------------------------------------------------------------
// Layer 2: source KAT over the per-coin addrme handlers
// ---------------------------------------------------------------------------

namespace
{

const char* const kCoins[] = {"dash", "ltc", "btc", "dgb", "bch"};

std::string read_source(const std::string& coin, const std::string& generation)
{
    const std::string path =
        std::string(C2POOL_SRC_ROOT) + "/impl/" + coin + "/protocol_" + generation + ".cpp";
    std::ifstream in(path);
    EXPECT_TRUE(in.good()) << "cannot open " << path;
    std::ostringstream buf;
    buf << in.rdbuf();
    return buf.str();
}

// Extract the body of `void <Qualifier>::HANDLER(<name>)` up to the closing
// brace of the handler (the handlers are brace-balanced and never contain a
// string literal with an unbalanced brace).
std::string handler_body(const std::string& src, const std::string& handler)
{
    const std::string needle = "::HANDLER(" + handler + ")";
    const auto at = src.find(needle);
    EXPECT_NE(std::string::npos, at) << "handler " << handler << " not found";
    if (at == std::string::npos)
        return {};

    const auto open = src.find('{', at);
    EXPECT_NE(std::string::npos, open);
    if (open == std::string::npos)
        return {};

    int depth = 0;
    for (auto i = open; i < src.size(); ++i)
    {
        if (src[i] == '{')
            ++depth;
        else if (src[i] == '}')
        {
            --depth;
            if (depth == 0)
                return src.substr(open, i - open + 1);
        }
    }
    ADD_FAILURE() << "unbalanced handler body for " << handler;
    return {};
}

size_t count_matches(const std::string& hay, const std::regex& re)
{
    return static_cast<size_t>(
        std::distance(std::sregex_iterator(hay.begin(), hay.end(), re), std::sregex_iterator()));
}

} // namespace

// The relay guard must be `!m_peers.empty()` in BOTH generations of all five
// coins, on BOTH branches of addrme (the 127.x self-probe branch and the
// ordinary-peer branch). The inverted form must appear nowhere.
TEST(AddrmeRelayGuard, GuardsOnHavingPeersNotOnHavingNone)
{
    const std::regex correct(R"(!\s*m_peers\.empty\(\))");
    // A `m_peers.empty()` that is NOT preceded by `!` — the #869 inversion.
    const std::regex inverted(R"((^|[^!])\s*\(?\s*m_peers\.empty\(\))");

    for (const char* coin : kCoins)
    {
        for (const char* generation : {"legacy", "actual"})
        {
            const std::string src = read_source(coin, generation);
            const std::string body = handler_body(src, "addrme");
            ASSERT_FALSE(body.empty()) << coin << "/" << generation;

            EXPECT_EQ(2u, count_matches(body, correct))
                << coin << "::" << generation
                << " addrme must relay on !m_peers.empty() on BOTH branches";
            EXPECT_EQ(0u, count_matches(body, inverted))
                << coin << "::" << generation
                << " addrme still carries the inverted m_peers.empty() guard (#869)";
        }
    }
}

// Audit companion: HANDLER(addrs) relays through m_connections and was already
// guarded correctly. Pin it so it does not drift into the same inversion.
TEST(AddrsRelayGuard, GuardsOnHavingConnections)
{
    const std::regex correct(R"(!\s*m_connections\.empty\(\))");
    const std::regex inverted(R"((^|[^!])\s*\(?\s*m_connections\.empty\(\))");

    for (const char* coin : kCoins)
    {
        for (const char* generation : {"legacy", "actual"})
        {
            const std::string src = read_source(coin, generation);
            const std::string body = handler_body(src, "addrs");
            ASSERT_FALSE(body.empty()) << coin << "/" << generation;

            EXPECT_EQ(1u, count_matches(body, correct))
                << coin << "::" << generation << " addrs must relay on !m_connections.empty()";
            EXPECT_EQ(0u, count_matches(body, inverted))
                << coin << "::" << generation << " addrs carries an inverted connections guard";
        }
    }
}
