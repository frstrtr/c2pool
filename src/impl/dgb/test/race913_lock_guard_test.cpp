// D-DGB.RACE913 — source-structural guard pinning notify_local_share`s lock scope.
//
// The fix folds the racy chain.contains() read INSIDE the try_to_lock scope so
// contains + attempt_verify hold one continuous lock, gated on owns_lock() —
// the BTC reference shape (btc/node.cpp:1054-1058; LTC mirror f445db8e). The
// prior code read m_tracker.chain.contains() UNLOCKED in the early-return guard,
// racing clean_tracker()`s exclusive prune -> UAF/SIGSEGV once an M3/#82 caller
// wires notify_local_share (today zero callers -> latent).
//
// A true data-race repro is nondeterministic; this guard is the deterministic
// red/green the invariant admits: it parses the shipped node.cpp and asserts the
// contains() read sits under owns_lock(), NOT in the unlocked early-return.
// Perturb node.cpp back to the unlocked form -> RED; restore -> GREEN.
#include <gtest/gtest.h>
#include <fstream>
#include <sstream>
#include <string>

#ifndef DGB_NODE_SRC
#error "DGB_NODE_SRC must be defined by CMake to the path of src/impl/dgb/node.cpp"
#endif

namespace {

// Return the body text of NodeImpl::notify_local_share(...) from node.cpp.
std::string read_notify_local_share_body()
{
    std::ifstream in(DGB_NODE_SRC);
    EXPECT_TRUE(in.good()) << "cannot open " << DGB_NODE_SRC;
    std::stringstream ss; ss << in.rdbuf();
    const std::string src = ss.str();

    const std::string sig = "void NodeImpl::notify_local_share";
    auto start = src.find(sig);
    EXPECT_NE(start, std::string::npos) << "notify_local_share not found";
    // Stop at the next top-level NodeImpl member definition.
    auto end = src.find("\nvoid NodeImpl::", start + sig.size());
    if (end == std::string::npos) end = src.size();
    return src.substr(start, end - start);
}

std::string line_containing(const std::string& body, const std::string& needle)
{
    auto pos = body.find(needle);
    if (pos == std::string::npos) return "";
    auto ls = body.rfind(char(10), pos);
    auto le = body.find(char(10), pos);
    ls = (ls == std::string::npos) ? 0 : ls + 1;
    le = (le == std::string::npos) ? body.size() : le;
    return body.substr(ls, le - ls);
}

} // namespace

// The chain read must be reachable ONLY through owns_lock() short-circuit.
TEST(Race913LockGuard, ContainsReadIsGatedOnOwnsLock)
{
    const std::string body = read_notify_local_share_body();
    const std::string owns_line = line_containing(body, "owns_lock()");
    ASSERT_FALSE(owns_line.empty()) << "owns_lock() guard missing entirely";
    EXPECT_NE(owns_line.find("chain.contains(share_hash)"), std::string::npos)
        << "chain.contains(share_hash) must sit on the owns_lock() conditional "
           "(BTC btc/node.cpp:1054 shape). Line was: " << owns_line;
}

// The unlocked early-return must NOT touch the tracker chain.
TEST(Race913LockGuard, EarlyReturnDoesNotReadChain)
{
    const std::string body = read_notify_local_share_body();
    const std::string null_line = line_containing(body, "IsNull()");
    ASSERT_FALSE(null_line.empty()) << "IsNull() early-return missing";
    EXPECT_EQ(null_line.find("contains"), std::string::npos)
        << "early-return reads the chain UNLOCKED (the pre-fix UAF shape). "
           "Line was: " << null_line;
}

// Exactly one chain.contains(share_hash) read in the function (no stray copy).
TEST(Race913LockGuard, SingleGatedContainsRead)
{
    const std::string body = read_notify_local_share_body();
    size_t n = 0, pos = 0;
    const std::string needle = "chain.contains(share_hash)";
    while ((pos = body.find(needle, pos)) != std::string::npos) { ++n; pos += needle.size(); }
    EXPECT_EQ(n, 1u) << "expected exactly one gated chain.contains(share_hash)";
}
