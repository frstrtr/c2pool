#include <gtest/gtest.h>

#include <core/block_broadcast.hpp>

// SSOT guard/policy KATs for core::broadcast_block_with_fallback.
//
// These lock the cross-coin won-block broadcast invariant at the core symbol
// (the BTC entry point is a thin delegate to this): primary-then-fallback
// ordering, no unconditional double-broadcast, both legs guarded against a
// throwing sink, and a never-silent-drop false return when neither sink takes
// the block.

namespace {

// 1. Primary P2P relay succeeds -> return true and DO NOT invoke the RPC
//    fallback (no unconditional double-broadcast).
TEST(CoreBlockBroadcast, PrimarySucceeds_NoDoubleBroadcast)
{
    bool rpc_called = false;
    bool ok = core::broadcast_block_with_fallback(
        [] { return true; },
        [&] { rpc_called = true; return true; });
    EXPECT_TRUE(ok);
    EXPECT_FALSE(rpc_called) << "RPC fallback must not fire after a successful P2P relay";
}

// 2. P2P relay returns false -> fall back to the RPC, which accepts.
TEST(CoreBlockBroadcast, PrimaryFails_FallbackAccepts)
{
    bool rpc_called = false;
    bool ok = core::broadcast_block_with_fallback(
        [] { return false; },
        [&] { rpc_called = true; return true; });
    EXPECT_TRUE(ok);
    EXPECT_TRUE(rpc_called) << "RPC fallback must fire when P2P relay did not succeed";
}

// 3. A THROWING P2P relay is a relay-FAILED mode, NOT a reason to skip the
//    fallback: the exception must be swallowed and the RPC must still fire.
TEST(CoreBlockBroadcast, PrimaryThrows_FallbackStillFires)
{
    bool rpc_called = false;
    bool ok = core::broadcast_block_with_fallback(
        [] () -> bool { throw std::runtime_error("relay blew up"); },
        [&] { rpc_called = true; return true; });
    EXPECT_TRUE(ok);
    EXPECT_TRUE(rpc_called) << "throwing P2P relay must not bypass the RPC fallback";
}

// 4. The last-resort RPC sink throwing collapses to a definite false return so
//    the caller's "reached neither sink, scream" path fires (not an escaping
//    exception).
TEST(CoreBlockBroadcast, FallbackThrows_ReturnsFalseNotException)
{
    bool ok = true;
    EXPECT_NO_THROW({
        ok = core::broadcast_block_with_fallback(
            [] { return false; },
            [] () -> bool { throw std::runtime_error("submitblock blew up"); });
    });
    EXPECT_FALSE(ok) << "a throwing RPC sink must collapse to false, never escape";
}

// 5. Both sinks decline -> false (won block reached NEITHER sink: caller screams).
TEST(CoreBlockBroadcast, NeitherSink_ReturnsFalse)
{
    bool ok = core::broadcast_block_with_fallback(
        [] { return false; },
        [] { return false; });
    EXPECT_FALSE(ok);
}

// 6. Null callables are tolerated and treated as unavailable sinks: a null P2P
//    leg falls through to the RPC; both null -> false (never a crash).
TEST(CoreBlockBroadcast, NullSinks_NoCrash)
{
    std::function<bool()> none;
    bool ok_rpc = core::broadcast_block_with_fallback(none, [] { return true; });
    EXPECT_TRUE(ok_rpc) << "null P2P leg must fall through to the RPC fallback";

    bool ok_neither = core::broadcast_block_with_fallback(none, none);
    EXPECT_FALSE(ok_neither) << "both sinks unavailable -> false, no crash";
}

} // namespace
