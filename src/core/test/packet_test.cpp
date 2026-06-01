#include <gtest/gtest.h>

#include <cstddef>
#include <limits>
#include <ios>
#include <vector>

#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/message.hpp>
#include <core/hash.hpp>
#include <core/packet.hpp>

// A4 (Bug-9 hardening) cap-boundary tests for the Packet read-constructor.
// The read ctor caps prefix_length at MAX_PREFIX_LENGTH (16) and throws
// std::ios_base::failure on over-cap values, which is how UAF garbage from a
// destroyed m_node (Bug-3-family rapid disconnect/reconnect) is rejected
// without crashing the process. See src/core/packet.hpp.
namespace {

constexpr size_t kCap = 16; // must track MAX_PREFIX_LENGTH in packet.hpp

// --- at/under the cap: must succeed and size the prefix exactly ---

TEST(PacketPrefixCap, ZeroLengthSucceeds)
{
    core::Packet p(0);
    EXPECT_EQ(p.prefix.size(), 0u);
}

TEST(PacketPrefixCap, JustUnderCapSucceeds)
{
    core::Packet p(kCap - 1);
    EXPECT_EQ(p.prefix.size(), kCap - 1);
}

TEST(PacketPrefixCap, AtCapSucceeds)
{
    // Boundary: exactly at the cap is the largest accepted value.
    core::Packet p(kCap);
    EXPECT_EQ(p.prefix.size(), kCap);
}

// --- over the cap: must throw cleanly, never resize ---

TEST(PacketPrefixCap, JustOverCapThrows)
{
    EXPECT_THROW({ core::Packet p(kCap + 1); }, std::ios_base::failure);
}

TEST(PacketPrefixCap, WayOverCapThrows)
{
    EXPECT_THROW({ core::Packet p(1024); }, std::ios_base::failure);
}

TEST(PacketPrefixCap, UafGarbageMaxSizeThrows)
{
    // Simulates the garbage size_t read from a freed m_node vector; pre-cap
    // this reached resize() and aborted via std::length_error.
    EXPECT_THROW({ core::Packet p(std::numeric_limits<size_t>::max()); },
                 std::ios_base::failure);
}

} // namespace
