#pragma once

// Phase S8 — WonBlock dual-arm delivery plan + reached-network verdict (LEAF).
//
// THE last PURE rung before the operator-gated broadcaster_full keystone. The
// binding (block_relay_binding.hpp) joins the live broadcaster pool to the
// planner and yields an AnnouncePlan (one inv frame + the live slot keys). A won
// block must reach the network by EITHER of two independent arms:
//
//     [won block] --+-- embedded-P2P arm  -- inv fan-out to live pool slots
//                   +-- dashd submitblock  -- raw-block RPC fallback
//
// This leaf decides, as INERT data, WHICH arms a given won block is armed on,
// and (separately) evaluates whether the block actually REACHED the network once
// the keystone has executed both arms and reported their results. It performs no
// I/O: it opens no socket, drives no io_context, issues no RPC, recomputes no
// hash. The keystone walks the plan, writes the inv frames onto the live slots'
// sockets, calls dashd submitblock with the raw bytes, collects the per-arm
// results, and hands them back to evaluate() for the won-block-reaches-network
// verdict. That transmit + RPC is the keystone's operator-gated concern; the
// DECISION of arms and the verdict LOGIC are pure and unit-testable here, with
// zero sockets and zero live dashd, like every sibling leaf.
//
// SCOPE / NON-CONSENSUS: single dash tree, header-only, socket-free. The raw
// block bytes are an OPAQUE, caller-supplied blob (the won block as captured for
// submission, the same span the broadcaster's submit_block_raw_all / FanOutHook
// already consume) -- they are carried verbatim, NOT re-serialized here, and no
// consensus value is computed or altered.

#include "block_relay_binding.hpp"
#include "block_relay_plan.hpp"

#include <core/uint256.hpp>

#include <cstddef>
#include <span>
#include <utility>
#include <vector>

namespace dash
{

// The dual-arm delivery plan for ONE won block: the embedded-P2P fan-out plan
// plus the raw block bytes for the dashd submitblock fallback, each tagged with
// whether that arm is armed. The submitblock arm is armed whenever raw bytes are
// present, INDEPENDENT of live-slot count -- so a won block with zero live peers
// still ships via dashd. The P2P arm is armed only when the live pool is
// non-empty. Both arms are INERT: nothing is transmitted until the keystone
// walks this plan.
struct DualArmPlan
{
    AnnouncePlan               p2p;                 // inv frame + live slot keys
    std::vector<unsigned char> submitblock_bytes;   // raw won block (opaque)
    bool                       p2p_armed{false};     // live pool non-empty
    bool                       submitblock_armed{false}; // raw bytes present

    // True if the block is armed on at least one arm -- i.e. there is some path
    // to the network. A won block recorded with no live peers and no raw bytes is
    // a dead end (caller error); both arms then report false.
    bool any_armed() const { return p2p_armed || submitblock_armed; }
};

// The post-execution verdict: did the won block actually reach the network? The
// keystone fills this in AFTER it has driven both arms, from the real results:
//   * p2p_acks       -- how many live slots accepted the inv fan-out (>=1 relayed)
//   * submitblock_ok -- dashd accepted the raw block via the RPC fallback
// reached_network is the OR of the two arms: a single successful arm suffices.
struct DeliveryVerdict
{
    std::size_t p2p_acks{0};
    bool        submitblock_ok{false};

    bool reached_network() const { return p2p_acks > 0 || submitblock_ok; }
};

// Builds dual-arm delivery plans over a binding (which owns the live-pool view
// and the relay book). Stateless and pure: opens no socket, recomputes no hash.
class DualArmPlanner
{
public:
    explicit DualArmPlanner(WonBlockRelayBinding& binding) : m_binding(binding) {}

    // Record the won block (via the binding -> planner -> relay) and build its
    // dual-arm plan against the broadcaster's CURRENT live slots. The raw bytes
    // are carried verbatim for the dashd submitblock arm and copied into the
    // plan so it outlives the caller's buffer. The P2P arm is armed iff the live
    // fan-out is non-empty; the submitblock arm is armed iff raw bytes were
    // supplied. The block records even when BOTH would be disarmed (recording is
    // decoupled from delivery), so a peer connecting later can still getdata it.
    DualArmPlan plan(const uint256& hash,
                     WonBlockRelay::BlockType block,
                     std::span<const unsigned char> raw_block_bytes)
    {
        DualArmPlan out;
        out.p2p = m_binding.plan_announce(hash, std::move(block));
        out.submitblock_bytes.assign(raw_block_bytes.begin(), raw_block_bytes.end());
        out.p2p_armed         = out.p2p.fanout() > 0;
        out.submitblock_armed = !out.submitblock_bytes.empty();
        return out;
    }

    // Pure verdict evaluator: given the per-arm results the keystone observed,
    // decide whether the won block reached the network. Static -- it depends only
    // on the reported results, not on any pool state.
    static DeliveryVerdict evaluate(std::size_t p2p_acks, bool submitblock_ok)
    {
        DeliveryVerdict v;
        v.p2p_acks       = p2p_acks;
        v.submitblock_ok = submitblock_ok;
        return v;
    }

private:
    WonBlockRelayBinding& m_binding;
};

} // namespace dash
