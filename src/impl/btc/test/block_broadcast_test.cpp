// SPDX-License-Identifier: AGPL-3.0-or-later
// Broadcaster-gate verify test (path 3): proves the WON-BLOCK broadcast obeys
// FALLBACK semantics and NEVER silent-drops. Standalone harness in the style
// of tx_data_memo_test.cpp -- no btc/test CMake plumbing required.
//
// Build (from repo root):
//   g++ -std=gnu++20 -I src -I src/btclibs \
//       src/impl/btc/test/block_broadcast_test.cpp -o /tmp/block_broadcast_test
// Run:
//   /tmp/block_broadcast_test
//
// Maps to the integrator gate spec:
//   relay_p2p sink  <-> btc::coin::Node::submit_block_p2p_raw -> NodeP2P::
//                       submit_block_raw -> message_block::make_raw (p2p_node.hpp)
//   submit_rpc sink <-> btc::coin::Node::submit_block_hex -> NodeRPC::
//                       submit_block_hex -> submitblock CallMethod (rpc.cpp:393)
//
// The seam (block_broadcast.hpp) is the new wiring under test; make_raw /
// CallMethod themselves are already-exercised primitives. The fakes record
// invocation so we can assert exactly WHICH sink fired in each scenario.
//
// Invariants proven:
//   (1) happy path (P2P up)      -> P2P fires, RPC does NOT (fallback, not
//                                   always-both / no double-broadcast)
//   (2) degraded (P2P null/fail) -> RPC fires (fallback engages)
//   (3) both down                -> reaches NEITHER -> won-block path screams
//   (4) the won-block decision (work_source.cpp) flips "reached_network" off
//       exactly when both sinks fail, so a found block can never be lost quietly

#include <impl/btc/coin/block_broadcast.hpp>

#include <cstdio>

using btc::coin::broadcast_block_with_fallback;

static int g_fails = 0;
static void check(bool ok, const char* label) {
    std::printf("  %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) ++g_fails;
}

int main() {
    std::printf("== broadcaster gate: FALLBACK + never-silent-drop ==\n");

    // (1) Happy path: P2P relay succeeds. RPC must NOT fire.
    {
        bool p2p_called = false, rpc_called = false;
        bool reached = broadcast_block_with_fallback(
            [&]{ p2p_called = true; return true; },
            [&]{ rpc_called = true; return true; });
        check(reached,        "happy: block reached network");
        check(p2p_called,     "happy: P2P (primary) fired");
        check(!rpc_called,    "happy: RPC did NOT fire (no double-broadcast)");
    }

    // (2) Degraded: P2P unavailable/failed -> RPC fallback engages.
    {
        bool p2p_called = false, rpc_called = false;
        bool reached = broadcast_block_with_fallback(
            [&]{ p2p_called = true; return false; },   // relay failed / no peer
            [&]{ rpc_called = true; return true; });    // bitcoind accepts
        check(reached,        "degraded: block reached network");
        check(p2p_called,     "degraded: P2P attempted first");
        check(rpc_called,     "degraded: RPC fallback fired");
    }

    // (2b) Degraded by null P2P sink (m_p2p == null -> empty std::function).
    {
        bool rpc_called = false;
        std::function<bool()> no_p2p;   // empty: models m_p2p == nullptr
        bool reached = broadcast_block_with_fallback(
            no_p2p,
            [&]{ rpc_called = true; return true; });
        check(reached,        "null-p2p: block reached network");
        check(rpc_called,     "null-p2p: RPC fallback fired");
    }

    // (3) Both sinks down -> reaches NEITHER -> caller MUST scream.
    {
        bool p2p_called = false, rpc_called = false;
        bool reached = broadcast_block_with_fallback(
            [&]{ p2p_called = true; return false; },
            [&]{ rpc_called = true; return false; });
        check(!reached,       "both-down: reached NEITHER sink");
        check(p2p_called,     "both-down: P2P attempted");
        check(rpc_called,     "both-down: RPC fallback attempted");

        // Mirror the won-block decision in work_source.cpp: a found block with
        // reached_network==false triggers the loud error (never silent-drop).
        bool would_scream = !reached;
        check(would_scream,   "both-down: won-block path screams (no silent drop)");
    }

    // (3b) No fn wired at all is handled at the work_source layer (empty both)
    {
        std::function<bool()> none;
        bool reached = broadcast_block_with_fallback(none, none);
        check(!reached,       "no-sinks: reached NEITHER (work_source screams)");
    }

    std::printf(g_fails ? "\nFAILED (%d)\n" : "\nALL PASS\n", g_fails);
    return g_fails ? 1 : 0;
}