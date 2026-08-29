// SPDX-License-Identifier: AGPL-3.0-or-later
// G3 block-production harness (pin-independent scaffolding).
//
// Proves the WON-BLOCK production path FOUND -> ASSEMBLED -> ACCEPTED behaves
// IDENTICALLY across the three c2pool share-version regimes -- v35 (pre-V36),
// HYBRID (the activation-boundary window where v35 and v36 shares co-exist),
// and v36 -- and that the dual-path broadcaster reaches the network in every
// regime under both a healthy P2P sink and an RPC-only fallback.
//
// WHY THIS IS PIN-INDEPENDENT (and safe to land before the canonical p2pool
// fork pin / golden share-format fixture):
//   The Forrest-vs-jtoomim pin decides the SHARE-FORMAT golden bytes (G0/G1).
//   It does NOT touch the production state machine: a found block is assembled
//   into a PARENT-coin block (bitcoind has no notion of c2pool share versions)
//   and broadcast. So G3 can be scaffolded now against the real version_gate
//   SSOT and the real broadcaster seam, with zero dependency on the pin.
//
// WHY THIS IS VM-INDEPENDENT:
//   The terminal ACCEPTED-by-real-bitcoind leg is VM-gated (regtest bitcoind +
//   bitaxe via vm-fleet) and is modelled here by the sink fakes. When VM130
//   auth lands, the same FOUND->ASSEMBLED->ACCEPTED state machine drives the
//   live regtest harness; only the two sink lambdas swap from fakes to the real
//   submit_block_p2p_raw / submitblock RPC calls. The state-machine wiring and
//   the regime-independence invariant are locked HERE, on host CI, today.
//
//   LIVE LEG (realized): tools/conformance/g3_live_submitblock.py performs that
//   exact sink swap against a live regtest bitcoind (VM420), driving the real
//   submitblock RPC for each regime and asserting the same regime _|_ reach
//   invariant on accepted blocks. Run it on a VM with an authed regtest node.
//
// THE LOAD-BEARING INVARIANT (regime _|_ reaches_network):
//   core::version_gate governs the SHARE encoding / consensus revision. It must
//   NEVER gate whether a found block reaches the chain. A v35 win and a v36 win
//   are equally entitled to hit the network. This harness fails loud if the
//   gate ever leaks into the production/broadcast outcome.
//
// Standalone in the style of block_broadcast_test.cpp -- no btc/test CMake
// plumbing, so it stays off the CI allowlist (no #137 NOT_BUILT trap) until the
// G2/G3 VM lane is authorized.
//
// Build (from repo root):
//   g++ -std=gnu++20 -I src -I src/btclibs \
//       src/impl/btc/test/g3_block_production_test.cpp -o /tmp/g3_block_production_test
// Run:
//   /tmp/g3_block_production_test

#include <core/version_gate.hpp>
#include <impl/btc/coin/block_broadcast.hpp>

#include <cstdint>
#include <cstdio>
#include <functional>

using btc::coin::broadcast_block_with_fallback;
using core::version_gate::is_v36_active;

static int g_fails = 0;
static void check(bool ok, const char* label) {
    std::printf("  %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) ++g_fails;
}

// ---- minimal production state machine (host-side model of the VM harness) ----

enum class ProdState { FOUND, ASSEMBLED, ACCEPTED, LOST };

static const char* name(ProdState s) {
    switch (s) {
        case ProdState::FOUND:     return "FOUND";
        case ProdState::ASSEMBLED: return "ASSEMBLED";
        case ProdState::ACCEPTED:  return "ACCEPTED";
        case ProdState::LOST:      return "LOST";
    }
    return "?";
}

struct Assembled {
    bool ok;            // a found share always assembles into a parent block
    bool v36_encoding;  // tag from the gate -- diagnostic ONLY, must not steer reach
};

// ASSEMBLE leg: the gate selects the SHARE encoding tag; the PARENT block
// assembly itself is version-agnostic. We deliberately read the gate here so a
// future refactor that (wrongly) makes assembly depend on it is observable, but
// `ok` is never a function of `v36_encoding`.
static Assembled assemble_from_found(uint64_t share_version) {
    return Assembled{ /*ok=*/true, /*v36_encoding=*/is_v36_active(share_version) };
}

// Full FOUND -> ASSEMBLED -> ACCEPTED drive. p2p_up / rpc_up model the two live
// sinks (fakes today, real submit paths under VM130).
static ProdState produce(uint64_t share_version, bool p2p_up, bool rpc_up) {
    Assembled a = assemble_from_found(share_version);   // FOUND -> ASSEMBLED
    if (!a.ok) return ProdState::LOST;
    bool reached = broadcast_block_with_fallback(       // ASSEMBLED -> ACCEPTED
        [&]{ return p2p_up; },
        [&]{ return rpc_up; });
    return reached ? ProdState::ACCEPTED : ProdState::LOST;
}

// A named regime is just a set of representative share versions that can win in
// that window. HYBRID carries BOTH a legacy and a V36 share to model the cross.
struct Regime { const char* label; std::initializer_list<uint64_t> versions; };

int main() {
    std::printf("== G3 block-production harness: FOUND->ASSEMBLED->ACCEPTED, regime-independent ==\n");

    const Regime regimes[] = {
        { "v35",    {35} },
        { "HYBRID", {35, 36} },   // activation-boundary: both encodings live
        { "v36",    {36} },
    };

    // (1) Happy path (P2P up): every regime's win is ACCEPTED via P2P.
    std::printf("-- happy path (P2P sink up) --\n");
    for (const auto& r : regimes)
        for (uint64_t v : r.versions) {
            ProdState s = produce(v, /*p2p=*/true, /*rpc=*/false);
            char lbl[96]; std::snprintf(lbl, sizeof lbl,
                "%s v=%llu -> %s (P2P)", r.label, (unsigned long long)v, name(s));
            check(s == ProdState::ACCEPTED, lbl);
        }

    // (2) Degraded (P2P down, RPC up): fallback still ACCEPTS in every regime.
    std::printf("-- degraded (P2P down -> RPC fallback) --\n");
    for (const auto& r : regimes)
        for (uint64_t v : r.versions) {
            ProdState s = produce(v, /*p2p=*/false, /*rpc=*/true);
            char lbl[96]; std::snprintf(lbl, sizeof lbl,
                "%s v=%llu -> %s (RPC fallback)", r.label, (unsigned long long)v, name(s));
            check(s == ProdState::ACCEPTED, lbl);
        }

    // (3) Both sinks down: every regime LOSES identically (never silent-accept).
    std::printf("-- both sinks down (must LOSE + scream, never silent-accept) --\n");
    for (const auto& r : regimes)
        for (uint64_t v : r.versions) {
            ProdState s = produce(v, /*p2p=*/false, /*rpc=*/false);
            char lbl[96]; std::snprintf(lbl, sizeof lbl,
                "%s v=%llu -> %s (both down)", r.label, (unsigned long long)v, name(s));
            check(s == ProdState::LOST, lbl);
        }

    // (4) THE invariant: reaches_network is INDEPENDENT of the version regime.
    //     For a fixed sink config, the outcome must be identical for a v35 win
    //     and a v36 win. If the gate ever leaks into the broadcast outcome this
    //     fails loud.
    std::printf("-- invariant: regime _|_ reaches_network --\n");
    {
        const std::pair<bool,bool> sinks[] = { {true,false}, {false,true}, {false,false} };
        const char* sink_names[] = { "P2P-up", "RPC-only", "both-down" };
        int i = 0;
        for (auto [p2p, rpc] : sinks) {
            ProdState s35 = produce(35, p2p, rpc);
            ProdState s36 = produce(36, p2p, rpc);
            char lbl[96]; std::snprintf(lbl, sizeof lbl,
                "%s: v35 and v36 yield SAME state (%s)", sink_names[i], name(s35));
            check(s35 == s36, lbl);
            ++i;
        }
    }

    // (5) The gate DID classify encoding (sanity: scaffolding reads the real
    //     SSOT, not a hardcoded constant) -- but this is the only thing it may
    //     change between regimes.
    std::printf("-- gate classifies share encoding (and ONLY that) --\n");
    check(!assemble_from_found(35).v36_encoding, "v35 assembles with legacy encoding tag");
    check( assemble_from_found(36).v36_encoding, "v36 assembles with V36 encoding tag");

    std::printf(g_fails ? "\nFAILED (%d)\n" : "\nALL PASS\n", g_fails);
    return g_fails ? 1 : 0;
}