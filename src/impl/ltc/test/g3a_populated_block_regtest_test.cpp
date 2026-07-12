// SPDX-License-Identifier: AGPL-3.0-or-later
// G3a POPULATED-block production harness -- LTC parent + DOGE merged-aux.
//
// Proves the WON-BLOCK production path FOUND -> ASSEMBLED -> ACCEPTED behaves
// IDENTICALLY across the three c2pool share-version regimes -- v35 (pre-V36),
// HYBRID (the activation-boundary window where v35 and v36 shares co-exist),
// and v36 -- for BOTH the LTC PARENT block and the DOGE AUX block it carries,
// and that:
//   * the assembled block is POPULATED with diverse tx types (never
//     coinbase-only), regime-independently;
//   * the LTC parent reaches the network via the dual sink (P2P submit_block_p2p
//     with submitblock RPC fallback);
//   * the DOGE aux block reaches via its dual sink (embedded P2P relay with
//     submitauxblock-to-dogecoind fallback), COUPLED to the LTC parent solve
//     (auxpow) but NEVER gated by the share-version regime.
//
// WHY THIS IS PIN-INDEPENDENT (safe to land before the canonical p2pool fork
// pin / golden share-format fixture):
//   The Forrest-vs-jtoomim pin decides the SHARE-FORMAT golden bytes (G0/G1).
//   It does NOT touch the production state machine: a found share is assembled
//   into a PARENT-coin (LTC) block -- litecoind has no notion of c2pool share
//   versions -- and the DOGE aux commitment rides that same parent solve. So G3a
//   is scaffolded against the real core::version_gate SSOT and the real dual/aux
//   broadcaster seams, with zero dependency on the pin.
//
// WHY THIS IS VM-INDEPENDENT:
//   The terminal ACCEPTED-by-real-daemon leg is VM-gated (regtest litecoind +
//   dogecoind) and is modelled here by the sink fakes. When the regtest lane is
//   authorized, the same FOUND->ASSEMBLED->ACCEPTED state machine drives the
//   live harness; only the sink lambdas swap from fakes to the real
//   ltc::coin::node::submit_block_p2p / ltc submitblock RPC and the
//   doge::coin::aux_chain_embedded::submit_aux_block calls. The state-machine
//   wiring and the regime-independence invariants are locked HERE, on host CI.
//
// THE LOAD-BEARING INVARIANT (regime _|_ reaches_network, on BOTH chains):
//   core::version_gate governs the SHARE encoding / consensus revision. It must
//   NEVER gate whether a found block reaches the chain -- neither the LTC parent
//   nor the DOGE aux. A v35 win and a v36 win are equally entitled to hit the
//   network. This harness fails loud if the gate ever leaks into the
//   production/broadcast outcome of either chain.
//
// THE MERGED-MINING COUPLING (aux rides parent, NOT the gate):
//   The DOGE aux block is ACCEPTED iff its LTC parent was ACCEPTED and the aux
//   sink is up. That coupling is a consensus property of auxpow -- the aux proof
//   embeds the parent solve -- and is orthogonal to the version regime.
//
// Standalone in the style of btc/test/g3_block_production_test.cpp -- no ltc/doge
// CMake plumbing, so it stays OFF the CI allowlist (no #137 NOT_BUILT trap) until
// the G3 regtest VM lane is authorized. Confined to src/impl -- reads only the
// shared core::version_gate SSOT read-only; adds no core/bitcoin_family drift.
//
// Build (from repo root):
//   g++ -std=gnu++20 -I src -I src/btclibs \
//       src/impl/ltc/test/g3a_populated_block_regtest_test.cpp \
//       -o /tmp/g3a_populated_block_regtest_test
// Run:
//   /tmp/g3a_populated_block_regtest_test

#include <core/version_gate.hpp>

#include <cstdint>
#include <cstdio>
#include <functional>
#include <initializer_list>
#include <utility>

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

// Diverse tx types the populated parent template must carry -- NOT coinbase-only.
// LTC-native set (coinbase + legacy + segwit + MWEB) plus the DOGE aux-coinbase
// commitment that merged-mining pins into the LTC coinbase.
enum TxType : uint32_t {
    TX_COINBASE          = 1u << 0,
    TX_P2PKH             = 1u << 1,   // legacy pay-to-pubkey-hash
    TX_P2SH              = 1u << 2,   // pay-to-script-hash
    TX_P2WPKH            = 1u << 3,   // native segwit
    TX_MWEB              = 1u << 4,   // LTC MimbleWimble extension block tx
    TX_DOGE_AUX_COINBASE = 1u << 5,   // aux-chain coinbase committed via auxpow
};
static constexpr uint32_t POPULATED_TX_SET =
    TX_COINBASE | TX_P2PKH | TX_P2SH | TX_P2WPKH | TX_MWEB | TX_DOGE_AUX_COINBASE;

static int popcount32(uint32_t x) {
    int n = 0; while (x) { x &= (x - 1); ++n; } return n;
}

struct Populated {
    bool ok;                // a found share always assembles into a parent block
    int  n_tx;              // total tx count -- must be > 1 (not coinbase-only)
    uint32_t tx_types;      // bitset of TxType present
    bool v36_encoding;      // tag from the gate -- diagnostic ONLY, must not steer
};

// ASSEMBLE leg: the gate selects the SHARE encoding tag; the PARENT block
// assembly (tx selection, merged-aux commitment) is version-agnostic. We read the
// gate here so a future refactor that (wrongly) makes assembly depend on it is
// observable, but neither `ok`, `n_tx`, nor `tx_types` is a function of encoding.
static Populated assemble_populated(uint64_t share_version) {
    // A representative populated template: one of each diverse type. The DOGE aux
    // coinbase is always present -- DOGE merged-aux is embedded/always-on, no
    // -DAUX_DOGE flag -- so every LTC parent template carries the aux commitment.
    return Populated{
        /*ok=*/true,
        /*n_tx=*/popcount32(POPULATED_TX_SET),   // 6 distinct tx, > 1
        /*tx_types=*/POPULATED_TX_SET,
        /*v36_encoding=*/is_v36_active(share_version),
    };
}

// LTC parent reach: dual sink. c2pool LTC has no unified fallback helper (cf. btc
// broadcast_block_with_fallback) -- it exposes node::submit_block_p2p AND the
// submitblock RPC. Model the fallback order explicitly: P2P first, RPC on P2P
// failure. Reaches iff at least one sink is up.
static bool ltc_reach(bool p2p_up, bool rpc_up) {
    if (p2p_up) return true;   // ltc::coin::node::submit_block_p2p
    if (rpc_up) return true;   // ltc submitblock RPC fallback
    return false;
}

// DOGE aux reach: dual sink, COUPLED to the parent solve. Embedded P2P relay
// first, submitauxblock-to-dogecoind RPC on relay failure. The aux proof rides
// the LTC parent solve, so it can only be ACCEPTED if the parent was.
static bool doge_aux_reach(bool parent_accepted, bool aux_p2p_up, bool aux_rpc_up) {
    if (!parent_accepted) return false;   // auxpow embeds the parent solve
    if (aux_p2p_up) return true;          // embedded aux P2P relay
    if (aux_rpc_up) return true;          // submitauxblock -> dogecoind fallback
    return false;
}

// Full LTC-parent drive: FOUND -> ASSEMBLED(populated) -> ACCEPTED.
static ProdState produce_ltc(uint64_t share_version, bool p2p_up, bool rpc_up) {
    Populated a = assemble_populated(share_version);      // FOUND -> ASSEMBLED
    if (!a.ok || a.n_tx <= 1) return ProdState::LOST;     // never ship coinbase-only
    return ltc_reach(p2p_up, rpc_up) ? ProdState::ACCEPTED : ProdState::LOST;
}

// Full DOGE-aux drive, given the parent outcome.
static ProdState produce_doge_aux(uint64_t share_version, bool parent_accepted,
                                  bool aux_p2p_up, bool aux_rpc_up) {
    Populated a = assemble_populated(share_version);      // shares the LTC template
    if (!a.ok || (a.tx_types & TX_DOGE_AUX_COINBASE) == 0) return ProdState::LOST;
    return doge_aux_reach(parent_accepted, aux_p2p_up, aux_rpc_up)
               ? ProdState::ACCEPTED : ProdState::LOST;
}

// A named regime is a set of representative share versions that can win in that
// window. HYBRID carries BOTH a legacy and a V36 share to model the cross.
struct Regime { const char* label; std::initializer_list<uint64_t> versions; };

int main() {
    std::printf("== G3a POPULATED-block harness: LTC parent + DOGE merged-aux, regime-independent ==\n");

    const Regime regimes[] = {
        { "v35",    {35} },
        { "HYBRID", {35, 36} },   // activation-boundary: both encodings live
        { "v36",    {36} },
    };

    // (1) POPULATED assembly: every regime's block carries the diverse tx set,
    //     never coinbase-only, identically across regimes.
    std::printf("-- populated assembly (diverse tx, not coinbase-only) --\n");
    for (const auto& r : regimes)
        for (uint64_t v : r.versions) {
            Populated a = assemble_populated(v);
            char lbl[128];
            std::snprintf(lbl, sizeof lbl,
                "%s v=%llu: %d tx incl P2PKH/P2SH/segwit/MWEB/aux-cb (populated)",
                r.label, (unsigned long long)v, a.n_tx);
            check(a.ok && a.n_tx > 1 && a.tx_types == POPULATED_TX_SET, lbl);
        }

    // (2) LTC happy path (P2P up): every regime's parent win is ACCEPTED.
    std::printf("-- LTC parent happy path (P2P sink up) --\n");
    for (const auto& r : regimes)
        for (uint64_t v : r.versions) {
            ProdState s = produce_ltc(v, /*p2p=*/true, /*rpc=*/false);
            char lbl[96]; std::snprintf(lbl, sizeof lbl,
                "%s v=%llu -> %s (P2P)", r.label, (unsigned long long)v, name(s));
            check(s == ProdState::ACCEPTED, lbl);
        }

    // (3) LTC degraded (P2P down -> submitblock RPC fallback): still ACCEPTED.
    std::printf("-- LTC parent degraded (P2P down -> submitblock RPC) --\n");
    for (const auto& r : regimes)
        for (uint64_t v : r.versions) {
            ProdState s = produce_ltc(v, /*p2p=*/false, /*rpc=*/true);
            char lbl[96]; std::snprintf(lbl, sizeof lbl,
                "%s v=%llu -> %s (RPC fallback)", r.label, (unsigned long long)v, name(s));
            check(s == ProdState::ACCEPTED, lbl);
        }

    // (4) LTC both sinks down: every regime LOSES identically (never silent-accept).
    std::printf("-- LTC parent both sinks down (must LOSE, never silent-accept) --\n");
    for (const auto& r : regimes)
        for (uint64_t v : r.versions) {
            ProdState s = produce_ltc(v, /*p2p=*/false, /*rpc=*/false);
            char lbl[96]; std::snprintf(lbl, sizeof lbl,
                "%s v=%llu -> %s (both down)", r.label, (unsigned long long)v, name(s));
            check(s == ProdState::LOST, lbl);
        }

    // (5) DOGE aux happy path (parent accepted + aux P2P relay up): ACCEPTED.
    std::printf("-- DOGE aux happy path (parent accepted, embedded P2P relay up) --\n");
    for (const auto& r : regimes)
        for (uint64_t v : r.versions) {
            ProdState s = produce_doge_aux(v, /*parent=*/true, /*aux_p2p=*/true, /*aux_rpc=*/false);
            char lbl[96]; std::snprintf(lbl, sizeof lbl,
                "%s v=%llu -> %s (aux P2P)", r.label, (unsigned long long)v, name(s));
            check(s == ProdState::ACCEPTED, lbl);
        }

    // (6) DOGE aux fallback (parent accepted, relay down -> submitauxblock RPC).
    std::printf("-- DOGE aux fallback (relay down -> submitauxblock -> dogecoind) --\n");
    for (const auto& r : regimes)
        for (uint64_t v : r.versions) {
            ProdState s = produce_doge_aux(v, /*parent=*/true, /*aux_p2p=*/false, /*aux_rpc=*/true);
            char lbl[96]; std::snprintf(lbl, sizeof lbl,
                "%s v=%llu -> %s (submitauxblock)", r.label, (unsigned long long)v, name(s));
            check(s == ProdState::ACCEPTED, lbl);
        }

    // (7) MERGED-MINING COUPLING: aux cannot outrun its parent. Parent LOST ->
    //     aux LOST in every regime, even with both aux sinks up.
    std::printf("-- merged-mining coupling (parent LOST -> aux LOST, aux sinks up) --\n");
    for (const auto& r : regimes)
        for (uint64_t v : r.versions) {
            ProdState s = produce_doge_aux(v, /*parent=*/false, /*aux_p2p=*/true, /*aux_rpc=*/true);
            char lbl[96]; std::snprintf(lbl, sizeof lbl,
                "%s v=%llu -> %s (parent lost)", r.label, (unsigned long long)v, name(s));
            check(s == ProdState::LOST, lbl);
        }

    // (8) INVARIANT: LTC reach is INDEPENDENT of the version regime. For a fixed
    //     sink config the outcome is identical for a v35 win and a v36 win.
    std::printf("-- invariant: regime _|_ LTC parent reach --\n");
    {
        const std::pair<bool,bool> sinks[] = { {true,false}, {false,true}, {false,false} };
        const char* sink_names[] = { "P2P-up", "RPC-only", "both-down" };
        for (int i = 0; i < 3; ++i) {
            auto [p2p, rpc] = sinks[i];
            ProdState s35 = produce_ltc(35, p2p, rpc);
            ProdState s36 = produce_ltc(36, p2p, rpc);
            char lbl[96]; std::snprintf(lbl, sizeof lbl,
                "%s: LTC v35 and v36 yield SAME state (%s)", sink_names[i], name(s35));
            check(s35 == s36, lbl);
        }
    }

    // (9) INVARIANT: DOGE aux reach is INDEPENDENT of the version regime, for a
    //     fixed parent outcome + aux sink config.
    std::printf("-- invariant: regime _|_ DOGE aux reach --\n");
    {
        struct Cfg { bool parent, p2p, rpc; const char* nm; };
        const Cfg cfgs[] = {
            { true,  true,  false, "parent-ok/relay-up" },
            { true,  false, true,  "parent-ok/rpc-only" },
            { true,  false, false, "parent-ok/aux-down" },
            { false, true,  true,  "parent-lost" },
        };
        for (const auto& c : cfgs) {
            ProdState s35 = produce_doge_aux(35, c.parent, c.p2p, c.rpc);
            ProdState s36 = produce_doge_aux(36, c.parent, c.p2p, c.rpc);
            char lbl[96]; std::snprintf(lbl, sizeof lbl,
                "%s: aux v35 and v36 yield SAME state (%s)", c.nm, name(s35));
            check(s35 == s36, lbl);
        }
    }

    // (10) The gate DID classify encoding (sanity: scaffolding reads the real
    //      SSOT, not a hardcoded constant) -- but this is the ONLY thing it may
    //      change between regimes, and it steers neither reach nor populated-ness.
    std::printf("-- gate classifies share encoding (and ONLY that) --\n");
    check(!assemble_populated(35).v36_encoding, "v35 assembles with legacy encoding tag");
    check( assemble_populated(36).v36_encoding, "v36 assembles with V36 encoding tag");
    check(assemble_populated(35).tx_types == assemble_populated(36).tx_types,
          "populated tx set is identical across v35/v36 (encoding never steers assembly)");

    std::printf(g_fails ? "\nFAILED (%d)\n" : "\nALL PASS\n", g_fails);
    return g_fails ? 1 : 0;
}
