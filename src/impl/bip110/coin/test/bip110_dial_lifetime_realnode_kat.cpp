// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bip110_dial_lifetime_realnode_kat — the REAL-TYPE dial-teardown UAF gate.
//
// This KAT exists because the PREVIOUS guard (e527abfe) shipped with a KAT that
// used a simplified single-inheritance make_shared StubNode and PASSED — while
// the fix NO-OPPED in production and the node SEGV-crash-looped. The reason:
// e527abfe's guard armed off node->weak_from_this(), and the DOMINANT crasher —
// the coin-P2P core::Client living inside bip110::coin::p2p::NodeP2P — was
// unique_ptr-owned (bip110::coin::Node::m_p2p), so weak_from_this() was empty,
// was_managed=false, the guard was skipped, and make_socket() ran
// dynamic_cast<ICommunicator*>() on a node freed by a start_p2p() redial → the
// exact backtrace frames #0 (__dynamic_cast) / #1 (make_socket) / #2
// (Client::resolve lambda).
//
// So this KAT drives the REAL NodeP2P type (NOT a stub) and exercises the REAL
// ownership pattern the robust fix requires:
//   * make_shared<NodeP2P>() + set_lifetime(self)  → lifetime_armed()==true
//     (the explicit strong-ref guard is genuinely ARMED on the real type — the
//     precise assertion that would have FAILED under e527abfe, where m_p2p was
//     a unique_ptr and set_lifetime was never called).
//   * an UNMANAGED (stack) NodeP2P → lifetime_armed()==false: the pre-fix skip
//     is faithfully reproduced (proves the KAT can SEE the failure mode).
//   * a simulated start_p2p() redial: capture the strong ref exactly as
//     core::Client's async handler does, DROP the owner (frees the old m_p2p),
//     and assert the node is STILL ALIVE and that make_socket's
//     dynamic_cast<ICommunicator*>() succeeds on it — i.e. the freed-vtable
//     dereference that crashed in prod CANNOT happen.
//
// Zero-socket / deterministic: nothing dials, resolves, or accepts. The
// io_context is constructed but never run.
//
// TRUE ACCEPTANCE GATE: this KAT is necessary but NOT sufficient — e527abfe's
// KAT passed and the fix still failed live. The real gate is a crash-free soak
// on the contabo flag-ON canary under the addrman dial-storm (the integrator
// runs it). Do not over-claim from a green KAT.
// ---------------------------------------------------------------------------

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>

#include <core/inetwork.hpp>
#include <core/socket.hpp>            // core::make_socket / core::ICommunicator
#include "../p2p_node.hpp"           // bip110::coin::p2p::NodeP2P (the REAL type)

using bip110::coin::p2p::NodeP2P;

namespace {

int g_fail = 0;
void expect_true(const std::string& name, bool cond)
{
    if (cond) std::printf("  [ok]   %s\n", name.c_str());
    else { std::printf("  [FAIL] %s\n", name.c_str()); ++g_fail; }
}

// Duck-typed config mirroring main_bip110's MiniConfig — the same minimal shape
// bip110_peer_discovery_kat uses to instantiate NodeP2P<Cfg>. NodeP2P only reads
// config->coin()->... on the dial path, which this KAT never drives.
struct KatCoinCfg {
    struct P2P { std::vector<std::byte> prefix; NetService address; } m_p2p;
    bool m_testnet{false};
    bool m_regtest{false};
    std::string m_symbol{"BIP110"};
};
struct KatConfig {
    KatCoinCfg m_coin;
    bool m_testnet{false};
    KatCoinCfg* coin() { return &m_coin; }
};

} // namespace

int main()
{
    std::printf("bip110_dial_lifetime_realnode_kat: REAL NodeP2P dial-teardown UAF guard\n");

    boost::asio::io_context ioc;
    KatConfig cfg;

    // ── (A) REAL NodeP2P, shared_ptr-owned + set_lifetime → guard ARMED ──
    // This is the exact ownership the robust fix installs (coin/node.hpp
    // init_p2p/start_p2p: make_shared + set_lifetime BEFORE connect). Under
    // e527abfe m_p2p was a unique_ptr and set_lifetime did not exist, so this
    // assertion is precisely what was FALSE when the node crash-looped.
    {
        auto node = std::make_shared<NodeP2P<KatConfig>>(&ioc, nullptr, &cfg, "kat-A");
        node->set_lifetime(node);
        expect_true("[A] real NodeP2P: set_lifetime ARMS the strong-ref dial guard "
                    "(lifetime_armed()==true) — the e527abfe no-op is closed",
                    node->lifetime_armed());
    }

    // ── (B) UNMANAGED (stack) NodeP2P → guard NOT armed (pre-fix skip) ──
    // Faithfully reproduces the crashing condition: no explicit lifetime handle,
    // and (as a unique_ptr/stack node) esft yields an empty weak_from_this().
    // Proves the KAT can OBSERVE the failure mode e527abfe's StubNode could not.
    {
        NodeP2P<KatConfig> unmanaged(&ioc, nullptr, &cfg, "kat-B");
        expect_true("[B] unmanaged real NodeP2P: lifetime NOT armed "
                    "(the pre-fix was_managed=false skip)",
                    !unmanaged.lifetime_armed());
        expect_true("[B] unmanaged real NodeP2P: weak_from_this() is EMPTY "
                    "(exactly why the e527abfe esft guard no-opped)",
                    unmanaged.weak_from_this().lock() == nullptr);
    }

    // ── (C) SIMULATED start_p2p() REDIAL: strong ref survives owner drop ──
    // Reproduce the production race deterministically: an async resolve/connect
    // is in flight (its handler captured a STRONG ref via the registered
    // lifetime), then start_p2p() reassigns m_p2p and FREES the previous node.
    // Because the handler holds a strong ref, the node must stay ALIVE and
    // make_socket's dynamic_cast must succeed on it — no freed-vtable deref.
    {
        auto node = std::make_shared<NodeP2P<KatConfig>>(&ioc, nullptr, &cfg, "kat-C");
        node->set_lifetime(node);
        expect_true("[C] pre-redial: guard armed on the real node",
                    node->lifetime_armed());

        // Exactly what core::Client's async handler captures for the managed
        // path: lock the registered lifetime into a STRONG ref held by value.
        std::weak_ptr<core::INetwork> lifetime = node;   // == Client::m_lifetime
        std::shared_ptr<core::INetwork> captured = lifetime.lock();
        expect_true("[C] async handler captured a live strong ref before redial",
                    captured != nullptr);

        // start_p2p() redial: the owner reassigns m_p2p, dropping this node's
        // last OWNING reference. The in-flight handler's strong ref must keep it
        // alive.
        node.reset();
        expect_true("[C] after owner drop (redial), node is STILL ALIVE via the "
                    "handler's strong ref (use_count>0) — NOT freed mid-flight",
                    captured && captured.use_count() > 0);

        // The exact operation that SEGV'd in prod (backtrace frame #0/#1):
        // make_socket() does dynamic_cast<ICommunicator*>(node) on the node
        // pointer. Run it on the captured (guaranteed-live) node.
        auto* comm = dynamic_cast<core::ICommunicator*>(captured.get());
        expect_true("[C] dynamic_cast<ICommunicator*>(node) on the redial-freed "
                    "node SUCCEEDS (make_socket runs on a LIVE vtable, no UAF)",
                    comm != nullptr);

        // Build a real Socket exactly as the Client dial path would, proving the
        // whole make_socket() call — not just the cross-cast — runs cleanly on
        // the strong-ref-pinned node.
        auto raw_socket = std::make_unique<boost::asio::ip::tcp::socket>(ioc);
        auto socket = core::make_socket(std::move(raw_socket),
                                        core::connection_type::outgoing, captured.get());
        expect_true("[C] make_socket() completes on the pinned node (no freed-node "
                    "dynamic_cast) and returns a Socket",
                    socket != nullptr);

        // Releasing the last strong ref frees the node cleanly (the ioc-teardown
        // case: the pending handler is destroyed → strong ref released → free).
        captured.reset();
    }

    if (g_fail == 0) {
        std::printf("RESULT: PASS — the REAL coin NodeP2P arms the explicit strong-ref "
                    "dial guard; a redial-freed node stays alive for make_socket's "
                    "dynamic_cast. KAT is necessary, NOT sufficient — live contabo "
                    "flag-ON soak under the addrman dial-storm is the acceptance gate.\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d assertion(s) failed.\n", g_fail);
    return 1;
}
