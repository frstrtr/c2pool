// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bip110_broadcaster_slot_lifetime_kat — the REAL broadcaster fan-out SLOT
// dial-teardown UAF gate.
//
// WHY THIS KAT EXISTS
// -------------------
// The coin::Node::m_p2p dial-teardown UAF was fixed (make_shared + set_lifetime,
// node.hpp) and bip110_dial_lifetime_realnode_kat proved it — yet the flag-ON
// contabo canary STILL SEGV-crash-looped on the ~30-40s cadence. Adversarial
// verify found the second, UNMANAGED owner of the SAME crasher type: the
// Bip110Broadcaster fan-out pool. Its slots were `std::unique_ptr<NodeP2P>`
// dialed via make_default_slot WITHOUT set_lifetime, so the strong-ref guard
// could not arm them. The self-rescheduling broadcaster_timer (main_bip110.cpp,
// 30s) runs prune_dead() every tick; a slot still dialing a dead/slow addrman
// peer (TCP connect > 30s; GAP-6 feeds not-yet-tried, often-dead peers) is
// not-handshake-complete at the next tick, so prune_dead() m_slots.erase() FREED
// its unique_ptr<NodeP2P> while its Client resolve/connect completion was still
// queued on the single ioc. The completion then ran make_socket()'s
// dynamic_cast<ICommunicator*>() on the freed node -> the exact SEGV backtrace
// (#0 __dynamic_cast / #1 make_socket / #2 Client::resolve lambda). 30s tick ==
// the observed crash cadence.
//
// THE FIX UNDER TEST (broadcaster.hpp)
//   * Slot: std::unique_ptr<Node> -> std::shared_ptr<Node>
//   * make_default_slot: make_shared<Node> + node->set_lifetime(node) +
//     assert(lifetime_armed()) BEFORE node->connect(addr)
// so a resolve/connect completion captures a STRONG ref by value (core::Client),
// and prune_dead()'s erase drops ONLY the owner — the in-flight handler keeps the
// slot alive until it completes, then it frees cleanly.
//
// WHAT THIS KAT DRIVES (the REAL broadcaster, not a stub)
//   [A] The REAL default factory (make_default_slot): discover() builds a slot
//       via make_shared + set_lifetime + connect. A slot_configurator observes,
//       on the real live slot, lifetime_armed()==true and a non-empty
//       weak_from_this() — the precise assertions that are FALSE under the old
//       unique_ptr slot (set_lifetime never called; unmanaged esft empty).
//   [B] The REAL prune-during-pending-dial race: a slot is created, an in-flight
//       dial completion holds a STRONG ref exactly as core::Client::resolve
//       captures it (by value), then prune_dead() (liveness predicate false, the
//       real "still dialing / not handshook" condition) erases the slot. Assert
//       the OWNER is gone (slot_count()==0) yet the node is STILL ALIVE via the
//       handler's strong ref, that make_socket()'s dynamic_cast succeeds on it
//       (no freed-vtable deref), and that releasing the completion's ref THEN
//       frees it cleanly. Under the old unique_ptr slot, the erase would free the
//       node immediately -> the pending completion's dynamic_cast is a UAF.
//   [C] Counterfactual: an UNMANAGED node (no set_lifetime) reports
//       lifetime_armed()==false — the KAT can SEE the pre-fix failure mode.
//
// Zero-socket / deterministic: [B]/[C] never run the io_context; the in-flight
// completion's strong ref is modelled exactly as core::Client captures it. [A]'s
// real connect() posts an async_resolve that is never run (queued, then drained
// at scope exit) — no DNS, no socket.
//
// TRUE ACCEPTANCE GATE: this KAT is necessary but NOT sufficient. v2 (the
// coin::Node fix) passed its KAT and the node still crash-looped via THIS
// broadcaster. The real gate is a crash-free soak on the contabo flag-ON canary
// under the addrman dial-storm (the integrator runs it): the systemd restart
// counter must hold at 0 for hours past the 30-40s crash cadence. Do not
// over-claim from a green KAT.
// ---------------------------------------------------------------------------

#include <cstdio>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include <core/inetwork.hpp>
#include <core/netaddress.hpp>
#include <core/socket.hpp>            // core::make_socket / core::ICommunicator

#include "../broadcaster.hpp"        // bip110::coin::Bip110Broadcaster (REAL)
#include "../p2p_node.hpp"           // bip110::coin::p2p::NodeP2P (the REAL type)
#include "../node_interface.hpp"     // bip110::interfaces::Node

namespace {

int g_fail = 0;
void expect(const std::string& name, bool cond)
{
    if (cond) std::printf("  [ok]   %s\n", name.c_str());
    else { std::printf("  [FAIL] %s\n", name.c_str()); ++g_fail; }
}

// Duck-typed config mirroring main_bip110's MiniConfig — the same minimal shape
// the sibling bip110 KATs use to instantiate NodeP2P<Cfg>. NodeP2P only reads
// config->coin()->... on the message-framing path, which this KAT never drives.
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

using Broadcaster = bip110::coin::Bip110Broadcaster<KatConfig>;
using Node        = bip110::coin::p2p::NodeP2P<KatConfig>;

} // namespace

int main()
{
    std::printf("bip110_broadcaster_slot_lifetime_kat: REAL fan-out slot dial-teardown UAF guard\n");

    boost::asio::io_context ioc;
    KatConfig cfg;
    bip110::interfaces::Node coin_iface;   // simple struct target for the slot

    // ── (A) REAL default factory arms the guard on every live slot ────────────
    // discover() builds the slot through make_default_slot (make_shared +
    // set_lifetime + assert BEFORE connect). The configurator runs AFTER
    // set_lifetime and BEFORE connect, so it observes the real, live slot with
    // the guard already armed — exactly the property the old unique_ptr slot
    // lacked (set_lifetime was never called; the slot was esft-unmanaged).
    {
        Broadcaster bc(&ioc, &coin_iface, &cfg, /*max_peers=*/8);
        bool  saw_slot = false;
        bool  armed    = false;
        bool  esft_managed = false;
        bc.set_slot_configurator([&](Node& slot) {
            saw_slot     = true;
            armed        = slot.lifetime_armed();
            esft_managed = (slot.weak_from_this().lock() != nullptr);
        });
        // Predicate irrelevant here (no prune); keep every slot "live".
        bc.set_live_predicate([](const Node&) { return true; });

        size_t dialed = bc.discover({ NetService("10.0.0.1", 8333) });
        expect("[A] default factory dialed the slot", dialed == 1 && bc.slot_count() == 1);
        expect("[A] make_default_slot ran the configurator on the real live slot", saw_slot);
        expect("[A] REAL default slot: lifetime_armed()==true "
               "(make_shared + set_lifetime BEFORE connect — FALSE under the old "
               "unique_ptr slot)", armed);
        expect("[A] REAL default slot: shared-owned, weak_from_this() non-empty "
               "(the old unique_ptr slot was esft-unmanaged)", esft_managed);
    }

    // ── (B) prune_dead() during a PENDING dial does NOT free the slot ─────────
    // The production race, driven through the REAL broadcaster. An injected
    // factory reproduces make_default_slot's construction EXACTLY (make_shared +
    // set_lifetime + assert) and hands the KAT a weak_ptr to the slot; the
    // in-flight dial completion's strong ref is modelled precisely as
    // core::Client::resolve captures it (a shared_ptr held by value for the
    // duration of the async op). The liveness predicate returns false — the real
    // "still dialing a dead/slow peer, not handshake-complete" condition that the
    // 30s prune tick trips on.
    {
        Broadcaster bc(&ioc, &coin_iface, &cfg, /*max_peers=*/8);
        std::weak_ptr<Node> slot_weak;
        bc.set_slot_factory([&](const NetService&) -> std::shared_ptr<Node> {
            auto node = std::make_shared<Node>(&ioc, &coin_iface, &cfg, "kat-fanout");
            node->set_lifetime(node);                 // identical to make_default_slot
            expect("[B] injected slot arms the guard (mirror of make_default_slot)",
                   node->lifetime_armed());
            slot_weak = node;
            return node;                              // dial NOT issued (zero-socket)
        });
        bc.set_live_predicate([](const Node&) { return false; });  // "still dialing"

        size_t dialed = bc.discover({ NetService("10.0.0.2", 8333) });
        expect("[B] slot installed by discover", dialed == 1 && bc.slot_count() == 1);

        // The in-flight resolve/connect completion holds a STRONG ref by value —
        // this is that ref (== core::Client's captured `strong`).
        std::shared_ptr<Node> pending_completion = slot_weak.lock();
        expect("[B] in-flight dial completion holds a live strong ref before prune",
               pending_completion != nullptr);

        // 30s tick: prune_dead() erases the not-live slot -> drops the OWNER.
        size_t pruned = bc.prune_dead();
        expect("[B] prune_dead removed the owner (slot_count==0)",
               pruned == 1 && bc.slot_count() == 0);
        expect("[B] after prune, the slot is STILL ALIVE via the pending "
               "completion's strong ref (use_count>0) — NOT freed mid-flight",
               pending_completion && pending_completion.use_count() > 0
               && slot_weak.lock() != nullptr);

        // The exact op that SEGV'd in prod (backtrace #0/#1): make_socket runs
        // dynamic_cast<ICommunicator*>(node). It MUST succeed on the pinned node.
        auto* comm = dynamic_cast<core::ICommunicator*>(pending_completion.get());
        expect("[B] dynamic_cast<ICommunicator*> on the prune-freed slot SUCCEEDS "
               "(make_socket runs on a LIVE vtable, no UAF)", comm != nullptr);
        auto raw = std::make_unique<boost::asio::ip::tcp::socket>(ioc);
        auto socket = core::make_socket(std::move(raw), core::connection_type::outgoing,
                                        pending_completion.get());
        expect("[B] full make_socket() completes on the pinned slot", socket != nullptr);

        // Completion runs and releases its ref -> the slot frees cleanly.
        socket.reset();
        pending_completion.reset();
        expect("[B] once the completion releases its ref, the slot frees cleanly "
               "(weak expired)", slot_weak.lock() == nullptr);
    }

    // ── (C) counterfactual: an UNMANAGED node is NOT guarded (pre-fix mode) ───
    {
        Node unmanaged(&ioc, &coin_iface, &cfg, "kat-unmanaged");
        expect("[C] unmanaged node (no set_lifetime): lifetime_armed()==false "
               "— the pre-fix broadcaster slot the KAT reproduces",
               !unmanaged.lifetime_armed());
    }

    if (g_fail == 0) {
        std::printf("RESULT: PASS — the REAL Bip110Broadcaster fan-out slots arm the "
                    "strong-ref dial guard; prune_dead() during a pending dial drops "
                    "only the owner and the completion keeps the slot alive for "
                    "make_socket's dynamic_cast. KAT is necessary, NOT sufficient — a "
                    "live contabo flag-ON soak under the addrman dial-storm (restart "
                    "counter 0 for hours past the 30-40s cadence) is the acceptance gate.\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d assertion(s) failed.\n", g_fail);
    return 1;
}
