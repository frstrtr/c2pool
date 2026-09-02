// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_dial_lifetime_guard_kat — FINDING B (core UAF, class of #759) mechanism
// KAT. It asserts the enable_shared_from_this invariant that core::Client's
// resolve()/connect_socket() dial-teardown guard relies on:
//
//   * A shared_ptr-managed core::INetwork (the bip110 M3 sharechain node, now
//     make_shared) yields a LOCKABLE weak_from_this() — so was_managed=true and
//     the guard `if (was_managed && weak_node.expired()) return;` is ARMED.
//   * When that node is destroyed while an async dial is in flight, the captured
//     weak_ptr EXPIRES — so the guard fires and connect_socket() returns BEFORE
//     make_socket() dynamic_casts the (now freed) node vtable -> no SEGV.
//   * A legacy UNMANAGED node (unique_ptr / stack) yields an EMPTY
//     weak_from_this() -> was_managed=false -> guard skipped, behavior identical
//     to the pre-fix raw-pointer path (why bip110 had to migrate to make_shared).
//
// A full async UAF reproduction is inherently non-deterministic; this proves the
// exact lifetime primitive the guard is built on, deterministically. The core
// guard reordering (liveness check BEFORE make_socket) is additionally covered by
// the cross-coin c2pool-dash build.

#include <core/inetwork.hpp>

#include <cstdio>
#include <memory>
#include <string>

namespace {

int g_fail = 0;
void expect_true(const std::string& name, bool cond)
{
    if (cond) std::printf("  [ok]   %s\n", name.c_str());
    else { std::printf("  [FAIL] %s\n", name.c_str()); ++g_fail; }
}

// Minimal INetwork the Factory dial path would carry (only weak_from_this() is
// exercised by the guard). connected()/disconnect() are pure virtual stubs.
struct StubNode : public core::INetwork
{
    void connected(std::shared_ptr<core::Socket>) override {}
    void disconnect() override {}
};

} // namespace

int main()
{
    std::printf("bip110_dial_lifetime_guard_kat: FINDING B — dial-teardown lifetime guard\n");

    // ── Managed node (bip110 M3 make_shared): guard is ARMED ──
    std::weak_ptr<core::INetwork> captured;
    {
        auto managed = std::make_shared<StubNode>();
        captured = managed->weak_from_this();     // exactly resolve()'s capture
        expect_true("[managed] weak_from_this() locks while alive (was_managed=true)",
                    captured.lock() != nullptr);

        // Node destroyed mid-dial (e.g. ioc.stop() drops the owning shared_ptr
        // while async_resolve is in flight).
        managed.reset();
    }
    expect_true("[managed] captured weak_ptr EXPIRES after destruction "
                "-> guard fires, no dynamic_cast on freed node",
                captured.expired());

    // ── Unmanaged node (legacy unique_ptr/stack): guard is SKIPPED ──
    {
        StubNode stack_node;
        std::weak_ptr<core::INetwork> w = stack_node.weak_from_this();
        expect_true("[unmanaged] weak_from_this() is EMPTY (was_managed=false, "
                    "guard skipped exactly as pre-fix)",
                    w.lock() == nullptr);
    }

    if (g_fail == 0) {
        std::printf("RESULT: PASS — shared_ptr node arms the dial-teardown guard; "
                    "destroyed node expires the captured weak_ptr before make_socket.\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d assertion(s) failed.\n", g_fail);
    return 1;
}
