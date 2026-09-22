// Regression cover for the 2026-09-22 btc.voidbind SEGV crash-loop.
//
// ROOT CAUSE. Factory::Client, on an outbound dial failure, feeds the dead
// target back to the owning node via INetwork::connect_failed() so a scored
// peer manager can penalise it (#940). For a LEGACY UNMANAGED node -- one that
// registered no explicit lifetime handle (set_lifetime) and whose
// weak_from_this() is empty (BTC/LTC/DOGE lanes) -- the pre-fix feedback fell
// back to the RAW m_node pointer:
//
//     if (!was_managed || strong_node)
//         (strong_node ? strong_node.get() : m_node)->connect_failed(addr);
//
// connect_failed fires during teardown / start_p2p() redial -- the exact
// window in which the owning node is destroyed. A freed node leaves m_node
// non-null (dangling), so the guard passes and the virtual call reads a freed
// vtable => heap-use-after-free / SEGV. A null-check is worthless here: a freed
// pointer is non-null and passes it.
//
// THE FIX. The feedback is a SOFT scoring signal, so it must route through the
// SAME live-handle discipline as the connected() success path: score ONLY
// through a pinned/relocked strong_node; if no live handle is held, drop the
// signal rather than dereference m_node. (The success/make_socket path keeps
// its raw fallback because a completed connection is load-bearing for the
// unmanaged lanes -- dropping it would break their connectivity; the soft
// feedback can be dropped safely. That asymmetry is why the fix is scoped to
// the two connect_failed feedback sites only.)
//
// This test builds RED under -fsanitize=address on the pre-fix tree (the
// virtual call on freed memory aborts the process with a UAF report) and GREEN
// post-fix (the freed node is never touched). Folded into the EXISTING
// allowlisted core_test target -- never a standalone add_executable (the #769
// "Not Run" trap).
//
// Determinism: the dial target is the RFC 6761 reserved `.invalid` TLD, which
// every conforming resolver hard-fails (NXDOMAIN) offline -- routing straight
// to the resolve-failure feedback branch WITHOUT reaching make_socket. Both
// connect_failed sites are byte-identical and fixed identically; this repro
// exercises the resolve site.

#include <gtest/gtest.h>

#include <core/factory.hpp>
#include <core/inetwork.hpp>
#include <core/netaddress.hpp>
#include <core/socket.hpp>

#include <boost/asio.hpp>

#include <memory>
#include <string>

namespace {

// Minimal INetwork whose connect_failed() would touch its own vtable. Allocated
// with raw `new` (never make_shared) so enable_shared_from_this enrollment is
// empty -> weak_from_this() is null -> was_managed == false: the unmanaged
// legacy lane that btc.voidbind runs.
struct UafProbeNode : public core::INetwork
{
    void connected(std::shared_ptr<core::Socket> /*socket*/) override {}
    void disconnect() override {}
    void connect_failed(const ::NetService& /*addr*/) override {}
};

} // namespace

// Pre-fix: heap-use-after-free (ASan abort). Post-fix: runs to SUCCEED().
TEST(FactoryConnectFailedUaf, UnmanagedNodeFreedMidDialIsNotDereferenced)
{
    boost::asio::io_context ioc;

    auto* node = new UafProbeNode();               // unmanaged: weak_from_this() empty
    core::Factory<core::Client> fac(&ioc, node);
    // Deliberately NO fac.set_lifetime(...): reproduce the unmanaged lane.

    // .invalid always fails to resolve -> the resolve-failure feedback branch.
    fac.connect(core::NetService(std::string("host.does.not.exist.invalid"),
                                 std::string("9999")));

    // Free the owning node while the async resolve is still pending -- the
    // teardown/redial race. m_node is now a dangling, non-null pointer.
    delete node;

    // Drive the resolve handler: it fires connect_failed feedback. Pre-fix this
    // dereferences the freed node (UAF abort under ASan); post-fix it locks an
    // empty handle, finds no live node, and drops the soft signal.
    ioc.run();

    SUCCEED();  // reached only if no UAF aborted the process
}
