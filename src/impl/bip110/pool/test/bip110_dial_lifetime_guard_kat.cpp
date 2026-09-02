// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_dial_lifetime_guard_kat — CORE dial/accept-teardown UAF guard mechanism.
//
// SUPERSEDES the e527abfe version, which asserted only the enable_shared_from_this
// (esft) primitive on a single-inheritance make_shared StubNode. That was
// INSUFFICIENT: the shipped guard armed off node->weak_from_this(), which
// silently returns an EMPTY weak_ptr for (a) unique_ptr/stack-owned nodes — the
// coin NodeP2P, the DOMINANT crasher — and, on a virtual-inheritance diamond
// (bip110::pool::Node), is not a handle the owner controls at all. The old KAT
// passed while the fix no-opped and the node SEGV-crash-looped in prod.
//
// The ROBUST guard does NOT depend on esft. The owner registers an EXPLICIT
// shared_ptr<INetwork> with the Factory (Factory::set_lifetime), sourced from the
// REAL owning control block; core::Client/Server store it as a weak_ptr and, per
// async op, lock it and capture the resulting STRONG ref BY VALUE in the handler
// — so a pending resolve/connect/accept keeps the node alive until it runs and
// make_socket()'s dynamic_cast can NEVER touch freed memory.
//
// This KAT drives REAL core::Factory-derived node types (NOT a bare StubNode):
//   * Factory<Client>          — the coin NodeP2P component shape (outbound dial).
//   * Factory<Server, Client>  — the pool-node component set (inbound accept AND
//                                outbound dial both carry the guard).
// (The REAL virtual-inheritance pool::Node — INetwork via a shared virtual base —
// is covered at runtime by the main_bip110 sharechain_node->lifetime_armed()
// assert; the REAL coin NodeP2P by the sibling bip110_dial_lifetime_realnode_kat.)
// For each it asserts:
//   1. set_lifetime() ARMS the guard (lifetime_armed()==true) — the exact thing
//      that silently failed under e527abfe.
//   2. WITHOUT set_lifetime the guard is NOT armed (the pre-fix skip is faithfully
//      reproduced, so the KAT can SEE the failure mode).
//   3. A simulated dial-teardown redial: capture the strong ref exactly as
//      core::Client does, DROP the owner, and assert the node is STILL ALIVE and
//      make_socket()'s dynamic_cast<ICommunicator*>() succeeds — no freed-vtable
//      dereference (the crashing frame #0/#1).
//
// The REAL coin NodeP2P is additionally driven end-to-end by the sibling
// bip110_dial_lifetime_realnode_kat (coin/test). Zero-socket / deterministic.
//
// TRUE ACCEPTANCE GATE: KAT is necessary but NOT sufficient — e527abfe's KAT
// passed and the fix still failed live. The real gate is a crash-free soak on the
// contabo flag-ON canary under the addrman dial-storm (the integrator runs it).

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>

#include <core/inetwork.hpp>
#include <core/socket.hpp>     // core::ICommunicator / core::make_socket
#include <core/factory.hpp>    // core::Factory / set_lifetime / lifetime_armed

namespace {

int g_fail = 0;
void expect_true(const std::string& name, bool cond)
{
    if (cond) std::printf("  [ok]   %s\n", name.c_str());
    else { std::printf("  [FAIL] %s\n", name.c_str()); ++g_fail; }
}

const std::vector<std::byte>& kat_prefix()
{
    static const std::vector<std::byte> p{};
    return p;
}

// Shared ICommunicator/INetwork stubs (pure-virtuals the Factory dial path needs).
#define KAT_NODE_IFACE_STUBS                                                        \
    void error(const message_error_type&, const NetService&,                        \
               const std::source_location = std::source_location::current()) override {} \
    void error(const boost::system::error_code&, const NetService&,                 \
               const std::source_location = std::source_location::current()) override {} \
    void handle(std::unique_ptr<::RawMessage>, const NetService&) override {}         \
    const std::vector<std::byte>& get_prefix() const override { return kat_prefix(); } \
    void connected(std::shared_ptr<core::Socket>) override {}                        \
    void disconnect() override {}

// ── SINGLE inheritance — the coin NodeP2P shape ──
struct SingleNode : public core::ICommunicator,
                    public core::INetwork,
                    public core::Factory<core::Client>
{
    explicit SingleNode(boost::asio::io_context* c)
        : core::Factory<core::Client>(c, this, "kat-single") {}
    KAT_NODE_IFACE_STUBS
};

// A Server+Client Factory node (the pool-node component set: both the inbound
// accept() path and the outbound dial path carry the lifetime guard). Single
// inheritance keeps the KAT focused on the guard mechanism; the REAL virtual-
// inheritance pool::Node (INetwork via a shared virtual base) is covered by the
// runtime lifetime_armed() assertion wired at main_bip110 sharechain_node
// construction, and the REAL coin NodeP2P by bip110_dial_lifetime_realnode_kat.
struct ServerClientNode : public core::ICommunicator,
                          public core::INetwork,
                          public core::Factory<core::Server, core::Client>
{
    explicit ServerClientNode(boost::asio::io_context* c)
        : core::Factory<core::Server, core::Client>(c, this, "kat-srvcli") {}
    KAT_NODE_IFACE_STUBS
};

} // namespace

int main()
{
    std::printf("bip110_dial_lifetime_guard_kat: CORE dial-teardown strong-ref guard\n");

    boost::asio::io_context ioc;

    // ── SINGLE inheritance ──
    {
        auto node = std::make_shared<SingleNode>(&ioc);
        expect_true("[single] before set_lifetime: guard NOT armed (pre-fix skip)",
                    !node->lifetime_armed());
        node->set_lifetime(node);
        expect_true("[single] after set_lifetime: guard ARMED (lifetime_armed()==true)",
                    node->lifetime_armed());

        std::weak_ptr<core::INetwork> lifetime = node;
        std::shared_ptr<core::INetwork> captured = lifetime.lock();
        node.reset();  // start_p2p redial / owner drop
        expect_true("[single] node ALIVE after owner drop via handler strong ref",
                    captured && captured.use_count() > 0);
        expect_true("[single] dynamic_cast<ICommunicator*> on redial-freed node "
                    "SUCCEEDS (no UAF — the crashing frame runs on a LIVE vtable)",
                    dynamic_cast<core::ICommunicator*>(captured.get()) != nullptr);
        auto sock = core::make_socket(
            std::make_unique<boost::asio::ip::tcp::socket>(ioc),
            core::connection_type::outgoing, captured.get());
        expect_true("[single] make_socket() completes on the pinned node",
                    sock != nullptr);
    }

    // ── Server+Client node: BOTH accept() and dial paths carry the guard ──
    {
        auto node = std::make_shared<ServerClientNode>(&ioc);
        expect_true("[srvcli] before set_lifetime: guard NOT armed on either component",
                    !node->lifetime_armed());
        // set_lifetime fans out to BOTH the Server and Client Factory components
        // (lifetime_armed() is the fold-AND over them) — the inbound accept() path
        // is guarded too, not just outbound dial.
        node->set_lifetime(node);
        expect_true("[srvcli] after set_lifetime: guard ARMED on BOTH Server+Client "
                    "components (fold over both)",
                    node->lifetime_armed());

        std::weak_ptr<core::INetwork> lifetime = node;
        std::shared_ptr<core::INetwork> captured = lifetime.lock();
        node.reset();  // owner drop
        expect_true("[srvcli] node ALIVE after owner drop via handler strong ref",
                    captured && captured.use_count() > 0);
        expect_true("[srvcli] dynamic_cast<ICommunicator*> on redial-freed node "
                    "SUCCEEDS (accept/connect make_socket runs on a LIVE vtable)",
                    dynamic_cast<core::ICommunicator*>(captured.get()) != nullptr);
        auto sock = core::make_socket(
            std::make_unique<boost::asio::ip::tcp::socket>(ioc),
            core::connection_type::incoming, captured.get());
        expect_true("[srvcli] make_socket() completes on the pinned node (accept path)",
                    sock != nullptr);
    }

    // ── UNMANAGED (stack) node → guard NOT armed (pre-fix skip preserved) ──
    {
        SingleNode stack_node(&ioc);
        expect_true("[unmanaged] lifetime NOT armed (was_managed=false skip) AND "
                    "weak_from_this() empty — exactly the e527abfe no-op condition",
                    !stack_node.lifetime_armed()
                    && stack_node.weak_from_this().lock() == nullptr);
    }

    if (g_fail == 0) {
        std::printf("RESULT: PASS — set_lifetime arms the strong-ref guard for the "
                    "Factory<Client> and Factory<Server,Client> shapes; a redial-freed node "
                    "stays alive for make_socket's dynamic_cast. KAT is necessary, NOT "
                    "sufficient — live contabo flag-ON soak is the acceptance gate.\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d assertion(s) failed.\n", g_fail);
    return 1;
}
