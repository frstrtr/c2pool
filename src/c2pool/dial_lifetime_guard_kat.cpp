// SPDX-License-Identifier: AGPL-3.0-or-later
//
// dial_lifetime_guard_kat — CORE dial/accept-teardown UAF guard mechanism
// (coin-agnostic). This is the shared mechanism EVERY coin now relies on after
// the all-coin migration: a node owner registers an explicit shared_ptr<INetwork>
// via core::Factory::set_lifetime; core::Client (resolve/connect) and core::Server
// (accept) lock it into a STRONG ref captured BY VALUE in the async handler, so
// make_socket()'s dynamic_cast can never run on a freed node.
//
// SUPERSEDES the e527abfe esft-primitive guard, whose weak_from_this() silently
// returned an EMPTY weak_ptr for (a) unique_ptr/stack-owned nodes (the coin
// NodeP2P — the DOMINANT crasher) and (b) a virtual-inheritance diamond pool node
// whose esft base was never enrolled through the owning control block. The old KAT
// passed while the fix no-opped and the node SEGV-crash-looped in prod.
//
// This KAT drives REAL core::Factory-derived node shapes (NOT a bare StubNode):
//   * Factory<Client>          — the coin NodeP2P / CoinClient dial shape.
//   * Factory<Server, Client>  — the pool sharechain-node component set (inbound
//                                accept AND outbound dial both carry the guard).
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
// TRUE ACCEPTANCE GATE: KAT is necessary but NOT sufficient — e527abfe's KAT
// passed and the fix still failed live. The real gate is CONSTRUCTION-LEVEL: the
// actual coin node core::Client dials through must be provably shared_ptr-owned at
// the connect point AND call set_lifetime(self) before connect, enforced by the
// runtime assert(node->lifetime_armed()) wired at each real make_shared site (see
// each coin's node.hpp / main_*.cpp). The bip110 live contabo flag-ON soak already
// validated the core mechanism; this KAT guards the mechanism on master for all coins.

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

#define KAT_NODE_IFACE_STUBS                                                        \
    void error(const message_error_type&, const NetService&,                        \
               const std::source_location = std::source_location::current()) override {} \
    void error(const boost::system::error_code&, const NetService&,                 \
               const std::source_location = std::source_location::current()) override {} \
    void handle(std::unique_ptr<::RawMessage>, const NetService&) override {}         \
    const std::vector<std::byte>& get_prefix() const override { return kat_prefix(); } \
    void connected(std::shared_ptr<core::Socket>) override {}                        \
    void disconnect() override {}

// SINGLE inheritance — the coin NodeP2P / CoinClient shape (Factory<Client>).
struct SingleNode : public core::ICommunicator,
                    public core::INetwork,
                    public core::Factory<core::Client>
{
    explicit SingleNode(boost::asio::io_context* c)
        : core::Factory<core::Client>(c, this, "kat-single") {}
    KAT_NODE_IFACE_STUBS
};

// Factory<Server,Client> — the pool sharechain-node component set.
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
    std::printf("dial_lifetime_guard_kat: CORE dial-teardown strong-ref guard\n");

    boost::asio::io_context ioc;

    // ── Factory<Client> (coin dialer shape) ──
    {
        auto node = std::make_shared<SingleNode>(&ioc);
        expect_true("[client] before set_lifetime: guard NOT armed (pre-fix skip)",
                    !node->lifetime_armed());
        node->set_lifetime(node);
        expect_true("[client] after set_lifetime: guard ARMED (lifetime_armed()==true)",
                    node->lifetime_armed());

        std::weak_ptr<core::INetwork> lifetime = node;
        std::shared_ptr<core::INetwork> captured = lifetime.lock();  // == Client's captured strong
        node.reset();  // start_p2p redial / owner drop
        expect_true("[client] node ALIVE after owner drop via handler strong ref",
                    captured && captured.use_count() > 0);
        expect_true("[client] dynamic_cast<ICommunicator*> on redial-freed node SUCCEEDS "
                    "(the crashing frame runs on a LIVE vtable)",
                    dynamic_cast<core::ICommunicator*>(captured.get()) != nullptr);
        auto sock = core::make_socket(
            std::make_unique<boost::asio::ip::tcp::socket>(ioc),
            core::connection_type::outgoing, captured.get());
        expect_true("[client] make_socket() completes on the pinned node", sock != nullptr);
    }

    // ── Factory<Server,Client>: BOTH accept() and dial paths carry the guard ──
    {
        auto node = std::make_shared<ServerClientNode>(&ioc);
        expect_true("[srvcli] before set_lifetime: guard NOT armed on either component",
                    !node->lifetime_armed());
        node->set_lifetime(node);  // fold over BOTH Server + Client components
        expect_true("[srvcli] after set_lifetime: guard ARMED on BOTH components (fold-AND)",
                    node->lifetime_armed());

        std::weak_ptr<core::INetwork> lifetime = node;
        std::shared_ptr<core::INetwork> captured = lifetime.lock();
        node.reset();
        expect_true("[srvcli] node ALIVE after owner drop via handler strong ref",
                    captured && captured.use_count() > 0);
        auto sock = core::make_socket(
            std::make_unique<boost::asio::ip::tcp::socket>(ioc),
            core::connection_type::incoming, captured.get());
        expect_true("[srvcli] make_socket() completes on the pinned node (accept path)",
                    sock != nullptr);
    }

    // ── UNMANAGED (stack) node → guard NOT armed (pre-fix skip preserved) ──
    {
        SingleNode stack_node(&ioc);
        expect_true("[unmanaged] lifetime NOT armed AND weak_from_this() empty "
                    "— exactly the e527abfe no-op condition",
                    !stack_node.lifetime_armed()
                    && stack_node.weak_from_this().lock() == nullptr);
    }

    if (g_fail == 0) {
        std::printf("RESULT: PASS — set_lifetime arms the strong-ref guard for the coin "
                    "Factory<Client> and pool Factory<Server,Client> shapes; a redial-freed "
                    "node stays alive for make_socket's dynamic_cast. KAT is necessary, NOT "
                    "sufficient — the real gate is each coin's runtime lifetime_armed() assert "
                    "on the REAL node + the live soak.\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d assertion(s) failed.\n", g_fail);
    return 1;
}
