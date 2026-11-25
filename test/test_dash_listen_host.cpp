// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH --listen [HOST:]PORT binds HOST (2026-11-17).
//
// main_dash parsed the host of --listen but called core::Server::listen(port),
// which binds every interface, while the startup line printed HOST. A node
// started with --listen 127.0.0.1:N was reachable on its LAN address. The
// binding itself is pinned in core_test (ListenerHost.*: a 127.0.0.1 listener
// is refused on the LAN address). This pins the DASH wiring: a wildcard host
// keeps the unchanged every-interface path, any other host goes through
// listen_on and a failure to bind it is fatal (never a silent wider bind).
//
// Folded into test_dash_node (DASH_MAIN_SRC is defined for this target).

#include <gtest/gtest.h>

#include <cctype>
#include <fstream>
#include <iterator>
#include <string>

namespace {

std::string squeezed_main_dash()
{
    std::ifstream in(DASH_MAIN_SRC);
    EXPECT_TRUE(in.good()) << "cannot open " << DASH_MAIN_SRC;
    std::string out;
    for (std::istreambuf_iterator<char> it(in), end; it != end; ++it)
        if (!std::isspace(static_cast<unsigned char>(*it))) out.push_back(*it);
    return out;
}

} // namespace

TEST(DashListenHost, MainDashBindsTheListenHost)
{
    const std::string s = squeezed_main_dash();
    const auto wild = s.find("if(core::is_wildcard_listen_host(peer.listen_host)){");
    const auto all = s.find("p2p_node.core::Server::listen(bind_port);", wild);
    const auto on = s.find("elseif(!p2p_node.core::Server::listen_on(peer.listen_host,bind_port)){", all);
    const auto fatal = s.find("return1;", on);
    ASSERT_NE(wild, std::string::npos) << "the wildcard check on the --listen host";
    EXPECT_NE(all, std::string::npos) << "a wildcard host keeps the every-interface listen(port)";
    EXPECT_NE(on, std::string::npos) << "any other host binds through listen_on(host, port)";
    EXPECT_NE(fatal, std::string::npos) << "and a failed bind of that host is fatal";
    EXPECT_LT(fatal - on, 600u) << "the fatal exit belongs to the listen_on branch";
}
