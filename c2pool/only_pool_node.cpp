#include <iostream>
#include <memory>

#include <libnet/pool_node.h>
#include <libnet/pool_socket.h>
#include <networks/network.h>
#include <libdevcore/config.h>
#include <libdevcore/addr_store.h>
#include <libp2p/preset/p2p_node_interface.h>

#include <boost/asio.hpp>

int main()
{
	// boost context
	auto context = std::make_shared<boost::asio::io_context>(0);

	// Network
	auto parent_net = std::make_shared<coind::DigibyteParentNetwork>();
	auto net = std::make_shared<c2pool::DigibyteNetwork>(parent_net);

	// Config
	auto config = std::make_shared<c2pool::dev::coind_config>();

	// AddrStore
	auto addr_store = std::make_shared<c2pool::dev::AddrStore>("only_pool_addrs	", net);

    // ShareTracker
    std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);

	// Pool Node
	std::shared_ptr<PoolNode> node = std::make_shared<PoolNode>(context);
	node
		->set_net(net)
		->set_config(config)
		->set_addr_store(addr_store)
        ->set_tracker(tracker);
	node->run<P2PListener<PoolSocket>, P2PConnector<PoolSocket>>();

	// DEBUG
	boost::asio::steady_timer t(*context, 10s);
	t.async_wait([](const boost::system::error_code &ec) {
		LOG_DEBUG << "DEBUG TIMER";
	});

	context->run();
}