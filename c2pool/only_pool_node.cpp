#include <iostream>
#include <memory>

#include <libnet2/pool_node.h>
#include <libnet2/pool_socket.h>
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

	// Pool Node
	std::shared_ptr<PoolNode> node = std::make_shared<PoolNode>(context);
	node
		->set_net(net)
		->set_config(config)
		->set_addr_store(addr_store);
	node->run<P2PListener<PoolSocket>, P2PConnector<PoolSocket>>();
	context->run();
}